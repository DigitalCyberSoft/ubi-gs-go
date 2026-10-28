// Package nat implements the NAT service: over SRP the game asks for its public address; it is told an
// id and port to ping, and the address its pings arrive from is its public address.
package nat

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/dl"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/gsm"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/logx"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/srp"
)

// ClientTimeout is how long a silent client is kept (the game gives up after 120 s).
const ClientTimeout = 150 * time.Second

// tick is how often silent clients are looked for.
const tick = 10 * time.Second

// Subtypes of NAT messages.
const (
	msgPortID  = "2"
	msgAddress = "3"
)

// Relay gives the address a player is told in relay mode.
type Relay interface {
	// Observed is called with a player's verified public address (its game port, from its ping) and
	// returns the address to tell it instead.
	Observed(real netip.AddrPort) (netip.AddrPort, bool)
}

// Client is a game's NAT connection.
type Client struct {
	Addr     netip.AddrPort // the SRP connection
	srp      srp.Conn
	pingID   uint32
	natReq   *gsm.Message
	lastSeen time.Time
	// Public is the address the game's last ping came from.
	Public netip.AddrPort
}

// Server is the NAT service.
type Server struct {
	Log        *logx.Logger
	Port       int // told to the game as where to ping
	MaxClients int
	MaxPerIP   int
	Relay      Relay // nil: relay off

	mu      sync.Mutex
	clients []*Client
}

// Packet is a datagram to send.
type Packet struct {
	Data []byte
	To   netip.AddrPort
}

func (s *Server) find(addr netip.AddrPort) *Client {
	for _, c := range s.clients {
		if c.Addr == addr {
			return c
		}
	}
	return nil
}

func (s *Server) findPing(id uint32) *Client {
	for _, c := range s.clients {
		if c.pingID == id && c.natReq != nil {
			return c
		}
	}
	return nil
}

func (s *Server) remove(c *Client) {
	for i, o := range s.clients {
		if o == c {
			s.clients = append(s.clients[:i], s.clients[i+1:]...)
			return
		}
	}
}

// newPingID returns a random nonzero id no other client uses. s.mu is held.
func (s *Server) newPingID() uint32 {
	var b [4]byte
	for {
		rand.Read(b[:])
		id := binary.BigEndian.Uint32(b[:])
		if id == 0 {
			continue
		}
		used := false
		for _, c := range s.clients {
			used = used || c.pingID == id
		}
		if !used {
			return id
		}
	}
}

func (s *Server) hasRoom(ip netip.Addr) bool {
	if len(s.clients) >= s.MaxClients {
		return false
	}
	n := 0
	for _, c := range s.clients {
		if c.Addr.Addr() == ip {
			n++
		}
	}
	return n < s.MaxPerIP
}

// natReply is a NAT message answering the game's request: [subtype, [socket id, ip, port]]. The game
// reads the ip as a host-order integer (127.0.0.1 is 0x7F000001) with atoi, so it is sent signed.
func natReply(req *gsm.Message, subtype string, ip uint32, port int) ([]byte, error) {
	args, _ := req.Data.List(1)
	socketID, ok := args.At(0)
	if !ok {
		return nil, errors.New("NAT request without a socket id")
	}
	m := gsm.Reply(req, gsm.NAT, dl.List{dl.S(subtype),
		dl.L(socketID, dl.S(strconv.Itoa(int(int32(ip)))), dl.S(strconv.Itoa(port)))})
	return m.Encode()
}

// HandlePacket handles a datagram and returns what to send.
func (s *Server) HandlePacket(data []byte, from netip.AddrPort, now time.Time) ([]Packet, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(data) < srp.HeaderSize {
		return s.handlePing(data, from, now)
	}
	return s.handleSegment(data, from, now)
}

// handlePing handles a ping from the game's own port with the id from PORT_ID: the reply over the SRP
// connection is the address the ping came from (which also keeps the connection alive).
func (s *Server) handlePing(data []byte, from netip.AddrPort, now time.Time) ([]Packet, error) {
	s.Log.Debugf("<- %s PING", from)
	if len(data) != 4 {
		return nil, nil
	}
	c := s.findPing(binary.BigEndian.Uint32(data))
	if c == nil {
		s.Log.Debugf("unknown ping id %x from %s", data, from)
		return nil, nil
	}
	c.lastSeen = now
	c.Public = from
	told := from
	if s.Relay != nil {
		a, ok := s.Relay.Observed(from)
		if !ok {
			s.Log.Warnf("no relay port for %s", from)
			return nil, nil
		}
		told = a
	}
	ip := told.Addr().Unmap()
	if !ip.Is4() {
		return nil, nil
	}
	msg, err := natReply(c.natReq, msgAddress, binary.BigEndian.Uint32(ip.AsSlice()), int(told.Port()))
	if err != nil {
		return nil, err
	}
	return []Packet{{c.srp.Respond(nil, msg), c.Addr}}, nil
}

func (s *Server) handleSegment(data []byte, from netip.AddrPort, now time.Time) ([]Packet, error) {
	c := s.find(from)
	seg, err := srp.Parse(data)
	if err != nil {
		return nil, err
	}
	s.Log.Debugf("<- %s SRP %s %v", from, srp.FlagNames(seg.Header.Flags&^srp.FlagID), seg.Msg)
	// a new connection from a known address (e.g. the game restarted) starts over
	if c != nil && seg.Header.Has(srp.FlagSYN) {
		s.remove(c)
		c = nil
	}
	if c == nil && !seg.Header.Has(srp.FlagFIN) {
		if !s.hasRoom(from.Addr()) {
			s.Log.Warnf("NAT table full, ignoring %s", from)
			return nil, nil
		}
		c = &Client{Addr: from}
		s.clients = append(s.clients, c)
		s.Log.Debugf("added client %s", from)
	}
	if c != nil {
		c.lastSeen = now
	}
	var out []Packet
	switch {
	case seg.Window != nil && c != nil:
		// connect (SYN)
		out = append(out, Packet{c.srp.Respond(seg, nil), from})
	case seg.Msg != nil && c != nil:
		// the address request; the address is sent when the game pings
		if seg.Msg.Header.Type != gsm.NAT {
			return nil, errors.New("not a NAT message")
		}
		c.natReq = seg.Msg
		if c.pingID == 0 {
			c.pingID = s.newPingID()
		}
		msg, err := natReply(c.natReq, msgPortID, c.pingID, s.Port)
		if err != nil {
			return nil, err
		}
		out = append(out, Packet{c.srp.Respond(seg, msg), from})
	}
	if seg.Header.Has(srp.FlagFIN) && c != nil {
		s.remove(c)
		s.Log.Debugf("removed client %s", from)
	}
	return out, nil
}

// RemoveSilent drops the clients nothing came from for ClientTimeout.
func (s *Server) RemoveSilent(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.clients[:0]
	for _, c := range s.clients {
		if now.Sub(c.lastSeen) > ClientTimeout {
			s.Log.Debugf("expired client %s", c.Addr)
			continue
		}
		kept = append(kept, c)
	}
	s.clients = kept
}

// Clients returns the number of clients.
func (s *Server) Clients() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.clients)
}

// Serve runs the service on the socket until it is closed.
func (s *Server) Serve(conn *net.UDPConn) {
	buf := make([]byte, 2048)
	last := time.Now()
	for {
		conn.SetReadDeadline(time.Now().Add(tick))
		n, from, err := conn.ReadFromUDPAddrPort(buf)
		now := time.Now()
		if now.Sub(last) >= time.Second {
			s.RemoveSilent(now)
			last = now
		}
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			s.Log.Warnf("read: %v", err)
			continue
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		// one bad packet must not stop the service
		func() {
			defer func() {
				if r := recover(); r != nil {
					s.Log.Errorf("bad packet from %s: internal error %v", from, r)
				}
			}()
			packets, err := s.HandlePacket(buf[:n], from, now)
			if err != nil {
				s.Log.Warnf("bad packet from %s: %v", from, err)
				return
			}
			for _, p := range packets {
				conn.WriteToUDPAddrPort(p.Data, p.To)
			}
		}()
	}
}
