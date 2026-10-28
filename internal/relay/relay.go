// Package relay forwards the players' peer-to-peer game traffic through the server, so no player learns
// another's address and nobody needs to forward their game port.
//
// Each player gets one relay port when the NAT service sees its game port (its ping). Every other
// player is told that port as the player's address: in the NAT reply (which the game advertises as its
// own address), the room info and member data. A datagram that peer Y sends to player X's relay port is
// forwarded to X's real address from Y's relay port, so X sees every peer at one consistent address,
// the one it was told. Only verified addresses (seen by the NAT service) of players in the same room or
// game are forwarded between, at a capped rate.
package relay

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/logx"
)

// Defaults.
const (
	DefaultPortMin = 9000
	DefaultPortMax = 9999
	// DefaultIdle frees a relay port nothing used for this long (pings, traffic).
	DefaultIdle = 5 * time.Minute
	// DefaultPacketsPerSecond and DefaultBytesPerSecond cap what a relay port forwards to its player.
	DefaultPacketsPerSecond = 400
	DefaultBytesPerSecond   = 256 * 1024
)

// Config configures the relay.
type Config struct {
	Bind             string // listening address
	Host             string // advertised address (UBIGS_HOST); empty: the address each player reaches
	PortMin, PortMax int
	MaxPerIP         int
	Idle             time.Duration
	PacketsPerSecond float64
	BytesPerSecond   float64
}

// Relay is the running relay.
type Relay struct {
	cfg Config
	Log *logx.Logger
	// Peers reports whether two player addresses may reach each other (same room or game).
	Peers func(a, b string) bool

	hostIP netip.Addr // resolved Host, if set

	mu      sync.Mutex
	byReal  map[netip.AddrPort]*endpoint
	byPort  map[uint16]*endpoint
	next    int
	routes  map[netip.Addr]netip.Addr
	closed  bool
	allowed map[[2]netip.Addr]time.Time // cache of Peers answers
	wg      sync.WaitGroup
	totals  Stats
}

type endpoint struct {
	real   netip.AddrPort
	port   uint16
	conn   *net.UDPConn
	seen   time.Time // last ping or traffic
	tokens float64
	bytes  float64
	refill time.Time
	stats  Stats
}

// Stats count what a relay port forwarded.
type Stats struct {
	Packets, Bytes, Dropped uint64
	// Delay is the total time between receiving and sending the forwarded datagrams.
	Delay time.Duration
}

// New returns a relay; Start begins serving.
func New(cfg Config, log *logx.Logger) (*Relay, error) {
	if cfg.PortMin <= 0 || cfg.PortMax < cfg.PortMin || cfg.PortMax > 65535 {
		return nil, fmt.Errorf("relay: bad port range %d-%d", cfg.PortMin, cfg.PortMax)
	}
	if cfg.Idle <= 0 {
		cfg.Idle = DefaultIdle
	}
	if cfg.PacketsPerSecond <= 0 {
		cfg.PacketsPerSecond = DefaultPacketsPerSecond
	}
	if cfg.BytesPerSecond <= 0 {
		cfg.BytesPerSecond = DefaultBytesPerSecond
	}
	if cfg.MaxPerIP <= 0 {
		cfg.MaxPerIP = 16
	}
	r := &Relay{cfg: cfg, Log: log, byReal: map[netip.AddrPort]*endpoint{}, byPort: map[uint16]*endpoint{},
		next: cfg.PortMin, routes: map[netip.Addr]netip.Addr{}, allowed: map[[2]netip.Addr]time.Time{}}
	if cfg.Host != "" {
		if a, err := netip.ParseAddr(cfg.Host); err == nil && a.Unmap().Is4() {
			r.hostIP = a.Unmap()
		} else {
			ips, err := net.LookupIP(cfg.Host)
			if err != nil {
				return nil, fmt.Errorf("relay: resolving %s: %w", cfg.Host, err)
			}
			for _, ip := range ips {
				if v4 := ip.To4(); v4 != nil {
					r.hostIP = netip.AddrFrom4([4]byte(v4))
					break
				}
			}
			if !r.hostIP.IsValid() {
				return nil, fmt.Errorf("relay: %s has no IPv4 address", cfg.Host)
			}
		}
	}
	return r, nil
}

// Ports returns the relay's port range.
func (r *Relay) Ports() (int, int) { return r.cfg.PortMin, r.cfg.PortMax }

// hostFor is the relay's address as the player at ip reaches it.
func (r *Relay) hostFor(ip netip.Addr) netip.Addr {
	if r.hostIP.IsValid() {
		return r.hostIP
	}
	if ip.IsLoopback() {
		return netip.AddrFrom4([4]byte{127, 0, 0, 1})
	}
	if a, ok := r.routes[ip]; ok {
		return a
	}
	// the local address the system would send to the player from; no packet is sent
	a := netip.IPv4Unspecified()
	if c, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, 9))); err == nil {
		if la, ok := c.LocalAddr().(*net.UDPAddr); ok {
			if v, ok := netip.AddrFromSlice(la.IP); ok {
				a = v.Unmap()
			}
		}
		c.Close()
	}
	r.routes[ip] = a
	return a
}

// Observed is the NAT service's hook: the player's verified public address. It returns the relay
// address the player is told instead, allocating a relay port on first sight.
func (r *Relay) Observed(real netip.AddrPort) (netip.AddrPort, bool) {
	real = netip.AddrPortFrom(real.Addr().Unmap(), real.Port())
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return netip.AddrPort{}, false
	}
	e := r.byReal[real]
	if e == nil {
		var err error
		if e, err = r.allocate(real); err != nil {
			r.Log.Warnf("no relay port for %s: %v", real, err)
			return netip.AddrPort{}, false
		}
	}
	e.seen = time.Now()
	return netip.AddrPortFrom(r.hostFor(real.Addr()), e.port), true
}

// allocate opens a relay port for a player. r.mu is held.
func (r *Relay) allocate(real netip.AddrPort) (*endpoint, error) {
	n := 0
	for _, e := range r.byReal {
		if e.real.Addr() == real.Addr() {
			n++
		}
	}
	if n >= r.cfg.MaxPerIP {
		return nil, errors.New("too many relay ports for the address")
	}
	size := r.cfg.PortMax - r.cfg.PortMin + 1
	for i := 0; i < size; i++ {
		port := r.next
		r.next++
		if r.next > r.cfg.PortMax {
			r.next = r.cfg.PortMin
		}
		if r.byPort[uint16(port)] != nil {
			continue
		}
		addr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(r.cfg.Bind, fmt.Sprint(port)))
		if err != nil {
			return nil, err
		}
		conn, err := net.ListenUDP("udp4", addr)
		if err != nil {
			continue // taken by another program
		}
		now := time.Now()
		e := &endpoint{real: real, port: uint16(port), conn: conn, seen: now, refill: now,
			tokens: r.cfg.PacketsPerSecond, bytes: r.cfg.BytesPerSecond}
		r.byReal[real] = e
		r.byPort[e.port] = e
		r.wg.Add(1)
		go r.forward(e)
		r.Log.Infof("relay port %d for %s", port, real)
		return e, nil
	}
	return nil, errors.New("the relay port range is used up")
}

// PeerAddr is the lobby's hook: the relay address standing for the player at playerIP, as the player
// at viewerIP reaches it. A hint naming one of the player's relay ports picks it.
func (r *Relay) PeerAddr(playerIP string, hint netip.AddrPort, viewerIP string) (netip.AddrPort, bool) {
	player, err := netip.ParseAddr(playerIP)
	if err != nil {
		return netip.AddrPort{}, false
	}
	viewer, err := netip.ParseAddr(viewerIP)
	if err != nil {
		return netip.AddrPort{}, false
	}
	player = player.Unmap()
	r.mu.Lock()
	defer r.mu.Unlock()
	var best *endpoint
	if e := r.byPort[hint.Port()]; e != nil && hint.Port() != 0 && e.real.Addr() == player {
		best = e
	} else if e := r.byReal[netip.AddrPortFrom(hint.Addr().Unmap(), hint.Port())]; e != nil && e.real.Addr() == player {
		best = e
	} else {
		for _, e := range r.byReal {
			if e.real.Addr() == player && (best == nil || e.seen.After(best.seen)) {
				best = e
			}
		}
	}
	if best == nil {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(r.hostFor(viewer.Unmap()), best.port), true
}

// IsRelayAddr reports whether a is one of the relay's addresses.
func (r *Relay) IsRelayAddr(a netip.AddrPort) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.byPort[a.Port()] != nil
}

// peers asks the lobby, with a short cache (it runs per datagram).
func (r *Relay) peers(a, b netip.Addr, now time.Time) bool {
	key := [2]netip.Addr{a, b}
	r.mu.Lock()
	until, ok := r.allowed[key]
	r.mu.Unlock()
	if ok && now.Before(until) {
		return true
	}
	if r.Peers == nil || !r.Peers(a.String(), b.String()) {
		return false
	}
	r.mu.Lock()
	r.allowed[key] = now.Add(2 * time.Second)
	r.mu.Unlock()
	return true
}

// forward relays what arrives on a player's relay port to the player, from the sender's relay port.
func (r *Relay) forward(dst *endpoint) {
	defer r.wg.Done()
	buf := make([]byte, 65536)
	for {
		n, from, err := dst.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		start := time.Now()
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		r.mu.Lock()
		src := r.byReal[from]
		ok := src != nil && src != dst && !r.closed
		var out *net.UDPConn
		if ok {
			out = src.conn
		}
		r.mu.Unlock()
		// only verified players of the same room or game, never arbitrary hosts
		if !ok || !r.peers(from.Addr(), dst.real.Addr(), start) {
			r.drop(dst)
			continue
		}
		if !r.take(dst, n, start) {
			r.drop(dst)
			continue
		}
		if _, err := out.WriteToUDPAddrPort(buf[:n], dst.real); err != nil {
			r.drop(dst)
			continue
		}
		r.mu.Lock()
		delay := time.Since(start)
		for _, s := range []*Stats{&dst.stats, &r.totals} {
			s.Packets++
			s.Bytes += uint64(n)
			s.Delay += delay
		}
		dst.seen = start
		src.seen = start
		r.mu.Unlock()
	}
}

func (r *Relay) drop(e *endpoint) {
	r.mu.Lock()
	e.stats.Dropped++
	r.totals.Dropped++
	r.mu.Unlock()
}

// take spends rate tokens for a datagram to the endpoint's player.
func (r *Relay) take(e *endpoint, size int, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	dt := now.Sub(e.refill).Seconds()
	e.refill = now
	e.tokens = min(r.cfg.PacketsPerSecond, e.tokens+dt*r.cfg.PacketsPerSecond)
	e.bytes = min(r.cfg.BytesPerSecond, e.bytes+dt*r.cfg.BytesPerSecond)
	if e.tokens < 1 || e.bytes < float64(size) {
		return false
	}
	e.tokens--
	e.bytes -= float64(size)
	return true
}

// Forget frees the relay ports of a player address (its game connection ended).
func (r *Relay) Forget(ip string) {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.byReal {
		if e.real.Addr() == a.Unmap() {
			r.free(e, "the player left")
		}
	}
}

// free closes a relay port. r.mu is held.
func (r *Relay) free(e *endpoint, why string) {
	delete(r.byReal, e.real)
	delete(r.byPort, e.port)
	e.conn.Close()
	s := e.stats
	avg := time.Duration(0)
	if s.Packets > 0 {
		avg = s.Delay / time.Duration(s.Packets)
	}
	r.Log.Infof("relay port %d of %s closed (%s): %d datagrams, %d bytes forwarded, %d dropped, %v added per datagram",
		e.port, e.real, why, s.Packets, s.Bytes, s.Dropped, avg)
}

// Expire frees ports idle since before now - Idle.
func (r *Relay) Expire(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.byReal {
		if now.Sub(e.seen) > r.cfg.Idle {
			r.free(e, "idle")
		}
	}
	for k, until := range r.allowed {
		if now.After(until) {
			delete(r.allowed, k)
		}
	}
}

// Run expires idle ports until stop is closed, then closes every port.
func (r *Relay) Run(stop <-chan struct{}) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case now := <-t.C:
			r.Expire(now)
		case <-stop:
			r.Close()
			return
		}
	}
}

// Close closes every relay port.
func (r *Relay) Close() {
	r.mu.Lock()
	r.closed = true
	for _, e := range r.byReal {
		r.free(e, "shutdown")
	}
	r.mu.Unlock()
	r.wg.Wait()
}

// Totals returns what the relay forwarded so far.
func (r *Relay) Totals() Stats {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.totals
}

// Endpoints lists the open relay ports and their players, for logs and tests.
func (r *Relay) Endpoints() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, e := range r.byReal {
		out = append(out, fmt.Sprintf("%d=%s", e.port, e.real))
	}
	sort.Strings(out)
	return out
}
