package nat

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/gsm"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/logx"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/srp"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/testvec"
)

var (
	game     = netip.MustParseAddrPort("127.0.0.1:1024")
	gamePort = netip.MustParseAddrPort("127.0.0.1:8888")
)

func vec(t *testing.T, key string) []byte {
	var s string
	testvec.Get(t, testvec.Load(t), key, &s)
	return testvec.Hex(t, s)
}

func newServer() *Server {
	return &Server{Log: logx.Discard(), Port: 7781, MaxClients: 4096, MaxPerIP: 16}
}

func TestReplyVectors(t *testing.T) {
	req, err := gsm.Decode(vec(t, "nat_request"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := natReply(req, msgPortID, 0xDEADBEEF, 7781); !bytes.Equal(got, vec(t, "nat_port_id")) {
		t.Errorf("PORT_ID %x", got)
	}
	ip := binary.BigEndian.Uint32([]byte{192, 168, 0, 41})
	if got, _ := natReply(req, msgAddress, ip, 8888); !bytes.Equal(got, vec(t, "nat_address")) {
		t.Errorf("ADDRESS %x", got)
	}
}

// connect does the SYN and the address request; it returns the ping id.
func connect(t *testing.T, s *Server, now time.Time) uint32 {
	t.Helper()
	if out, err := s.HandlePacket(vec(t, "srp_syn"), game, now); err != nil || len(out) != 1 {
		t.Fatalf("SYN: %v", err)
	}
	out, err := s.HandlePacket(vec(t, "srp_msg"), game, now)
	if err != nil || len(out) != 1 {
		t.Fatalf("request: %v", err)
	}
	seg, err := srp.Parse(out[0].Data)
	if err != nil {
		t.Fatal(err)
	}
	args, _ := seg.Msg.Data.List(1)
	s1, _ := args.Str(1)
	id, _ := strconv.ParseInt(s1, 10, 32)
	return uint32(int32(id))
}

func ping(id uint32) []byte { return binary.BigEndian.AppendUint32(nil, id) }

func TestPing(t *testing.T) {
	s := newServer()
	id := connect(t, s, time.Unix(0, 0))
	out, err := s.HandlePacket(ping(id), gamePort, time.Unix(25, 0))
	if err != nil || len(out) != 1 || out[0].To != game {
		t.Fatalf("ping: %v %v", out, err)
	}
	seg, _ := srp.Parse(out[0].Data)
	if got := seg.Msg.Data.String(); got != "['3', ['1', '2130706433', '8888']]" {
		t.Fatalf("address %s", got)
	}
	// later pings get a bare ACK: one address per request, or the game's receive buffer fills up
	out, _ = s.HandlePacket(ping(id), gamePort, time.Unix(50, 0))
	if len(out) != 1 || len(out[0].Data) != srp.HeaderSize {
		t.Fatalf("second ping: %v", out)
	}
	h, _ := srp.ParseHeader(out[0].Data)
	if h.Seg != 0xFFFF || h.DataSize != 0 || h.Flags != srp.FlagID|srp.FlagACK || h.Checksum != srp.Checksum(append([]byte{0xb7, 0x1a}, out[0].Data[2:]...)) {
		t.Fatalf("ACK %+v", h)
	}
	// a new request gets its address on the next ping
	s.HandlePacket(vec(t, "srp_msg"), game, time.Unix(60, 0))
	if out, _ := s.HandlePacket(ping(id), gamePort, time.Unix(61, 0)); len(out) != 1 || len(out[0].Data) == srp.HeaderSize {
		t.Fatal("no address for the second request")
	}
	if out, _ := s.HandlePacket(ping(id^1), gamePort, time.Unix(26, 0)); len(out) != 0 {
		t.Fatal("unknown ping answered")
	}
	if out, _ := s.HandlePacket([]byte{0, 0}, gamePort, time.Unix(26, 0)); len(out) != 0 {
		t.Fatal("short ping answered")
	}
}

func TestPingIDs(t *testing.T) {
	s := newServer()
	ids := map[uint32]bool{}
	for i := 0; i < 50; i++ {
		s.clients = append(s.clients, &Client{Addr: netip.AddrPortFrom(game.Addr(), uint16(2000+i)), pingID: s.newPingID()})
	}
	for _, c := range s.clients {
		if c.pingID == 0 || ids[c.pingID] {
			t.Fatal("ping id zero or reused")
		}
		ids[c.pingID] = true
	}
}

func TestExpiry(t *testing.T) {
	s := newServer()
	id := connect(t, s, time.Unix(0, 0))
	s.RemoveSilent(time.Unix(0, 0).Add(ClientTimeout - time.Second))
	if s.Clients() != 1 {
		t.Fatal("expired early")
	}
	s.HandlePacket(ping(id), gamePort, time.Unix(100, 0))
	s.RemoveSilent(time.Unix(0, 0).Add(ClientTimeout + time.Second))
	if s.Clients() != 1 {
		t.Fatal("a ping doesn't keep the client")
	}
	s.RemoveSilent(time.Unix(100, 0).Add(ClientTimeout + time.Second))
	if s.Clients() != 0 {
		t.Fatal("not expired")
	}
}

func TestReconnect(t *testing.T) {
	s := newServer()
	old := connect(t, s, time.Unix(0, 0))
	again := connect(t, s, time.Unix(10, 0))
	if s.Clients() != 1 || old == again || s.clients[0].srp.SegmentID != 2 {
		t.Fatal("a SYN from a known address must start over")
	}
}

func TestCaps(t *testing.T) {
	s := newServer()
	s.MaxPerIP = 3
	s.MaxClients = 5
	syn := vec(t, "srp_syn")
	for p := 0; p < 10; p++ {
		s.HandlePacket(syn, netip.AddrPortFrom(game.Addr(), uint16(3000+p)), time.Now())
	}
	if s.Clients() != 3 {
		t.Fatalf("per-address cap: %d", s.Clients())
	}
	for i := 0; i < 10; i++ {
		s.HandlePacket(syn, netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 1, byte(i), 1}), 1000), time.Now())
	}
	if s.Clients() != 5 {
		t.Fatalf("total cap: %d", s.Clients())
	}
}

type fakeRelay struct{}

func (fakeRelay) Observed(real netip.AddrPort) (netip.AddrPort, bool) {
	return netip.MustParseAddrPort("203.0.113.5:9001"), true
}

func (fakeRelay) Release(netip.AddrPort) {}

// portsRelay holds a relay port per address, as the relay does.
type portsRelay map[netip.AddrPort]bool

func (r portsRelay) Observed(real netip.AddrPort) (netip.AddrPort, bool) {
	r[real] = true
	return fakeRelay{}.Observed(real)
}

func (r portsRelay) Release(real netip.AddrPort) { delete(r, real) }

// Pings with a client's id from many addresses (forged sources) hold one relay port, not one each.
func TestRelayPortPerClient(t *testing.T) {
	s := newServer()
	r := portsRelay{}
	s.Relay = r
	id := connect(t, s, time.Unix(0, 0))
	for i := range 50 {
		from := netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}), 8888)
		s.HandlePacket(ping(id), from, time.Unix(1, 0))
	}
	if len(r) != 1 {
		t.Fatalf("%d relay ports for one client", len(r))
	}
}

func TestRelayAddress(t *testing.T) {
	s := newServer()
	s.Relay = fakeRelay{}
	id := connect(t, s, time.Unix(0, 0))
	out, _ := s.HandlePacket(ping(id), gamePort, time.Unix(1, 0))
	seg, _ := srp.Parse(out[0].Data)
	ip := int32(binary.BigEndian.Uint32([]byte{203, 0, 113, 5}))
	if got, want := seg.Msg.Data.String(), "['3', ['1', '"+strconv.Itoa(int(ip))+"', '9001']]"; got != want {
		t.Fatalf("relay address %s, want %s", got, want)
	}
}

func FuzzPacket(f *testing.F) {
	f.Add(make([]byte, 20))
	f.Add([]byte{0, 0, 0, 1})
	s := newServer()
	f.Fuzz(func(t *testing.T, b []byte) {
		s.HandlePacket(b, game, time.Now())
	})
}
