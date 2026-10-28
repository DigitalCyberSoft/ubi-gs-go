package relay

import (
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/logx"
)

func newRelay(t *testing.T, cfg Config) *Relay {
	t.Helper()
	ln, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	base := ln.LocalAddr().(*net.UDPAddr).Port
	ln.Close()
	if cfg.PortMin == 0 {
		cfg.PortMin, cfg.PortMax = base, base+20
	}
	cfg.Bind = "127.0.0.1"
	r, err := New(cfg, logx.Discard())
	if err != nil {
		t.Fatal(err)
	}
	r.Peers = func(a, b string) bool { return true }
	t.Cleanup(r.Close)
	return r
}

func game(t *testing.T) (*net.UDPConn, netip.AddrPort) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c, c.LocalAddr().(*net.UDPAddr).AddrPort()
}

func recv(c *net.UDPConn, d time.Duration) (string, netip.AddrPort, bool) {
	buf := make([]byte, 2048)
	c.SetReadDeadline(time.Now().Add(d))
	n, from, err := c.ReadFromUDPAddrPort(buf)
	return string(buf[:n]), from, err == nil
}

func TestConsistentAddresses(t *testing.T) {
	r := newRelay(t, Config{})
	a, ra := game(t)
	b, rb := game(t)
	c, rc := game(t)
	A, _ := r.Observed(ra)
	B, _ := r.Observed(rb)
	C, _ := r.Observed(rc)
	if again, _ := r.Observed(ra); again != A {
		t.Fatal("a second ping got another port")
	}
	// each game sees each peer at the one address it was told
	b.WriteToUDPAddrPort([]byte("b->a"), A)
	c.WriteToUDPAddrPort([]byte("c->a"), A)
	for i := 0; i < 2; i++ {
		msg, from, ok := recv(a, time.Second)
		if !ok || (msg == "b->a" && from != B) || (msg == "c->a" && from != C) {
			t.Fatalf("%q from %s", msg, from)
		}
	}
	a.WriteToUDPAddrPort([]byte("a->c"), C)
	if msg, from, ok := recv(c, time.Second); !ok || msg != "a->c" || from != A {
		t.Fatalf("%q from %s", msg, from)
	}
	if got, ok := r.PeerAddr("127.0.0.1", B, "127.0.0.1"); !ok || got != B {
		t.Fatalf("PeerAddr with a hint: %s", got)
	}
}

func TestOnlyPeers(t *testing.T) {
	r := newRelay(t, Config{})
	var allow atomic.Bool
	r.Peers = func(a, b string) bool { return allow.Load() }
	a, ra := game(t)
	b, rb := game(t)
	A, _ := r.Observed(ra)
	r.Observed(rb)
	b.WriteToUDPAddrPort([]byte("x"), A)
	if _, _, ok := recv(a, 300*time.Millisecond); ok {
		t.Fatal("forwarded between players who aren't in one room")
	}
	// an address the NAT service never saw
	stranger, _ := game(t)
	allow.Store(true)
	stranger.WriteToUDPAddrPort([]byte("y"), A)
	if _, _, ok := recv(a, 300*time.Millisecond); ok {
		t.Fatal("forwarded from an unverified address")
	}
	if r.Totals().Dropped != 2 {
		t.Fatalf("dropped %d", r.Totals().Dropped)
	}
}

func TestRateLimit(t *testing.T) {
	r := newRelay(t, Config{PacketsPerSecond: 10, BytesPerSecond: 1 << 20})
	a, ra := game(t)
	b, rb := game(t)
	A, _ := r.Observed(ra)
	r.Observed(rb)
	for i := 0; i < 50; i++ {
		b.WriteToUDPAddrPort([]byte("flood"), A)
	}
	n := 0
	for {
		if _, _, ok := recv(a, 200*time.Millisecond); !ok {
			break
		}
		n++
	}
	if n < 5 || n > 15 {
		t.Fatalf("%d of 50 datagrams forwarded at 10/s", n)
	}
}

func TestExpiryAndCaps(t *testing.T) {
	r := newRelay(t, Config{MaxPerIP: 2, Idle: time.Minute})
	_, ra := game(t)
	_, rb := game(t)
	_, rc := game(t)
	r.Observed(ra)
	r.Observed(rb)
	if _, ok := r.Observed(rc); ok {
		t.Fatal("over the per-address cap")
	}
	r.Expire(time.Now().Add(2 * time.Minute))
	if len(r.Endpoints()) != 0 {
		t.Fatal("idle ports kept")
	}
	if _, ok := r.Observed(rc); !ok {
		t.Fatal("no port after expiry")
	}
	r.Forget("127.0.0.1")
	if len(r.Endpoints()) != 0 {
		t.Fatal("Forget kept ports")
	}
}

func TestRangeUsedUp(t *testing.T) {
	r := newRelay(t, Config{})
	r.cfg.PortMin, r.cfg.PortMax, r.next = 1, 1, 1 // a port this user can't bind
	_, ra := game(t)
	if _, ok := r.Observed(ra); ok {
		t.Fatal("allocated from an unusable range")
	}
}
