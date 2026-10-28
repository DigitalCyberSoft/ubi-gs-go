package guard

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/accounts"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newGuard(t *testing.T, cfg Config) (*Guard, *clock) {
	s, err := accounts.Open(accounts.Memory, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	g := New(s, cfg)
	c := &clock{time.Unix(1_000_000, 0)}
	g.SetClock(c.now)
	return g, c
}

func TestNewAccountsPerIP(t *testing.T) {
	g, c := newGuard(t, Config{NewAccountsPerIPHour: 2})
	for _, n := range []string{"a", "b"} {
		if _, err := g.Login("10.0.0.1", n, "pw"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := g.Login("10.0.0.1", "c", "pw"); err != ErrTooManyAccounts {
		t.Fatalf("third account: %v", err)
	}
	// logging in to an existing account isn't limited, other addresses aren't either
	if _, err := g.Login("10.0.0.1", "a", "pw"); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Login("10.0.0.2", "c", "pw"); err != nil {
		t.Fatal(err)
	}
	c.t = c.t.Add(61 * time.Minute)
	if _, err := g.Login("10.0.0.1", "d", "pw"); err != nil {
		t.Fatalf("after an hour: %v", err)
	}
}

func TestMaxAccounts(t *testing.T) {
	g, _ := newGuard(t, Config{MaxAccounts: 2})
	g.Login("10.0.0.1", "a", "pw")
	g.Login("10.0.0.2", "b", "pw")
	if _, err := g.Login("10.0.0.3", "c", "pw"); err != ErrTooManyAccounts {
		t.Fatalf("over the cap: %v", err)
	}
}

func TestLoginRate(t *testing.T) {
	g, c := newGuard(t, Config{LoginsPerIPMinute: 3})
	for i := 0; i < 3; i++ {
		if _, err := g.Login("10.0.0.1", "a", "pw"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := g.Login("10.0.0.1", "a", "pw"); err != ErrSlowDown {
		t.Fatalf("fourth login in a minute: %v", err)
	}
	c.t = c.t.Add(61 * time.Second)
	if _, err := g.Login("10.0.0.1", "a", "pw"); err != nil {
		t.Fatal(err)
	}
}

func TestBackoffAfterMisses(t *testing.T) {
	g, c := newGuard(t, Config{MaxBackoff: time.Minute})
	g.Login("10.0.0.1", "alice", "secret")
	// guessing alice's password: the first miss is free (a new player picking a taken name)
	if a, err := g.Login("10.0.0.9", "alice", "guess1"); err != nil || a.Name != "alice-1" {
		t.Fatalf("%v %v", a, err)
	}
	if _, err := g.Login("10.0.0.9", "alice", "guess2"); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Login("10.0.0.9", "alice", "guess3"); err != ErrSlowDown {
		t.Fatalf("no back-off: %v", err)
	}
	// the real owner elsewhere isn't affected
	if _, err := g.Login("10.0.0.1", "alice", "secret"); err != nil {
		t.Fatal(err)
	}
	c.t = c.t.Add(3 * time.Second)
	if _, err := g.Login("10.0.0.9", "alice", "guess3"); err != nil {
		t.Fatalf("after the back-off: %v", err)
	}
	// alice-1 logging in again is not a miss
	if a, err := g.Login("10.0.0.9", "alice", "guess1"); err != ErrSlowDown && (err != nil || a.Name != "alice-1") {
		t.Fatalf("%v %v", a, err)
	}
}

func TestHashPoolBound(t *testing.T) {
	g, _ := newGuard(t, Config{HashWorkers: 2})
	var running, peak atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			g.hash(func() {
				n := running.Add(1)
				for {
					p := peak.Load()
					if n <= p || peak.CompareAndSwap(p, n) {
						break
					}
				}
				time.Sleep(20 * time.Millisecond)
				running.Add(-1)
			})
		}()
	}
	wg.Wait()
	if peak.Load() != 2 {
		t.Fatalf("%d hashes at once, want 2", peak.Load())
	}
}

func BenchmarkScrypt(b *testing.B) {
	s, _ := accounts.Open(accounts.Memory, nil)
	defer s.Close()
	s.Login("alice", "pw")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Login("alice", "pw")
	}
}
