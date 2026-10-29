package irc_test

import (
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/irc"
)

func got(lines []string, code string) bool {
	return has(lines, func(l string) bool { return strings.Contains(l, " "+code+" ") })
}

// closed waits up to d for the server to close c's connection.
func closed(c net.Conn, d time.Duration) bool {
	c.SetReadDeadline(time.Now().Add(d))
	buf := make([]byte, 1024)
	for {
		if _, err := c.Read(buf); err != nil {
			ne, ok := err.(net.Error)
			return !ok || !ne.Timeout()
		}
	}
}

// Before its nick is accepted, a connection can't listen in on a channel or set its topic.
func TestNothingBeforeRegistering(t *testing.T) {
	s := start(t, 30*time.Second, nil)
	alice := s.player(t, "", "alice", true)
	anon := s.player(t, "", "", false)
	anon.Send("JOIN :" + channel)
	if !got(anon.Read(300*time.Millisecond), "451") {
		t.Fatal("JOIN before registering wasn't refused")
	}
	anon.Send("TOPIC " + channel + " :orders")
	if !got(anon.Read(300*time.Millisecond), "451") {
		t.Fatal("TOPIC before registering wasn't refused")
	}
	alice.Send("PRIVMSG " + channel + " :alice%16777215%9%0%0%Arial%1hi")
	if has(anon.Read(300*time.Millisecond), func(l string) bool { return strings.Contains(l, "PRIVMSG") }) {
		t.Fatal("an unregistered connection got the channel's chat")
	}
}

func TestNeverRegisteredDropped(t *testing.T) {
	s := start(t, time.Second, nil)
	if !closed(s.player(t, "", "", false).Conn, 3*time.Second) {
		t.Fatal("a connection that never registered was kept")
	}
}

func TestChannelLimits(t *testing.T) {
	s := startWith(t, 30*time.Second, nil, func(s *irc.Server) { s.MaxChannelMembers = 2 })
	alice := s.player(t, "", "alice", true)
	s.player(t, "", "bob", true)
	carol := s.player(t, "", "carol", false)
	carol.Send("JOIN :" + channel)
	if !got(carol.Read(300*time.Millisecond), "471") {
		t.Fatal("joined a full channel")
	}
	for i := 1; i < irc.MaxChannelsPerClient; i++ {
		alice.Send(fmt.Sprintf("JOIN :#LobbyGrp1.%d", i))
	}
	alice.Read(300 * time.Millisecond)
	alice.Send("JOIN :#LobbyGrp1.99")
	if !got(alice.Read(300*time.Millisecond), "405") {
		t.Fatalf("joined more than %d channels", irc.MaxChannelsPerClient)
	}
}

func TestMessageRate(t *testing.T) {
	s := start(t, 30*time.Second, nil)
	alice, bob := s.player(t, "", "alice", true), s.player(t, "", "bob", true)
	alice.Read(100 * time.Millisecond)
	for i := range 2 * irc.MessageBurst {
		bob.Send(fmt.Sprintf("PRIVMSG %s :bob%%16777215%%9%%0%%0%%Arial%%1message %d", channel, i))
	}
	n := 0
	for _, l := range alice.Read(500 * time.Millisecond) {
		if strings.Contains(l, " PRIVMSG ") {
			n++
		}
	}
	// the burst, and at most what refills while the messages arrive
	if n < irc.MessageBurst || n > irc.MessageBurst+2 {
		t.Fatalf("%d of %d messages relayed, want about %d", n, 2*irc.MessageBurst, irc.MessageBurst)
	}
}

// The nick must stay a logged-in account: once the account isn't, its connection is dropped when it
// next acts, or at its next keepalive if it only listens.
func TestDroppedAfterLogout(t *testing.T) {
	var logged atomic.Bool
	policy := func(nick, ip string) bool { return logged.Load() }
	logged.Store(true)
	s := start(t, 30*time.Second, policy)
	alice := s.player(t, "", "alice", true)
	logged.Store(false)
	alice.Send("PRIVMSG " + channel + " :alice%16777215%9%0%0%Arial%1still here?")
	if !closed(alice.Conn, time.Second) {
		t.Fatal("a logged-out account kept chatting")
	}

	logged.Store(true)
	quick := start(t, time.Second, policy)
	bob := quick.player(t, "", "bob", true)
	logged.Store(false)
	if !closed(bob.Conn, 3*time.Second) {
		t.Fatal("a logged-out account kept listening")
	}
}
