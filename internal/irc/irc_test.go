package irc_test

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/gsclient"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/irc"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/limits"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/logx"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/netsrv"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/testvec"
)

const channel = "#LobbyGrp1.1000"

func TestFrameVectors(t *testing.T) {
	var vs []struct{ Line, Frame string }
	testvec.Get(t, testvec.Load(t), "irc", &vs)
	for _, v := range vs {
		got, err := irc.Frame(testvec.Hex(t, v.Line))
		if err != nil || !bytes.Equal(got, testvec.Hex(t, v.Frame)) {
			t.Errorf("frame %s: %x", v.Line, got)
		}
	}
}

func TestChatVectors(t *testing.T) {
	var vs []struct {
		Nick, Payload string
		Result        *string
	}
	testvec.Get(t, testvec.Load(t), "chat", &vs)
	for _, v := range vs {
		got, ok := irc.SanitizeChat(v.Nick, v.Payload)
		if (v.Result == nil) != !ok || (ok && got != *v.Result) {
			t.Errorf("SanitizeChat(%q) = %q %v, want %v", v.Payload, got, ok, v.Result)
		}
	}
}

type server struct {
	addr string
	srv  *irc.Server
	ln   net.Listener
}

// start runs the IRC service on loopback; allowed restricts nicks (nil: any).
func start(t *testing.T, timeout time.Duration, allowed irc.NickPolicy) *server {
	return startWith(t, timeout, allowed, nil)
}

// startWith is start with edit changing the server's settings before it serves.
func startWith(t *testing.T, timeout time.Duration, allowed irc.NickPolicy, edit func(*irc.Server)) *server {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := irc.New(logx.Discard(), timeout)
	s.Allowed = allowed
	if edit != nil {
		edit(s)
	}
	ns := &netsrv.Server{Name: "irc", Log: logx.Discard(), Limits: limits.New(10, 3), Timeout: timeout, Handle: s.Serve}
	done := make(chan struct{})
	go func() { ns.Serve(t.Context(), ln); close(done) }()
	t.Cleanup(func() { ln.Close(); <-done })
	return &server{addr: ln.Addr().String(), srv: s, ln: ln}
}

func (s *server) player(t *testing.T, from, nick string, joinChannel bool) *gsclient.IRC {
	c, err := gsclient.NewIRC(from, s.addr, nick)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	if joinChannel {
		c.Send("JOIN :" + channel)
	}
	c.Read(300 * time.Millisecond)
	return c
}

func has(lines []string, f func(string) bool) bool {
	for _, l := range lines {
		if f(l) {
			return true
		}
	}
	return false
}

func alive(c *gsclient.IRC) bool {
	c.Send("PING :check")
	return has(c.Read(300*time.Millisecond), func(l string) bool { return strings.Contains(l, "PONG") })
}

func TestChat(t *testing.T) {
	s := start(t, 30*time.Second, nil)
	alice, bob := s.player(t, "", "alice", true), s.player(t, "", "bob", true)
	alice.Read(100 * time.Millisecond)
	bob.Send("PRIVMSG " + channel + " :alice%16777215%9%0%0%Arial%1I give up")
	lines := alice.Read(300 * time.Millisecond)
	if !has(lines, func(l string) bool {
		return strings.HasSuffix(l, "PRIVMSG "+channel+" :bob%16777215%9%0%0%Arial%1I give up")
	}) {
		t.Fatalf("the name isn't forced to the sender: %q", lines)
	}
	bob.Send("PRIVMSG " + channel + " :bob%16777215%9%0%0%Arial%2alice has left the game")
	if has(alice.Read(300*time.Millisecond), func(l string) bool { return strings.Contains(l, "PRIVMSG") }) {
		t.Fatal("an announcement about someone else was relayed")
	}
	// non-UTF-8 text (the game's code page) goes through unchanged
	bob.Send("PRIVMSG " + channel + " :bob%1%9%0%0%Arial%1\xe9t\xe9")
	if !has(alice.Read(300*time.Millisecond), func(l string) bool { return strings.HasSuffix(l, "%1\xe9t\xe9") }) {
		t.Fatal("code page text changed")
	}
}

// The announcement policy lets the host announce another player in its room's channel: the game's
// "bob has joined the game", which the host's client sends when bob joins.
func TestAnnouncePolicy(t *testing.T) {
	var asked []string
	s := startWith(t, 30*time.Second, nil, func(srv *irc.Server) {
		srv.Announces = func(nick, ch, text string) bool {
			asked = append(asked, nick+" "+ch+" "+text)
			return nick == "alice" && ch == channel && strings.HasPrefix(text, "bob ")
		}
	})
	alice, bob, carol := s.player(t, "", "alice", true), s.player(t, "", "bob", true), s.player(t, "", "carol", true)
	bob.Read(100 * time.Millisecond)
	carol.Read(100 * time.Millisecond)
	alice.Send("PRIVMSG " + channel + " :alice%16777215%9%0%0%Arial%2bob has joined the game")
	for _, p := range []*gsclient.IRC{bob, carol} {
		if !has(p.Read(300*time.Millisecond), func(l string) bool {
			return strings.HasSuffix(l, "PRIVMSG "+channel+" :alice%16777215%9%0%0%Arial%2bob has joined the game")
		}) {
			t.Fatal("the host's announcement wasn't relayed")
		}
	}
	// the policy decides about others only: its own announcement and plain chat don't ask it
	asked = nil
	carol.Send("PRIVMSG " + channel + " :carol%16777215%9%0%0%Arial%2carol has joined the game")
	carol.Send("PRIVMSG " + channel + " :carol%16777215%9%0%0%Arial%1hi")
	if lines := bob.Read(300 * time.Millisecond); len(lines) != 2 || len(asked) != 0 {
		t.Fatalf("relayed %q, asked %q", lines, asked)
	}
	for _, line := range []string{
		"PRIVMSG " + channel + " :carol%16777215%9%0%0%Arial%2bob has joined the game", // not the host
		"PRIVMSG " + channel + " :alice%16777215%9%0%0%Arial%2carol has left the game", // not allowed about carol
		"PRIVMSG bob :alice%16777215%9%0%0%Arial%2bob has joined the game",             // not a channel
	} {
		from := alice
		if strings.Contains(line, ":carol%") {
			from = carol
		}
		from.Send(line)
		if has(bob.Read(300*time.Millisecond), func(l string) bool { return strings.Contains(l, "PRIVMSG") }) {
			t.Fatalf("relayed %q", line)
		}
	}
}

func TestSanitizeChatFor(t *testing.T) {
	about := func(text string) bool { return text == "bob has joined the game" }
	if _, ok := irc.SanitizeChatFor("alice", ":alice%1%9%0%0%Arial%2bob has joined the game", about); !ok {
		t.Error("allowed announcement dropped")
	}
	if _, ok := irc.SanitizeChatFor("alice", ":alice%1%9%0%0%Arial%2bob has left the game", about); ok {
		t.Error("announcement relayed that the policy refused")
	}
	if _, ok := irc.SanitizeChatFor("alice", ":alice%1%9%0%0%Arial%2bob has joined the game", nil); ok {
		t.Error("announcement about someone else relayed without a policy")
	}
}

func TestPart(t *testing.T) {
	s := start(t, 30*time.Second, nil)
	alice, bob := s.player(t, "", "alice", true), s.player(t, "", "bob", true)
	alice.Read(100 * time.Millisecond)
	alice.Send("PART " + channel + " :")
	if !has(bob.Read(300*time.Millisecond), func(l string) bool { return strings.HasSuffix(l, "PART "+channel+" :") }) {
		t.Fatal("PART not relayed")
	}
	if has(alice.Read(300*time.Millisecond), func(l string) bool { return strings.Contains(l, " 403 ") }) {
		t.Fatal("PART answered 403")
	}
	bob.Send("PRIVMSG " + channel + " :bob%16777215%9%0%0%Arial%1anyone?")
	if has(alice.Read(300*time.Millisecond), func(l string) bool { return strings.Contains(l, "PRIVMSG") }) {
		t.Fatal("alice still gets the channel")
	}
	alice.Send("PART " + channel + " :")
	if !has(alice.Read(300*time.Millisecond), func(l string) bool { return strings.Contains(l, " 442 ") }) {
		t.Fatal("no 442")
	}
}

func TestSplitFramesAndBadInput(t *testing.T) {
	s := start(t, 30*time.Second, nil)
	c := s.player(t, "", "", false)
	f1, _ := irc.Frame([]byte("NICK :alice\r\n"))
	f2, _ := irc.Frame([]byte("USER HEROES_657d2c2ebadc6a1d +i 0 :alice\r\n"))
	data := append(f1, f2...)
	for _, part := range [][]byte{data[:3], data[3:20], data[20:]} {
		c.Conn.Write(part)
		time.Sleep(100 * time.Millisecond)
	}
	if !has(c.Read(300*time.Millisecond), func(l string) bool { return strings.Contains(l, " 001 alice ") }) {
		t.Fatal("split frames not reassembled")
	}
	for _, line := range []string{"NICK :", "JOIN ,", "MODE x", "PRIVMSG", "NOTICE #x", "BOGUS", "\xff\xfe"} {
		c.Send(line)
		if !alive(c) {
			t.Fatalf("connection lost after %q", line)
		}
	}
	c.Conn.Write([]byte{0, 3, 1, 2, 3}) // undecryptable frame
	if !alive(c) {
		t.Fatal("a bad frame dropped the client")
	}
}

func TestReconnectTakesOverNick(t *testing.T) {
	s := start(t, 30*time.Second, nil)
	old := s.player(t, "", "alice", true)
	fresh := s.player(t, "", "alice", false)
	if has(fresh.Read(200*time.Millisecond), func(l string) bool { return strings.Contains(l, " 433 ") }) {
		t.Fatal("433 on reconnect")
	}
	old.Conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	for {
		if _, err := old.Conn.Read(buf); err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				t.Fatal("the stale connection is still open")
			}
			break
		}
	}
}

func TestNickPolicy(t *testing.T) {
	// only an account logged in from the same address may be used as a nick
	logged := map[string]string{"alice": "127.0.0.1"}
	s := start(t, 30*time.Second, func(nick, ip string) bool { return logged[strings.ToLower(nick)] == ip })
	c := s.player(t, "", "", false)
	c.Send("NICK :mallory")
	if lines := c.Read(300 * time.Millisecond); !has(lines, func(l string) bool { return strings.Contains(l, " 432 mallory ") }) {
		t.Fatalf("someone else's nick: %q", lines)
	}
	c.Send("NICK :alice")
	if lines := c.Read(300 * time.Millisecond); !has(lines, func(l string) bool { return strings.Contains(l, " 001 alice ") }) {
		t.Fatalf("own nick refused: %q", lines)
	}
}

func TestPingKeepsQuietClient(t *testing.T) {
	s := start(t, 1500*time.Millisecond, nil)
	c := s.player(t, "", "alice", false)
	var lines []string
	for end := time.Now().Add(2 * time.Second); time.Now().Before(end); {
		lines = append(lines, c.Read(50*time.Millisecond)...)
		if has(lines, func(l string) bool { return strings.HasPrefix(l, "PING") }) {
			break
		}
	}
	if !has(lines, func(l string) bool { return strings.HasPrefix(l, "PING") }) {
		t.Fatalf("no PING: %q", lines)
	}
	c.Send("PONG :localhost")
	time.Sleep(time.Second)
	if !alive(c) {
		t.Fatal("dropped after answering the PING")
	}
	quiet := s.player(t, "", "", false)
	quiet.Conn.SetReadDeadline(time.Now().Add(4 * time.Second))
	buf := make([]byte, 1024)
	for {
		if _, err := quiet.Conn.Read(buf); err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				t.Fatal("a silent client was kept")
			}
			break
		}
	}
}

func FuzzSanitizeChat(f *testing.F) {
	f.Add("bob", ":bob%16777215%9%0%0%Arial%1hello")
	f.Fuzz(func(t *testing.T, nick, payload string) {
		out, ok := irc.SanitizeChat(nick, payload)
		if ok && (strings.ContainsAny(out[strings.LastIndex(out, "%"):], "\r\n\x00") || !strings.HasPrefix(out, ":"+nick+"%")) {
			t.Fatalf("%q", out)
		}
	})
}
