package router_test

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/dl"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/env"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/gsclient"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/gsm"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/testserver"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/testvec"
)

const game = "HEROES_657d2c2ebadc6a1d"

func dial(t *testing.T, s *testserver.Server, from string, port int) *gsclient.Client {
	t.Helper()
	c, err := gsclient.New(from, s.Addr(port), gsm.PartyRouter)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func login(t *testing.T, s *testserver.Server, from, name, password string) (*gsclient.Client, *gsm.Message) {
	t.Helper()
	c := dial(t, s, from, env.PortRouter)
	if err := c.KeyExchange(); err != nil {
		t.Fatal(err)
	}
	if err := c.SendEncrypted(gsm.LOGIN, dl.S(name), dl.S(password), dl.S(game)); err != nil {
		t.Fatal(err)
	}
	res, err := c.Recv(3 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return c, res
}

func waitModule(t *testing.T, s *testserver.Server, from, typed string) *gsclient.Client {
	t.Helper()
	wm := dial(t, s, from, env.PortRouterWM)
	if res, err := wm.Request(gsm.LOGINWAITMODULE, dl.S(typed)); err != nil || res.Header.Type != gsm.GSSUCCESS {
		t.Fatalf("LOGINWAITMODULE: %v %v", res, err)
	}
	return wm
}

func TestLoginAndNames(t *testing.T) {
	testserver.NeedLoopbackAliases(t)
	s := testserver.Start(t, nil)
	_, res := login(t, s, "127.0.0.2", "alice", "one")
	if res.Header.Type != gsm.GSSUCCESS || res.Data.String() != "[b'f']" {
		t.Fatalf("login: %s", res)
	}
	// a taken name with another password: INVALID_PASSWORD (15), the game's "The password is not correct"
	_, res = login(t, s, "127.0.0.3", "alice", "two")
	if res.Header.Type != gsm.GSFAIL {
		t.Fatalf("wrong password: %s", res)
	}
	if reason, _ := res.Data.List(1); reason == nil {
		t.Fatalf("wrong password: %s", res)
	} else if b, _ := reason.Bin(0); !bytes.Equal(b, []byte{15, 0, 0, 0}) {
		t.Fatalf("wrong password: %s", res)
	}
	if a, _ := s.Accounts().Find("alice-1"); a != nil {
		t.Fatal("alice-1 created")
	}
	// an alice-1 from before (here created under its own name) still logs in with the typed name and its
	// password, and is known by the typed name from that address
	if _, err := s.Accounts().Login("alice-1", "two"); err != nil {
		t.Fatal(err)
	}
	_, res = login(t, s, "127.0.0.3", "alice", "two")
	if res.Header.Type != gsm.GSSUCCESS {
		t.Fatalf("alice-1 login: %s", res)
	}
	wm := waitModule(t, s, "127.0.0.3", "alice")
	res, _ = wm.Request(gsm.PLAYERINFO, dl.S("alice"))
	if got := res.Data.String(); got != "[b'\\x13', ['alice-1', 'alice-1', 'findme3', 'findme4', 'findme5', 'findme6', 'findme7']]" {
		t.Fatalf("PLAYERINFO %s", got)
	}
	wm = waitModule(t, s, "127.0.0.2", "alice")
	res, _ = wm.Request(gsm.PLAYERINFO, dl.S("alice"))
	if v, _ := res.Data.List(1); v[0].String() != "'alice'" {
		t.Fatalf("PLAYERINFO %s", res.Data)
	}
}

func TestRefusals(t *testing.T) {
	s := testserver.Start(t, nil)
	for name, want := range map[string]string{"a b": "02000000", "": "02000000"} {
		_, res := login(t, s, "", name, "pw")
		if res.Header.Type != gsm.GSFAIL {
			t.Fatalf("%q: %s", name, res)
		}
		reason, _ := res.Data.List(1)
		if b, _ := reason.Bin(0); testvec.Hex(t, want) == nil || !bytes.Equal(b, testvec.Hex(t, want)) {
			t.Errorf("%q: reason %x", name, b)
		}
	}
	_, res := login(t, s, "", "alice", "")
	reason, _ := res.Data.List(1)
	if b, _ := reason.Bin(0); !bytes.Equal(b, []byte{11, 0, 0, 0}) {
		t.Errorf("empty password: %s", res)
	}
}

func TestSecondLoginClosesOlder(t *testing.T) {
	s := testserver.Start(t, nil)
	old, _ := login(t, s, "", "alice", "pw")
	login(t, s, "", "alice", "pw")
	if _, err := old.Recv(2 * time.Second); err == nil {
		t.Fatal("the older connection got a message")
	}
	old.Conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := old.Conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("the older connection is still open")
	}
}

func friendNotices(msgs []*gsm.Message) []string {
	var out []string
	for _, m := range msgs {
		out = append(out, m.Header.Type.String()+" "+m.Data.String())
	}
	return out
}

func TestFriends(t *testing.T) {
	testserver.NeedLoopbackAliases(t)
	s := testserver.Start(t, nil)
	login(t, s, "127.0.0.2", "alice", "pw")
	login(t, s, "127.0.0.3", "bob", "pw")
	alice := waitModule(t, s, "127.0.0.2", "alice")
	alice.Send(gsm.LOGINFRIENDS, gsm.U32(0), gsm.U32(0))
	alice.All(300 * time.Millisecond)

	alice.Send(gsm.ADDFRIEND, dl.S("BOB"), dl.S(""), gsm.U32(0))
	got := friendNotices(alice.All(300 * time.Millisecond))
	// bob has no wait module connection yet: offline (status 1)
	want := []string{"GSSUCCESS [b'K', 'bob']", "UPDATEFRIEND ['bob', b'\\x01\\x00\\x00\\x00', '', b'\\x00\\x00\\x00\\x00', b'\\x00\\x00\\x00\\x00', '']"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("add friend: %q", got)
	}
	// bob comes online: alice is told, status 0
	bob := waitModule(t, s, "127.0.0.3", "bob")
	bob.Send(gsm.LOGINFRIENDS, gsm.U32(0), gsm.U32(0))
	got = friendNotices(alice.All(300 * time.Millisecond))
	if len(got) != 1 || got[0] != "UPDATEFRIEND ['bob', b'\\x00\\x00\\x00\\x00', '', b'\\x00\\x00\\x00\\x00', b'\\x00\\x00\\x00\\x00', '']" {
		t.Fatalf("bob online: %q", got)
	}
	alice.Send(gsm.FRIENDLIST)
	if got = friendNotices(alice.All(300 * time.Millisecond)); len(got) != 2 || got[0] != "GSSUCCESS [b'Y']" {
		t.Fatalf("friend list: %q", got)
	}
	bob.Close()
	if got = friendNotices(alice.All(500 * time.Millisecond)); len(got) != 1 || got[0][:len("UPDATEFRIEND ['bob', b'\\x01")] != "UPDATEFRIEND ['bob', b'\\x01" {
		t.Fatalf("bob offline: %q", got)
	}
	alice.Send(gsm.ADDFRIEND, dl.S("nobody"), dl.S(""), gsm.U32(0))
	if got = friendNotices(alice.All(300 * time.Millisecond)); len(got) != 1 || got[0] != "GSFAIL [b'K', [b'\\x01\\x00\\x00\\x00']]" {
		t.Fatalf("unknown friend: %q", got)
	}
	alice.Send(gsm.DELFRIEND, dl.S("bob"))
	alice.Send(gsm.FRIENDLIST)
	if got = friendNotices(alice.All(300 * time.Millisecond)); len(got) != 2 || got[0] != "GSSUCCESS [b'L', 'bob']" || got[1] != "GSSUCCESS [b'Y']" {
		t.Fatalf("remove friend: %q", got)
	}
}

type reply struct{ Name, Request, Response string }

func TestReplyVectors(t *testing.T) {
	var vs []reply
	testvec.Get(t, testvec.Load(t), "replies", &vs)
	s := testserver.Start(t, nil)
	wm := dial(t, s, "", env.PortRouterWM)
	off := s.Config.PortOffset
	for _, v := range vs {
		switch v.Name {
		case "proxyhandler_1", "proxyhandler_2", "join_server", "lobby_login", "group_info":
		default:
			continue
		}
		if err := wm.SendRaw(testvec.Hex(t, v.Request)); err != nil {
			t.Fatal(err)
		}
		res, err := wm.Recv(2 * time.Second)
		if err != nil {
			t.Fatal(err)
		}
		want, _ := gsm.Decode(testvec.Hex(t, v.Response), nil)
		// the reference's vectors use 10.0.0.1 and the standard ports
		got := res.Data.String()
		exp := want.Data.String()
		exp = replaceAll(exp, "10.0.0.1", "127.0.0.1")
		for _, p := range []int{7783, 7785} {
			exp = replaceAll(exp, "'"+itoa(p)+"'", "'"+itoa(p+off)+"'")
		}
		if got != exp || res.Header.Type != want.Header.Type || res.Header.Sender != want.Header.Sender {
			t.Errorf("%s: %s %s, want %s %s", v.Name, res.Header.Type, got, want.Header.Type, exp)
		}
		if v.Name == "lobby_login" {
			// then the lobby list (TestLobbyLoginSendsTheLobbyList)
			list, err := wm.Recv(2 * time.Second)
			if err != nil {
				t.Fatal(err)
			}
			lobbies(t, list)
		}
	}
	// the module-ready notice gets no reply (an echo would block the game's proxy messages)
	wm.Send(gsm.PROXY_HANDLER, dl.L(dl.S("3"), dl.S("1")))
	wm.Send(gsm.STILLALIVE)
	if res, err := wm.Recv(2 * time.Second); err != nil || res.Header.Type != gsm.STILLALIVE {
		t.Fatalf("after the notice: %v %v", res, err)
	}
}

func replaceAll(s, old, new string) string { return strings.ReplaceAll(s, old, new) }

func itoa(n int) string { return strconv.Itoa(n) }
