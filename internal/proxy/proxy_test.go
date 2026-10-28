package proxy_test

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/dl"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/env"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/gsclient"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/gsm"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/proxy"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/testserver"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/testvec"
)

// The reference's module vectors: ladder rows, profile get and set, from a game at 10.0.0.3; here the
// game is at 127.0.0.3.
func TestModuleVectors(t *testing.T) {
	testserver.NeedLoopbackAliases(t)
	s := testserver.Start(t, nil)
	alice, _ := s.Accounts().Login("alice", "pw")
	s.Accounts().BindSession("alice", "127.0.0.3", alice)
	s.Accounts().SetLadderStats(alice, proxy.LadderKey("HEROES_657d2c2ebadc6a1d", "1"), map[string]int64{"RATING": 1612, "WINS": 3})
	var vs []struct{ Request, Response string }
	testvec.Get(t, testvec.Load(t), "module", &vs)
	c, err := gsclient.New("127.0.0.3", s.Addr(env.PortProxyWM), gsm.PartyRouter)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for i, v := range vs {
		c.SendRaw(testvec.Hex(t, v.Request))
		res, err := c.Recv(3 * time.Second)
		if err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		if got, want := res.MustEncode(), testvec.Hex(t, v.Response); string(got) != string(want) {
			w, _ := gsm.Decode(want, nil)
			t.Errorf("vector %d:\n%s\nwant\n%s", i, res, w)
		}
	}
}

func TestProxyHandshake(t *testing.T) {
	s := testserver.Start(t, nil)
	c, _ := gsclient.New("", s.Addr(env.PortProxy), gsm.PartyRouter)
	defer c.Close()
	res, _ := c.Request(gsm.LOGIN, dl.S("averyveryverylongname"), dl.S("HEROES_657d2c2ebadc6a1d"))
	if res.Data.String() != "[b'f', []]" {
		t.Fatalf("LOGIN %s", res.Data)
	}
	res, _ = c.Request(gsm.JOINWAITMODULE)
	if got := res.Data.String(); !strings.HasPrefix(got, "[b']', ['averyveryverylo', '127.0.0.1', '") {
		t.Fatalf("JOINWAITMODULE %s", got)
	}
}

func TestUnknownModuleClosesConnection(t *testing.T) {
	s := testserver.Start(t, nil)
	c, _ := gsclient.New("", s.Addr(env.PortProxyWM), gsm.PartyRouter)
	defer c.Close()
	c.Send(gsm.PROXY_HANDLER, dl.S("9999"), dl.S("1"), dl.L())
	c.Conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := c.Conn.Read(make([]byte, 10)); err == nil {
		t.Fatalf("got %d bytes, want the connection closed", n)
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("connection still open")
	}
}

func TestProfileSizeLimit(t *testing.T) {
	testserver.NeedLoopbackAliases(t)
	s := testserver.Start(t, nil)
	alice, _ := s.Accounts().Login("alice", "pw")
	s.Accounts().BindSession("alice", "127.0.0.2", alice)
	c, _ := gsclient.New("127.0.0.2", s.Addr(env.PortProxyWM), gsm.PartyRouter)
	defer c.Close()
	blob := make([]byte, proxy.MaxProfileSize+1)
	res, err := c.Request(gsm.PROXY_HANDLER, dl.S("1026"), dl.S("1"), dl.L(dl.S("G"), dl.S("0"), dl.S("alice"), dl.S("0"), dl.S("PUBLIC"), dl.B(blob), dl.S("65537")))
	if err != nil || res.Data.String() != "['1026', '1', ['39', ['0']]]" {
		t.Fatalf("oversized profile: %v %v", res, err)
	}
	// someone else's data can't be written
	other, _ := gsclient.New("127.0.0.9", s.Addr(env.PortProxyWM), gsm.PartyRouter)
	defer other.Close()
	res, _ = other.Request(gsm.PROXY_HANDLER, dl.S("1026"), dl.S("1"), dl.L(dl.S("G"), dl.S("0"), dl.S("alice"), dl.S("0"), dl.S("PUBLIC"), dl.B([]byte("x")), dl.S("1")))
	if res.Data.String() != "['1026', '1', ['39', ['0']]]" {
		t.Fatalf("foreign write: %s", res.Data)
	}
}
