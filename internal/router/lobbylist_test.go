package router_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/dl"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/env"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/gsclient"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/gsm"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/testserver"
)

// lobbyList is the wait module's lobby list as "id:max/members" entries.
func lobbyList(t *testing.T, wm *gsclient.Client) string {
	t.Helper()
	res, err := wm.Request(gsm.LOBBY_MSG, dl.S("109"), dl.L(dl.S(game)))
	if err != nil {
		t.Fatal(err)
	}
	args, _ := res.Data.List(1)
	lists, _ := args.List(3)
	out := ""
	for _, v := range lists {
		e, _ := v.List()
		id, _ := e.Str(2)
		capacity, _ := e.Str(12)
		members, _ := e.Str(13)
		out += fmt.Sprintf("%s:%s/%s ", id, capacity, members)
	}
	return out
}

// The lobby list shows how many players each lobby has (the game shows it per channel), its rooms
// included, and the lobby service's cap as the most it takes.
func TestLobbyListCounts(t *testing.T) {
	s := testserver.Start(t, nil)
	joinLobby := func(name, lobby string) *gsclient.Client {
		c, err := gsclient.New("", s.Addr(env.PortLobby), gsm.PartyServer)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(c.Close)
		c.Send(gsm.LOBBYSERVERLOGIN, dl.S(name), dl.S("1"), dl.S("192.168.0.41"), dl.S("255.255.255.0"), dl.S("0"))
		c.Send(gsm.LOBBY_MSG, dl.S("23"), dl.L(dl.S(lobby), dl.S(""), dl.S("384")))
		return c
	}
	wm := dial(t, s, "", env.PortRouterWM)
	expect := func(want string) {
		t.Helper()
		got := ""
		// the lobby connections are separate: their joins land in their own time
		for end := time.Now().Add(3 * time.Second); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
			if got = lobbyList(t, wm); got == want {
				return
			}
		}
		t.Fatalf("lobby list %q, want %q", got, want)
	}
	expect("1:512/0 2:512/0 3:512/0 ")
	joinLobby("alice", "1")
	joinLobby("bob", "1")
	carol := joinLobby("carol", "3")
	expect("1:512/2 2:512/0 3:512/1 ")
	carol.Close()
	expect("1:512/2 2:512/0 3:512/0 ")
}
