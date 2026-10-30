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

// toe is the game id of Tribes of the East 3.1.
const toe = "HEROES_29988429c481f219"

// lobbyList is the wait module's lobby list as "id:max/members" entries.
func lobbyList(t *testing.T, wm *gsclient.Client) string {
	t.Helper()
	res, err := wm.Request(gsm.LOBBY_MSG, dl.S("109"), dl.L(dl.S(game)))
	if err != nil {
		t.Fatal(err)
	}
	return lobbies(t, res)
}

// lobbies is a lobby list (a GROUP_INFO) as "id:max/members" entries.
func lobbies(t *testing.T, m *gsm.Message) string {
	t.Helper()
	if sub, _ := m.Data.Str(0); m.Header.Type != gsm.LOBBY_MSG || sub != "53" {
		t.Fatalf("not a lobby list: %s", m)
	}
	args, _ := m.Data.List(1)
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

// Hammers of Fate and Tribes of the East never ask for the lobby list (CHANGE_REQUESTED_LOBBIES), as
// 1.60 does: after the lobby login they wait for it, and list no lobby until it comes.
func TestLobbyLoginSendsTheLobbyList(t *testing.T) {
	s := testserver.Start(t, nil)
	wm := dial(t, s, "", env.PortRouterWM)
	res, err := wm.Request(gsm.LOBBY_MSG, dl.S("21"), dl.L(dl.S(toe)))
	if err != nil || res.Data.String() != "['38', ['21']]" {
		t.Fatalf("lobby LOGIN: %v %v", res, err)
	}
	list, err := wm.Recv(2 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got := lobbies(t, list); got != "1:512/0 2:512/0 3:512/0 " || list.Header.Sender != gsm.PartyRouter {
		t.Fatalf("after the lobby LOGIN: %s, from %s", got, list.Header.Sender)
	}
	// asking still gets it
	if got := lobbyList(t, wm); got != "1:512/0 2:512/0 3:512/0 " {
		t.Fatalf("lobby list %q", got)
	}
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
