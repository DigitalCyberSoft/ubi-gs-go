package lobby_test

import (
	"fmt"
	"testing"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/dl"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/gsm"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/lobby"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/server"
)

// reply returns the one reply (result 38 or 39) to a lobby request of the subtype among the messages.
func reply(t *testing.T, l []dl.List, sub string) string {
	t.Helper()
	var out []string
	for _, m := range l {
		r, _ := m.Str(0)
		inner, _ := m.List(1)
		if s, _ := inner.Str(0); (r == "38" || r == "39") && s == sub {
			out = append(out, m.String())
		}
	}
	if len(out) != 1 {
		t.Fatalf("replies to %s: %v (all: %v)", sub, out, l)
	}
	return out[0]
}

// A refused CREATE_ROOM is answered with the failure the game reads, [39, [12, [reason, name]]]:
// without it the game stays on "Creating game" for good.
func TestCreateRoomRefused(t *testing.T) {
	s := start(t, func(c *server.Config) { c.MaxRooms = 1 })
	alice := join(t, s, "127.0.0.2", "alice", "pw")
	bob := join(t, s, "127.0.0.3", "bob", "pw")
	alice.createRoom()
	bob.msgs()
	alice.msgs()
	bob.lobby("12", dl.S("1"), dl.S("bob's Game"), dl.S(game), dl.S("7"), dl.S("2"), dl.S("0"), dl.B(roomInfo(t)),
		dl.S(""), dl.S(""), dl.S(gsVersion), dl.B(nil))
	if got := reply(t, bob.msgs(), "12"); got != `['39', ['12', ['24', 'bob\'s Game']]]` {
		t.Fatalf("over the room limit: %s", got)
	}
	if got := alice.msgs(); len(got) != 0 {
		t.Fatalf("the lobby heard of a refused room: %v", got)
	}

	// unreadable room info, and a malformed request: refused too, the name cut to the game's buffer
	long := "a name longer than the 36 bytes the game keeps"
	alice.Close()
	bob.msgs()
	bob.lobby("12", dl.S("1"), dl.S(long), dl.S(game), dl.S("7"), dl.S("2"), dl.S("0"), dl.B([]byte{1, 2, 3}),
		dl.S(""), dl.S(""), dl.S(gsVersion), dl.B(nil))
	if got := reply(t, bob.msgs(), "12"); got != "['39', ['12', ['24', '"+long[:gsm.LobbyNameSize-1]+"']]]" {
		t.Fatalf("unreadable room info: %s", got)
	}
	bob.lobby("12", dl.S("1"))
	if got := reply(t, bob.msgs(), "12"); got != "['39', ['12', ['0', '']]]" {
		t.Fatalf("malformed CREATE_ROOM: %s", got)
	}
	// the limit counts open rooms: with alice's gone, bob creates one
	bob.createRoom()
}

// JOIN_ROOM to a room that's gone or full is refused with the reason the game shows.
func TestJoinRoomRefused(t *testing.T) {
	s := start(t, nil)
	host := join(t, s, "127.0.0.2", "host", "pw")
	id := host.createRoom()
	bob := join(t, s, "127.0.0.3", "bob", "pw")
	bob.msgs()
	bob.lobby("24", dl.S("4242"), dl.S(""), dl.S("448"), dl.S("0"), dl.S(gsVersion))
	if got := reply(t, bob.msgs(), "24"); got != "['39', ['24', ['1', '4242']]]" {
		t.Fatalf("a room that isn't there: %s", got)
	}
	for i := 1; i < lobby.MaxRoomMembers; i++ {
		p := join(t, s, fmt.Sprintf("127.0.0.%d", 10+i), fmt.Sprintf("p%d", i), "pw")
		p.lobby("24", dl.S(id), dl.S(""), dl.S("448"), dl.S("0"), dl.S(gsVersion))
	}
	bob.msgs()
	bob.lobby("24", dl.S(id), dl.S(""), dl.S("448"), dl.S("0"), dl.S(gsVersion))
	// 7, NOMOREMEMBERS: "The game you're trying to enter is full."
	if got := reply(t, bob.msgs(), "24"); got != "['39', ['24', ['7', '"+id+"']]]" {
		t.Fatalf("a full room: %s", got)
	}
}

// Every request the game waits for gets an answer, a malformed one too; notifications and unknown
// subtypes still get none.
func TestRefusalsAnswered(t *testing.T) {
	s := start(t, nil)
	alice := join(t, s, "127.0.0.2", "alice", "pw")
	alice.msgs()
	for sub, want := range map[string]string{
		"8":  "['39', ['8', ['0', '0']]]",
		"15": "['39', ['15', ['0', '0']]]",
		"17": "['39', ['17', ['1', '4242']]]",
		"21": "['39', ['21', ['0', '0']]]",
		"23": "['39', ['23', ['0', '0']]]",
		"24": "['39', ['24', ['0', '4242']]]",
		"30": "['39', ['30', ['0', '0']]]",
		"31": "['39', ['31', ['1', '4242']]]",
		"33": "['39', ['33', ['1', '4242']]]",
		"42": "['39', ['42', ['0', '0']]]",
		"45": "['39', ['45', ['0', '0']]]",
	} {
		var args []dl.Value
		switch sub {
		case "17", "31", "24":
			// about a room that isn't there (JOIN_ROOM without its other fields)
			args = []dl.Value{dl.S("4242"), dl.S("0")}
		case "33":
			args = []dl.Value{dl.S("4242"), dl.B(nil), dl.S("0")}
		}
		alice.lobby(sub, args...)
		if got := reply(t, alice.msgs(), sub); got != want {
			t.Errorf("%s: %s, want %s", sub, got, want)
		}
	}
	for _, sub := range []string{"9", "34", "35", "44", "70", "99"} {
		alice.lobby(sub)
	}
	if got := alice.msgs(); len(got) != 0 {
		t.Fatalf("answered: %v", got)
	}
}
