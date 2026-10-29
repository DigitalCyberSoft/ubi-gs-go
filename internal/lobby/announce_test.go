package lobby_test

import (
	"testing"
	"time"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/dl"
)

// The host of a room announces the players joining and leaving it in the room's channel; nobody else
// announces anyone.
func TestAnnounces(t *testing.T) {
	s := start(t, nil)
	alice := join(t, s, "127.0.0.2", "alice", "pw")
	bob := join(t, s, "127.0.0.3", "bob", "pw")
	room := alice.createRoom()
	bob.lobby("24", dl.S(room), dl.S(""), dl.S("448"), dl.S("0"), dl.S(gsVersion))
	alice.msgs()
	bob.msgs()
	l := s.Lobby()
	ch := "#LobbyGrp1." + room
	for _, c := range []struct {
		nick, channel, text string
		ok                  bool
	}{
		{"alice", ch, "bob has joined the game", true},
		{"ALICE", ch, "bob has joined the game", true},
		{"alice", ch, "alice has joined the game", true},
		{"bob", ch, "alice has joined the game", false},    // not the host
		{"alice", ch, "carol has joined the game", false},  // not in the room
		{"alice", ch, "bobby has joined the game", false},  // a name is a whole word
		{"alice", ch, "Server: bob has joined", false},     // about nobody
		{"alice", "#LobbyGrp1.1", "bob has joined", false}, // the lobby's channel
		{"alice", "#LobbyGrp1.4242", "bob has joined", false},
		{"alice", "#other", "bob has joined", false},
		{"carol", ch, "bob has joined the game", false},
	} {
		if got := l.Announces(c.nick, c.channel, c.text); got != c.ok {
			t.Errorf("Announces(%q, %q, %q) = %v", c.nick, c.channel, c.text, got)
		}
	}
	// bob leaves: alice announces it ("bob has left the game")
	bob.lobby("8", dl.S(room))
	bob.msgs()
	if !l.Announces("alice", ch, "bob has left the game") {
		t.Error("the host can't announce a player that just left")
	}
	// the room is gone with its host: nobody announces in it
	alice.Close()
	time.Sleep(100 * time.Millisecond)
	if l.Announces("alice", ch, "bob has left the game") {
		t.Error("announced in a room that's gone")
	}
}
