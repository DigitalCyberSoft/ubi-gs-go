package lobby_test

import (
	"testing"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/dl"
)

// createOnly sends CREATE_ROOM without joining the room, and returns its id.
func (p *player) createOnly() string {
	p.msgs()
	p.lobby("12", dl.S("1"), dl.S("a room"), dl.S(game), dl.S("7"), dl.S("2"), dl.S("0"), dl.B(roomInfo(p.t)),
		dl.S(""), dl.S(""), dl.S(gsVersion), dl.B(nil))
	for _, m := range p.msgs() {
		sub, _ := m.List(1)
		if r, _ := m.Str(0); r == "38" && len(sub) > 1 && sub[0].String() == "'12'" {
			ids, _ := sub.List(1)
			id, _ := ids.Str(0)
			return id
		}
	}
	p.t.Fatal("no CREATE_ROOM reply")
	return ""
}

// removed returns the ids of the GROUP_REMOVE notifications.
func removed(l []dl.List) []string {
	var ids []string
	for _, m := range notifs(l, "55") {
		args, _ := m.List(1)
		id, _ := args.Str(0)
		ids = append(ids, id)
	}
	return ids
}

// A room nobody joined is closed when its creator creates another or leaves, so CREATE_ROOM alone
// can't pile rooms up in memory.
func TestUnjoinedRoomsClosed(t *testing.T) {
	s := start(t, nil)
	alice := join(t, s, "127.0.0.2", "alice", "pw")
	bob := join(t, s, "127.0.0.3", "bob", "pw")
	first := alice.createOnly()
	bob.msgs()
	second := alice.createOnly()
	if got := removed(bob.msgs()); len(got) != 1 || got[0] != first {
		t.Fatalf("after a second CREATE_ROOM, removed %v, want [%s]", got, first)
	}
	alice.Close()
	if got := removed(bob.msgs()); len(got) != 1 || got[0] != second {
		t.Fatalf("after the creator left, removed %v, want [%s]", got, second)
	}
}
