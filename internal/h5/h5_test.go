package h5

import (
	"bytes"
	"encoding/hex"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/testvec"
)

func vec(t *testing.T, key string) []byte {
	var s string
	testvec.Get(t, testvec.Load(t), key, &s)
	return testvec.Hex(t, s)
}

func TestRoomInfoVectors(t *testing.T) {
	in := vec(t, "room_info_input")
	info, err := DeserializeRoomInfo(in)
	if err != nil {
		t.Fatal(err)
	}
	name, _ := info.Field(7)
	maxPlayers, _ := info.Field(20)
	if string(name) != "a\x00l\x00i\x00c\x00e\x00'\x00s\x00 \x00G\x00a\x00m\x00e\x00" || u32(maxPlayers) != 2 {
		t.Fatalf("parsed %q %x", name, maxPlayers)
	}
	if got, want := info.Serialize(), vec(t, "room_info_output"); !bytes.Equal(got, want) {
		t.Fatalf("serialized\n%x\nwant\n%x", got, want)
	}
	p, err := DeserializePlayerInfo(vec(t, "player_info"))
	if err != nil {
		t.Fatal(err)
	}
	if string(p.Username) != "alice" || p.ExtIP.Port != 8888 || p.Int38 != 1500 || p.ExtIP.Addr().String() != "10.0.0.2" {
		t.Fatalf("player info %+v", p)
	}
	if got := p.Serialize(); !bytes.Equal(got, vec(t, "player_info")) {
		t.Fatalf("player info serialized %x", got)
	}
	info.PlayerInfos = append(info.PlayerInfos, p)
	if got, want := info.Serialize(), vec(t, "room_info_with_player"); !bytes.Equal(got, want) {
		t.Fatalf("with player\n%x\nwant\n%x", got, want)
	}
	again, err := DeserializeRoomInfo(info.Serialize())
	if err != nil || len(again.PlayerInfos) != 1 || *again.PlayerInfos[0].Key != 0 {
		t.Fatalf("round trip: %v", err)
	}
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	s, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	b, err := hex.DecodeString(strings.TrimSpace(string(s)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func ids(r *RoomInfo) []byte {
	var out []byte
	for _, s := range r.raw {
		out = append(out, s.ID)
	}
	return out
}

// The room info each game sends in CREATE_ROOM: the expansions write fields Heroes V doesn't and leave
// out some it writes. Each must be accepted and go back as it came, but for the fields the lobby sets.
func TestExpansionRoomInfo(t *testing.T) {
	base := []byte{2, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33}
	for _, c := range []struct {
		file    string
		ids     []byte
		version uint32
	}{
		{"hof-create-room.hex", append(slices.Clone(base), 34, 35, 36), 0x20001},
		{"toe-create-room.hex", append(slices.DeleteFunc(slices.Clone(base), func(id byte) bool { return id == 12 }),
			34, 35, 36, 37, 38, 39, 40, 41), 0x30001},
	} {
		in := fixture(t, c.file)
		info, err := DeserializeRoomInfo(in)
		if err != nil {
			t.Fatalf("%s: %v", c.file, err)
		}
		if !bytes.Equal(ids(info), c.ids) {
			t.Fatalf("%s: fields %v, want %v", c.file, ids(info), c.ids)
		}
		if v, _ := info.Field(23); u32(v) != c.version || info.GroupID != 0xffffffff || len(info.PlayerInfos) != 0 {
			t.Fatalf("%s: version %x, group %x, %d players", c.file, v, info.GroupID, len(info.PlayerInfos))
		}
		if got := info.Serialize(); !bytes.Equal(got, in) {
			t.Fatalf("%s: serialized\n%x\nwant\n%x", c.file, got, in)
		}
		// as the lobby does: the ids, a host and a player
		info.GroupID, info.LobbySrvID = 1000, 1
		info.HostIP = SockAddr{Family: 2, Port: 9000, IP: [4]byte{10, 0, 0, 2}}
		p, err := DeserializePlayerInfo(vec(t, "player_info"))
		if err != nil {
			t.Fatal(err)
		}
		info.PlayerInfos = append(info.PlayerInfos, p)
		again, err := DeserializeRoomInfo(info.Serialize())
		if err != nil {
			t.Fatalf("%s: rewritten: %v", c.file, err)
		}
		if again.GroupID != 1000 || again.LobbySrvID != 1 || again.HostIP != info.HostIP || len(again.PlayerInfos) != 1 ||
			!bytes.Equal(ids(again), c.ids) {
			t.Fatalf("%s: rewritten %+v", c.file, again)
		}
		orig, _ := DeserializeRoomInfo(in)
		for i, s := range again.raw {
			switch s.ID {
			case roomGroupID, roomLobbySrvID, roomHostIP, roomPlayerInfos:
			default:
				if !bytes.Equal(s.Data, orig.raw[i].Data) {
					t.Fatalf("%s: field %d changed", c.file, s.ID)
				}
			}
		}
		if bytes.Contains(again.WithoutAddresses().Serialize(), []byte{10, 0, 0, 2}) {
			t.Fatalf("%s: an address is still in the room info", c.file)
		}
	}
}

// A field no game is known to write is kept, and a field the lobby rewrites must be there once.
func TestRoomInfoUnknownFields(t *testing.T) {
	data, err := unwrap(vec(t, "room_info_input"))
	if err != nil {
		t.Fatal(err)
	}
	info, err := DeserializeRoomInfo(wrap(appendStream(slices.Clone(data), 99, []byte("later"))))
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := info.Field(99); !ok || string(v) != "later" {
		t.Fatalf("field 99: %q %v", v, ok)
	}
	if !bytes.Contains(info.Serialize(), []byte("later")) {
		t.Fatal("field 99 not written")
	}
	host := appendStream(nil, roomHostIP, writeSockAddr(SockAddr{Family: 2, IP: [4]byte{10, 0, 0, 2}}))
	if _, err := DeserializeRoomInfo(wrap(append(slices.Clone(data), host...))); err == nil {
		t.Fatal("a second host address accepted")
	}
	if _, err := DeserializeRoomInfo(wrap(appendStream(nil, roomHostIP, []byte{1, 2, 3}))); err == nil {
		t.Fatal("a malformed host address accepted")
	}
}

func TestPlayerInfoRest(t *testing.T) {
	data, err := unwrap(vec(t, "player_info"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := DeserializePlayerInfo(wrap(appendStream(slices.Clone(data), 6, []byte{7})))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p.Rest, []byte{6, 2, 7}) || !bytes.Contains(p.WithoutAddresses().Serialize(), p.Rest) {
		t.Fatalf("rest %x", p.Rest)
	}
	if again, err := DeserializePlayerInfo(p.Serialize()); err != nil || !bytes.Equal(again.Rest, p.Rest) {
		t.Fatalf("round trip: %v %x", err, again.Rest)
	}
}

func TestWithoutAddresses(t *testing.T) {
	info, err := DeserializeRoomInfo(vec(t, "room_info_with_player"))
	if err != nil {
		t.Fatal(err)
	}
	info.HostIP.IP = [4]byte{10, 0, 0, 2}
	scrubbed := info.WithoutAddresses()
	if scrubbed.HostIP.IP != [4]byte{} || scrubbed.PlayerInfos[0].ExtIP.IP != [4]byte{} || scrubbed.PlayerInfos[0].LocalIP != [4]byte{} {
		t.Fatal("addresses left")
	}
	if info.HostIP.IP != [4]byte{10, 0, 0, 2} || info.PlayerInfos[0].ExtIP.IP == [4]byte{} {
		t.Fatal("original changed")
	}
	if bytes.Contains(scrubbed.Serialize(), []byte{10, 0, 0, 2}) || bytes.Contains(scrubbed.Serialize(), []byte{192, 168, 0, 41}) {
		t.Fatal("an address is still in the serialized room info")
	}
}

func TestTruncated(t *testing.T) {
	in := vec(t, "room_info_input")
	// the trailing empty streams are optional, as for the reference
	for n := 0; n < len(in)-6; n++ {
		if _, err := DeserializeRoomInfo(in[:n]); err == nil {
			t.Fatalf("%d of %d bytes accepted", n, len(in))
		}
	}
}

func FuzzRoomInfo(f *testing.F) {
	f.Add(vec(&testing.T{}, "room_info_input"))
	f.Fuzz(func(t *testing.T, b []byte) {
		info, err := DeserializeRoomInfo(b)
		if err != nil {
			return
		}
		again, err := DeserializeRoomInfo(info.Serialize())
		if err != nil {
			t.Fatalf("reserialized room info doesn't parse: %v", err)
		}
		if !bytes.Equal(again.Serialize(), info.Serialize()) {
			t.Fatal("not stable")
		}
	})
}

func FuzzPlayerInfo(f *testing.F) {
	f.Add(vec(&testing.T{}, "player_info"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if p, err := DeserializePlayerInfo(b); err == nil {
			p.WithoutAddresses().Serialize()
		}
	})
}
