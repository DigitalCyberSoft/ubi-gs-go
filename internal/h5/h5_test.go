package h5

import (
	"bytes"
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
	if string(info.GroupName) != "a\x00l\x00i\x00c\x00e\x00'\x00s\x00 \x00G\x00a\x00m\x00e\x00" || info.MaxPlayers != 2 {
		t.Fatalf("parsed %q %d", info.GroupName, info.MaxPlayers)
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

// streamsOf splits a structure's fields.
func streamsOf(t *testing.T, buf []byte) []Stream {
	t.Helper()
	var out []Stream
	for len(buf) > 0 {
		s, n, err := readStream(buf)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
		buf = buf[n:]
	}
	return out
}

func dataOf(t *testing.T, buf []byte) []byte {
	t.Helper()
	data, err := unwrap(buf)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// relaid is the room info vector with its fields passed through edit.
func relaid(t *testing.T, edit func([]Stream) []Stream) []byte {
	var out []byte
	for _, s := range edit(streamsOf(t, dataOf(t, vec(t, "room_info_with_player")))) {
		out = appendStream(out, s.ID, s.Data)
	}
	return wrap(out)
}

// The expansions don't lay out the room info like 1.60: the fields the lobby doesn't read go back as they
// came, in their place, and the ones it changes are still changed.
func TestRoomInfoOtherLayouts(t *testing.T) {
	for _, c := range []struct {
		name string
		edit func([]Stream) []Stream
		diff string
	}{
		{"a field in another form, and a field 1.60 doesn't have", func(f []Stream) []Stream {
			for i := range f {
				if f[i].ID == 12 {
					f[i].Data = le32(2)
				}
			}
			return append(f, Stream{ID: 41, Data: []byte("new")})
		}, "kept as sent: 12 (size 4), 41 (size 3)"},
		{"fields 1.60 doesn't have, and some of its fields missing", func(f []Stream) []Stream {
			var out []Stream
			for _, s := range f {
				if s.ID >= 37 {
					continue
				}
				out = append(out, s)
				if s.ID == 33 {
					out = append(out, Stream{ID: 34, Data: le32(7)}, Stream{ID: 35, Data: []byte{1}})
				}
			}
			return out
		}, "kept as sent: 34 (size 4), 35 (size 1); missing: 37, 38, 39, 40"},
	} {
		in := relaid(t, c.edit)
		info, err := DeserializeRoomInfo(in)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := info.Serialize(); !bytes.Equal(got, in) {
			t.Fatalf("%s: written back\n%x\nwant\n%x", c.name, got, in)
		}
		if d := info.Differences(); d != c.diff {
			t.Fatalf("%s: differences %q, want %q", c.name, d, c.diff)
		}
		info.GroupID = 77
		info.HostIP.IP = [4]byte{10, 0, 0, 2}
		out := info.WithoutAddresses().Serialize()
		again, err := DeserializeRoomInfo(out)
		if err != nil || again.GroupID != 77 || again.HostIP.IP != [4]byte{} || again.PlayerInfos[0].ExtIP.IP != [4]byte{} {
			t.Fatalf("%s: changed room info %+v (%v)", c.name, again, err)
		}
		if bytes.Contains(out, []byte{10, 0, 0, 2}) || bytes.Contains(out, []byte{192, 168, 0, 41}) {
			t.Fatalf("%s: an address is still in the room info", c.name)
		}
		want, got := streamsOf(t, dataOf(t, in)), streamsOf(t, dataOf(t, out))
		if len(got) != len(want) {
			t.Fatalf("%s: %d fields, want %d", c.name, len(got), len(want))
		}
		for i := range want {
			changed := want[i].ID == 2 || want[i].ID == 4 || want[i].ID == 22
			if got[i].ID != want[i].ID || (!changed && !bytes.Equal(got[i].Data, want[i].Data)) {
				t.Fatalf("%s: field %d is %d %x, want %d %x", c.name, i, got[i].ID, got[i].Data, want[i].ID, want[i].Data)
			}
		}
	}
}

// The fields the lobby changes must be there in the form it knows, once.
func TestRoomInfoRequiredFields(t *testing.T) {
	without := func(id byte) func([]Stream) []Stream {
		return func(f []Stream) []Stream {
			var out []Stream
			for _, s := range f {
				if s.ID != id {
					out = append(out, s)
				}
			}
			return out
		}
	}
	for name, edit := range map[string]func([]Stream) []Stream{
		"no group id":     without(2),
		"no host address": without(4),
		"no player list":  without(22),
		"host address in another form": func(f []Stream) []Stream {
			for i := range f {
				if f[i].ID == 4 {
					f[i].Data = le32(1)
				}
			}
			return f
		},
		"host address twice": func(f []Stream) []Stream { return append(f, f[2]) },
		"a field twice":      func(f []Stream) []Stream { return append(f, Stream{ID: 12, Data: []byte{1}}) },
	} {
		if _, err := DeserializeRoomInfo(relaid(t, edit)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestPlayerInfoOtherLayout(t *testing.T) {
	extra := appendStream(nil, 6, []byte{1, 2, 3, 4})
	in := wrap(append(dataOf(t, vec(t, "player_info")), extra...))
	p, err := DeserializePlayerInfo(in)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Serialize(); !bytes.Equal(got, in) {
		t.Fatalf("written back %x, want %x", got, in)
	}
	out := dataOf(t, p.WithoutAddresses().Serialize())
	if bytes.Contains(out, []byte{10, 0, 0, 2}) || bytes.Contains(out, []byte{192, 168, 0, 41}) || !bytes.HasSuffix(out, extra) {
		t.Fatalf("without addresses: %x", out)
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
