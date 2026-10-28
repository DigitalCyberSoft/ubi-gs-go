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
