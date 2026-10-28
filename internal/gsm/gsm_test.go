package gsm_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/dl"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/gsm"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/testvec"
)

// Reply is one request/reply vector of the reference.
type Reply struct{ Name, Request, Response string }

func replies(t *testing.T) map[string]Reply {
	var vs []Reply
	testvec.Get(t, testvec.Load(t), "replies", &vs)
	out := map[string]Reply{}
	for _, v := range vs {
		out[v.Name] = v
	}
	return out
}

func TestReplyVectors(t *testing.T) {
	builders := map[string]func(*gsm.Message) *gsm.Message{
		"stillalive":     gsm.StillAlive,
		"login":          func(r *gsm.Message) *gsm.Message { return gsm.Success(r) },
		"login_fail":     func(r *gsm.Message) *gsm.Message { return gsm.Fail(r, 2) },
		"joinwaitmodule": func(r *gsm.Message) *gsm.Message { return gsm.JoinWaitModule(r, "10.0.0.1", 7782) },
		"proxy_joinwaitmodule": func(r *gsm.Message) *gsm.Message {
			return gsm.ProxyJoinWaitModule(r, "averyveryverylongname", "10.0.0.1", 7784)
		},
		"loginwaitmodule":       func(r *gsm.Message) *gsm.Message { return gsm.Success(r) },
		"proxy_loginwaitmodule": func(r *gsm.Message) *gsm.Message { return gsm.Success(r, dl.L()) },
		"proxy_login":           func(r *gsm.Message) *gsm.Message { return gsm.Success(r, dl.L()) },
		"playerinfo":            func(r *gsm.Message) *gsm.Message { return gsm.PlayerInfo(r, "alice") },
		"playerinfo_long":       func(r *gsm.Message) *gsm.Message { return gsm.PlayerInfo(r, "averyveryverylongname") },
		"loginfriends":          func(r *gsm.Message) *gsm.Message { return gsm.Success(r) },
		"addfriend":             func(r *gsm.Message) *gsm.Message { return gsm.Success(r, dl.S("bob")) },
		"addfriend_fail":        func(r *gsm.Message) *gsm.Message { return gsm.Fail(r, 1) },
		"friendlist":            func(r *gsm.Message) *gsm.Message { return gsm.Success(r) },
		"lobby_result":          gsm.LobbyResult,
		"lobby_group":           gsm.LobbyGroup,
	}
	vs := replies(t)
	for name, build := range builders {
		v, ok := vs[name]
		if !ok {
			t.Fatalf("no vector %s", name)
		}
		req, err := gsm.Decode(testvec.Hex(t, v.Request), nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got := build(req).MustEncode()
		if want := testvec.Hex(t, v.Response); !bytes.Equal(got, want) {
			t.Errorf("%s: %x, want %x", name, got, want)
		}
	}
}

func TestUpdateFriendVectors(t *testing.T) {
	all := testvec.Load(t)
	for key, online := range map[string]bool{"update_friend_online": true, "update_friend_offline": false} {
		var want string
		testvec.Get(t, all, key, &want)
		if got := gsm.UpdateFriend("bob", online).MustEncode(); !bytes.Equal(got, testvec.Hex(t, want)) {
			t.Errorf("%s: %x, want %s", key, got, want)
		}
	}
}

func TestHeaderChecks(t *testing.T) {
	for _, b := range [][]byte{
		{0, 0, 6, 1, 0xFE, 0x42},  // unknown type
		{0, 0, 6, 0xC1, 58, 0x42}, // property 3
		{0, 0, 6, 1, 58, 0x02},    // sender 0
		{0, 0, 5, 1, 58, 0x42},    // size below the header
		{0, 0, 6},
	} {
		if _, err := gsm.Decode(b, nil); err == nil {
			t.Errorf("Decode(%x) accepted", b)
		}
	}
	if _, err := gsm.Decode([]byte{0, 0, 9, 0x81, 58, 0x42, 1, 2, 3}, nil); err == nil {
		t.Error("GS_ENCRYPT without a key accepted")
	}
}

func TestRead(t *testing.T) {
	keep := []byte{0, 0, 6, 1, 58, 0x42}
	r := bytes.NewReader(append(append([]byte{}, keep...), keep...))
	for i := 0; i < 2; i++ {
		m, _, err := gsm.Read(r, nil)
		if err != nil || m.Header.Type != gsm.STILLALIVE {
			t.Fatalf("message %d: %v", i, err)
		}
	}
	big := []byte{0x10, 0, 0, 1, 58, 0x42}
	if _, _, err := gsm.Read(bytes.NewReader(big), nil); err == nil {
		t.Fatal("oversized message accepted")
	}
}

func TestRedaction(t *testing.T) {
	m := gsm.Notification(gsm.LOGIN, gsm.PartyPlayer, gsm.PartyRouter, dl.List{dl.S("alice"), dl.S("secret"), dl.S("HEROES_c83663d1c69a2024")})
	dec, err := gsm.Decode(m.MustEncode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	s := dec.String()
	if strings.Contains(s, "secret") || !strings.Contains(s, "alice") || !strings.Contains(s, "HEROES_c83663d1c69a2024") {
		t.Fatalf("log line %s", s)
	}
	if v, _ := dec.Data.Str(1); v != "secret" {
		t.Fatal("payload changed")
	}
}

func TestCap(t *testing.T) {
	if got := gsm.Cap("ééééééé", 12); got != "ééééé" {
		t.Errorf("Cap = %q", got)
	}
	if got := gsm.Cap("short", 12); got != "short" {
		t.Errorf("Cap = %q", got)
	}
	// the game's own code page is cut at the byte
	if got := gsm.Cap("\xe9\xe9\xe9\xe9\xe9\xe9\xe9\xe9\xe9\xe9\xe9\xe9", 12); len(got) != 11 {
		t.Errorf("Cap = %q", got)
	}
}

func FuzzDecode(f *testing.F) {
	f.Add([]byte{0, 0, 6, 1, 58, 0x42})
	f.Add(gsm.Notification(gsm.LOBBY_MSG, gsm.PartyPlayer, gsm.PartyServer, dl.List{dl.S("12"), dl.Strs("1", "x")}).MustEncode())
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := gsm.Decode(b, nil)
		if err == nil {
			_ = m.String()
		}
		gsm.Read(bytes.NewReader(b), nil)
	})
}
