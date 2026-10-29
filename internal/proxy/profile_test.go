package proxy_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/dl"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/env"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/gsclient"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/gsm"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/proxy"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/testserver"
)

// What the game sent after "hello from ubigs" was typed into a new profile's Additional Information.
var saved, _ = hex.DecodeString("0408040000000154015002083c0001000440680065006c006c006f002000660072006f006d002000750062006900670073000000020005" + "00")

func utf16le(s string) []byte {
	var out []byte
	for _, r := range s {
		out = binary.LittleEndian.AppendUint16(out, uint16(r))
	}
	return out
}

// chunk is a chunk or section: [id][length*2], or [id][length*2|1 as 4 bytes], then the data.
func chunk(id byte, data []byte, long bool) []byte {
	out := []byte{id}
	if n := len(data) * 2; long || n >= 0x100 {
		out = binary.LittleEndian.AppendUint32(out, uint32(n)|1)
	} else {
		out = append(out, byte(n))
	}
	return append(out, data...)
}

func i32(v int32) []byte { return binary.LittleEndian.AppendUint32(nil, uint32(v)) }

var (
	version = chunk(4, i32(4), false)
	empty   = cat(chunk(0, nil, false), chunk(2, nil, false), chunk(5, nil, false))
)

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

func profileWith(sections []byte, fields ...[]byte) []byte {
	return cat(version, chunk(1, chunk(1, cat(fields...), false), false), sections)
}

func TestProfileCodec(t *testing.T) {
	if want := "0408040000000114011002083c0001000400000002000500"; hex.EncodeToString(proxy.DefaultProfile) != want {
		t.Fatalf("default profile %x, want %s", proxy.DefaultProfile, want)
	}
	p, err := proxy.DecodeProfile(saved)
	if err != nil || p.Avatar != 0x1003c || string(p.Text) != string(utf16le("hello from ubigs")) {
		t.Fatalf("the game's profile: %+v %v", p, err)
	}
	if !bytes.Equal(p.Encode(), saved) {
		t.Fatalf("written again: %x", p.Encode())
	}
	// the longest text takes 4-byte lengths
	long := proxy.Profile{Avatar: 7, Text: utf16le(strings.Repeat("é", proxy.MaxProfileText))}.Encode()
	if p, err := proxy.DecodeProfile(long); err != nil || len(long) > proxy.MaxProfileSize || p.Avatar != 7 || len(p.Text) != 2*proxy.MaxProfileText {
		t.Fatalf("longest text: %d bytes, %v", len(long), err)
	}
	// missing fields read as the defaults, as in the game
	if p, err := proxy.DecodeProfile(profileWith(empty)); err != nil || p.Avatar != proxy.DefaultAvatar || len(p.Text) != 0 {
		t.Fatalf("no fields: %+v %v", p, err)
	}
	// 4-byte lengths everywhere, no empty sections
	loose := cat(chunk(4, i32(4), true), chunk(1, chunk(1, cat(chunk(2, i32(0x1003c), true), chunk(4, utf16le("hello from ubigs"), true)), true), true))
	if p, err := proxy.DecodeProfile(loose); err != nil || !bytes.Equal(p.Encode(), saved) {
		t.Fatalf("loose: %+v %v", p, err)
	}
}

func TestProfileRefused(t *testing.T) {
	avatar := chunk(2, i32(1), false)
	bad := map[string][]byte{
		"garbage":         []byte("x"),
		"empty":           nil,
		"truncated":       saved[:len(saved)-1],
		"version 5":       cat(chunk(4, i32(5), false), saved[6:]),
		"type map entry":  profileWith(cat(empty[:4], chunk(5, []byte("x"), false)), avatar),
		"object":          profileWith(cat(chunk(0, make([]byte, 9), false), empty[2:]), avatar),
		"unknown section": cat(saved, chunk(3, nil, false)),
		"section twice":   cat(saved, version),
		"profile twice":   cat(version, chunk(1, cat(chunk(1, nil, false), chunk(1, nil, false)), false)),
		"other chunk":     cat(version, chunk(1, chunk(3, nil, false), false)),
		"odd text":        profileWith(empty, avatar, chunk(4, []byte("abc"), false)),
		"long text":       proxy.Profile{Text: utf16le(strings.Repeat("x", proxy.MaxProfileText+1))}.Encode(),
		"short avatar":    profileWith(empty, chunk(2, []byte{1, 0}, false)),
		"unknown field":   profileWith(empty, avatar, chunk(6, nil, false)),
		"field twice":     profileWith(empty, avatar, avatar),
		"huge length":     cat(version, []byte{1, 0xff, 0xff, 0xff, 0xff}),
	}
	for name, data := range bad {
		if p, err := proxy.DecodeProfile(data); err == nil {
			t.Errorf("%s: accepted as %+v", name, p)
		}
	}
}

func TestProfileStore(t *testing.T) {
	testserver.NeedLoopbackAliases(t)
	s := testserver.Start(t, nil)
	alice, _ := s.Accounts().Login("alice", "pw")
	s.Accounts().BindSession("alice", "127.0.0.2", alice)
	c, _ := gsclient.New("127.0.0.2", s.Addr(env.PortProxyWM), gsm.PartyRouter)
	defer c.Close()
	request := func(code, seq string, payload ...dl.Value) string {
		t.Helper()
		res, err := c.Request(gsm.PROXY_HANDLER, dl.S(code), dl.S(seq), dl.L(payload...))
		if err != nil {
			t.Fatal(err)
		}
		return res.Data.String()
	}
	get := func(seq, name string) string {
		return request("1025", seq, dl.S("G"), dl.S("0"), dl.S(name), dl.S("0"), dl.S("PUBLIC"))
	}
	set := func(seq string, data []byte) string {
		return request("1026", seq, dl.S("G"), dl.S("0"), dl.S("alice"), dl.S("0"), dl.S("PUBLIC"), dl.B(data), dl.S("1"))
	}
	reply := func(code, seq string, data []byte) string {
		return dl.L(dl.S(code), dl.S(seq), dl.L(dl.S("38"), dl.L(dl.B(data), dl.S(strconv.Itoa(len(data)))))).String()
	}
	// a new player gets the default profile; no such player, the failure
	if got := get("1", "alice"); got != reply("1025", "1", proxy.DefaultProfile) {
		t.Fatalf("new player: %s", got)
	}
	if got := get("2", "nobody"); got != "['1025', '2', ['39', ['1']]]" {
		t.Fatalf("no such player: %s", got)
	}
	// only a profile is stored
	if got := set("3", []byte("not a profile")); got != "['1026', '3', ['39', ['0']]]" {
		t.Fatalf("garbage: %s", got)
	}
	// stored as written again
	loose := cat(chunk(4, i32(4), true), chunk(1, chunk(1, cat(chunk(2, i32(0x1003c), true), chunk(4, utf16le("hello from ubigs"), true)), true), true))
	if got := set("4", loose); got != "['1026', '4', ['38', []]]" {
		t.Fatalf("save: %s", got)
	}
	if got := get("5", "ALICE"); got != reply("1025", "5", saved) {
		t.Fatalf("after the save: %s", got)
	}
}

// Whatever a game sends, decoding doesn't panic, and what it accepts is written again as a profile
// that decodes to the same.
func FuzzDecodeProfile(f *testing.F) {
	f.Add(saved)
	f.Add(proxy.DefaultProfile)
	f.Add(cat(version, chunk(1, chunk(1, chunk(2, i32(9), true), true), true)))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := proxy.DecodeProfile(data)
		if err != nil {
			return
		}
		again, err := proxy.DecodeProfile(p.Encode())
		if err != nil || again.Avatar != p.Avatar || !bytes.Equal(again.Text, p.Text) || len(p.Encode()) > proxy.MaxProfileSize {
			t.Fatalf("%x: %+v, written again %+v %v", data, p, again, err)
		}
	})
}
