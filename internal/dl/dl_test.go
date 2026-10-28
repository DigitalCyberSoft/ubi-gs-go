package dl_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/dl"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/testvec"
)

type vec struct {
	Value json.RawMessage
	Enc   string
}

func TestVectors(t *testing.T) {
	all := testvec.Load(t)
	var vs []vec
	testvec.Get(t, all, "dl", &vs)
	for _, v := range vs {
		want := testvec.Value(t, v.Value)
		l, _ := want.List()
		enc := testvec.Hex(t, v.Enc)
		if got := l.Encode(); !bytes.Equal(got, enc) {
			t.Errorf("encode %s: %x, want %x", l, got, enc)
		}
		if len(enc) == 0 {
			continue
		}
		got, err := dl.Decode(enc)
		if err != nil || !got.Equal(l) {
			t.Errorf("decode %x: %s %v, want %s", enc, got, err, l)
		}
	}
	testvec.Get(t, all, "dl_decode", &vs)
	for _, v := range vs {
		want := testvec.Value(t, v.Value)
		l, _ := want.List()
		got, err := dl.Decode(testvec.Hex(t, v.Enc))
		if err != nil || !got.Equal(l) {
			t.Errorf("decode %s: %s %v, want %s", v.Enc, got, err, l)
		}
	}
}

func TestMalformed(t *testing.T) {
	// (a single trailing byte is ignored, as by the reference)
	for _, b := range []string{"", "xy", "b\x00\x00", "b\x00\x00\x00\x05ab", "Ls", "[s1\x00", "s1\x00zz"} {
		if l, err := dl.Decode([]byte(b)); err == nil {
			t.Errorf("Decode(%q) = %s, want an error", b, l)
		}
	}
	deep := bytes.Repeat([]byte("["), dl.MaxDepth+2)
	if _, err := dl.Decode(append(deep, 's', 0)); err == nil {
		t.Error("deep nesting accepted")
	}
}

func TestParseInt(t *testing.T) {
	for s, want := range map[string]int{"12": 12, " 7 ": 7, "-3": -3, "+4": 4, "1_000": 1000} {
		if n, ok := dl.ParseInt(s); !ok || n != want {
			t.Errorf("ParseInt(%q) = %d %v", s, n, ok)
		}
	}
	for _, s := range []string{"", "x", "1x", "_1", "1__0", "99999999999999999999"} {
		if _, ok := dl.ParseInt(s); ok {
			t.Errorf("ParseInt(%q) accepted", s)
		}
	}
}

func TestString(t *testing.T) {
	l := dl.List{dl.S("a'b"), dl.B([]byte{0, 'x'}), dl.L(dl.S("c"))}
	if got := l.String(); got != `['a\'b', b'\x00x', ['c']]` {
		t.Errorf("String() = %s", got)
	}
}

func FuzzDecode(f *testing.F) {
	for _, s := range []string{"s1\x00[s2\x00]", "b\x00\x00\x00\x01x", "[[[]]]", "s\x00"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		l, err := dl.Decode(b)
		if err != nil {
			return
		}
		// what decodes encodes and decodes to the same list
		again, err := dl.Decode(l.Encode())
		if len(l) > 0 && (err != nil || !again.Equal(l)) {
			t.Fatalf("%x: %s then %s %v", b, l, again, err)
		}
		_ = l.String()
	})
}
