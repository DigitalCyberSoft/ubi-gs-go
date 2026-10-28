package cdkey

import (
	"bytes"
	"strings"
	"testing"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/dl"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/testvec"
)

func TestVectors(t *testing.T) {
	var vs []struct {
		Request  string
		Response *string
	}
	testvec.Get(t, testvec.Load(t), "cdkey", &vs)
	for _, v := range vs {
		m, err := Parse(testvec.Hex(t, v.Request))
		if err != nil {
			t.Fatal(err)
		}
		got, err := Reply(m)
		if err != nil {
			t.Fatal(err)
		}
		if v.Response == nil {
			if got != nil {
				t.Errorf("%s answered", m)
			}
			continue
		}
		if !bytes.Equal(got, testvec.Hex(t, *v.Response)) {
			t.Errorf("%s: %x, want %s", m, got, *v.Response)
		}
	}
}

func TestRedaction(t *testing.T) {
	for _, rt := range []int{Activation, Auth, Validation, DisconnectUser} {
		m, err := Parse(Request(1, rt, dl.List{dl.B([]byte("KEYDERIVEDDATA"))}))
		if err != nil {
			t.Fatal(err)
		}
		if s := m.String(); strings.Contains(s, "KEYDERIVED") || !strings.Contains(s, requestNames[rt]) {
			t.Errorf("log line %s", s)
		}
	}
}

func TestBadPackets(t *testing.T) {
	for _, b := range [][]byte{{1, 0}, {1, 0, 0, 0, 0}, append([]byte{1, 0, 0, 0, 10}, make([]byte, 10)...),
		Request(1, 99, dl.List{})} {
		if _, err := Parse(b); err == nil {
			t.Errorf("Parse(%x) accepted", b)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add(Request(1, Challenge, dl.List{}))
	f.Fuzz(func(t *testing.T, b []byte) {
		if m, err := Parse(b); err == nil {
			Reply(m)
			_ = m.String()
		}
	})
}
