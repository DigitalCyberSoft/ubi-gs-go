package srp

import (
	"bytes"
	"testing"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/dl"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/gsm"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/testvec"
)

func TestVectors(t *testing.T) {
	raw := testvec.Load(t)
	get := func(key string) []byte {
		var s string
		testvec.Get(t, raw, key, &s)
		return testvec.Hex(t, s)
	}
	c := &Conn{}
	syn, err := Parse(get("srp_syn"))
	if err != nil || syn.Window == nil {
		t.Fatalf("SYN: %v", err)
	}
	if got := c.Respond(syn, nil); !bytes.Equal(got, get("srp_syn_ack")) {
		t.Fatalf("SYN+ACK %x, want %x", got, get("srp_syn_ack"))
	}
	seg, err := Parse(get("srp_msg"))
	if err != nil || seg.Msg == nil {
		t.Fatalf("message: %v", err)
	}
	args, _ := seg.Msg.Data.List(1)
	reply := func(sub, ip, port string) []byte {
		return gsm.Reply(seg.Msg, gsm.NAT, dl.List{dl.S(sub), dl.L(args[0], dl.S(ip), dl.S(port))}).MustEncode()
	}
	if got := c.Respond(seg, reply("2", "5", "7781")); !bytes.Equal(got, get("srp_msg_reply")) {
		t.Fatalf("reply %x, want %x", got, get("srp_msg_reply"))
	}
	if got := c.Respond(nil, reply("3", "2130706433", "8888")); !bytes.Equal(got, get("srp_server_initiated")) {
		t.Fatalf("server segment %x, want %x", got, get("srp_server_initiated"))
	}
	var sums []struct {
		Data string
		Sum  uint16
	}
	testvec.Get(t, raw, "srp_checksum", &sums)
	for _, s := range sums {
		if got := Checksum(testvec.Hex(t, s.Data)); got != s.Sum {
			t.Errorf("checksum of %s: %04x, want %04x", s.Data, got, s.Sum)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add(make([]byte, 20))
	f.Fuzz(func(t *testing.T, b []byte) {
		Parse(b)
		Checksum(b)
	})
}
