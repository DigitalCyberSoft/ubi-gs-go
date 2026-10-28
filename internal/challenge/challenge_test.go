package challenge

import (
	"encoding/hex"
	"testing"
	"time"
)

// Vectors computed independently from the spec (Python hmac/hashlib).
func TestVectors(t *testing.T) {
	for _, v := range []struct{ token, nonce, verifier, response string }{
		{"abcdefghijklmnop", "00112233445566778899aabbccddeeff", "e5bf4c1473fb0e72609d6e9c3450b376a7ad6e348b43cc9d968c28411ca175ab", "~1:UJMaJUfHNeznWBx0"},
		{"Zz09_-AbCdEfGhIj", "0123456789abcdef", "630d03c52b71a59b00dff9d6c9813ebff8fb4e20089ce7ac652cc20c95742bb9", "~1:4WLvq1o2gm5m91hX"},
	} {
		V := Verifier(v.token)
		if hex.EncodeToString(V) != v.verifier {
			t.Errorf("verifier of %s: %x", v.token, V)
		}
		r := Response(V, v.nonce)
		if r != v.response || len(r) != 19 {
			t.Errorf("response: %s, want %s", r, v.response)
		}
		if !Check(V, v.nonce, v.response) || Check(V, v.nonce, v.response[:18]+"A") {
			t.Error("Check")
		}
	}
}

func TestNonces(t *testing.T) {
	n := NewNonces()
	now := time.Unix(1000, 0)
	n.SetClock(func() time.Time { return now })
	a := n.Issue("10.0.0.1")
	if len(a) != 32 {
		t.Fatalf("nonce %q", a)
	}
	// another address can't use it
	if n.Redeem("10.0.0.2", func(x string) bool { return x == a }) {
		t.Fatal("redeemed from another address")
	}
	if !n.Redeem("10.0.0.1", func(x string) bool { return x == a }) {
		t.Fatal("not redeemed")
	}
	if n.Redeem("10.0.0.1", func(x string) bool { return x == a }) {
		t.Fatal("redeemed twice")
	}
	b := n.Issue("10.0.0.1")
	now = now.Add(NonceTTL + time.Second)
	if n.Redeem("10.0.0.1", func(x string) bool { return x == b }) {
		t.Fatal("expired nonce redeemed")
	}
	// a miss uses up the address's nonces
	c := n.Issue("10.0.0.1")
	n.Redeem("10.0.0.1", func(string) bool { return false })
	if n.Redeem("10.0.0.1", func(x string) bool { return x == c }) {
		t.Fatal("nonce kept after a miss")
	}
	// bounded per address
	for i := 0; i < MaxPerIP+5; i++ {
		n.Issue("10.0.0.3")
	}
	if got := n.Outstanding("10.0.0.3"); got != MaxPerIP {
		t.Fatalf("%d outstanding", got)
	}
}

func TestKind(t *testing.T) {
	for pw, want := range map[string]string{"~r:abc": "register", "~1:abc": "challenge", "secret": "plain", "a~r:": "plain"} {
		if Kind(pw) != want {
			t.Errorf("Kind(%q)", pw)
		}
	}
}
