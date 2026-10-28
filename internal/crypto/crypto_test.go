package crypto

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/testvec"
)

func TestXORVectors(t *testing.T) {
	var vs []struct{ Plain, Enc string }
	testvec.Get(t, testvec.Load(t), "gsxor", &vs)
	for _, v := range vs {
		plain, enc := testvec.Hex(t, v.Plain), testvec.Hex(t, v.Enc)
		if got := XOREncrypt(plain); !bytes.Equal(got, enc) {
			t.Errorf("encrypt %d bytes: %x, want %x", len(plain), got, enc)
		}
		if got := XORDecrypt(enc); !bytes.Equal(got, plain) {
			t.Errorf("decrypt %d bytes: %x, want %x", len(plain), got, plain)
		}
	}
}

func TestBlowfishBlockVectors(t *testing.T) {
	var vs []struct {
		Key    string
		L, R   uint32
		El, Er uint32
	}
	testvec.Get(t, testvec.Load(t), "blowfish_block", &vs)
	for _, v := range vs {
		bf := MustBlowfish(testvec.Hex(t, v.Key))
		if l, r := bf.EncryptBlock(v.L, v.R); l != v.El || r != v.Er {
			t.Errorf("encrypt %x %x: %x %x, want %x %x", v.L, v.R, l, r, v.El, v.Er)
		}
		if l, r := bf.DecryptBlock(v.El, v.Er); l != v.L || r != v.R {
			t.Errorf("decrypt: %x %x", l, r)
		}
	}
}

func TestBlowfishCipherVectors(t *testing.T) {
	var vs []struct{ Name, Key, Plain, Enc string }
	testvec.Get(t, testvec.Load(t), "blowfish_cipher", &vs)
	for _, v := range vs {
		bf := MustBlowfish(testvec.Hex(t, v.Key))
		plain, enc := testvec.Hex(t, v.Plain), testvec.Hex(t, v.Enc)
		got, err := bf.Encrypt(plain)
		if err != nil || !bytes.Equal(got, enc) {
			t.Errorf("%s encrypt %d bytes: %x, want %x (%v)", v.Name, len(plain), got, enc, err)
		}
		dec, err := bf.Decrypt(enc)
		if err != nil || !bytes.Equal(dec, plain) {
			t.Errorf("%s decrypt: %x (%v)", v.Name, dec, err)
		}
	}
}

func TestBlowfishLongPayload(t *testing.T) {
	// the reference read the length's high byte as x16 (Python bug); 300 bytes must survive
	bf := MustBlowfish([]byte("key"))
	data := bytes.Repeat([]byte("x"), 300)
	enc, _ := bf.Encrypt(data)
	dec, err := bf.Decrypt(enc)
	if err != nil || !bytes.Equal(dec, data) {
		t.Fatalf("round trip: %d bytes, %v", len(dec), err)
	}
}

func TestBlowfishBadInput(t *testing.T) {
	bf := MustBlowfish([]byte("key"))
	for _, b := range [][]byte{nil, {1}, {1, 2, 3}, make([]byte, 9), append(make([]byte, 8), 0xff, 0xff)} {
		if _, err := bf.Decrypt(b); err == nil {
			t.Errorf("Decrypt(%x) accepted", b)
		}
	}
	if _, err := NewBlowfish(nil); err == nil {
		t.Error("empty key accepted")
	}
}

func TestRSAVectors(t *testing.T) {
	var v struct {
		N, D, Plain, Cipher, Pubkey string
		E                           int64
	}
	testvec.Get(t, testvec.Load(t), "rsa", &v)
	n, _ := new(big.Int).SetString(v.N, 16)
	d, _ := new(big.Int).SetString(v.D, 16)
	priv := &PrivateKey{PublicKey: PublicKey{Bits: RSABits, N: n, E: big.NewInt(v.E)}, D: d}
	if got := priv.PublicKey.Marshal(); hex.EncodeToString(got) != v.Pubkey {
		t.Errorf("public key %x, want %s", got, v.Pubkey)
	}
	plain, err := DecryptPKCS1v15(priv, testvec.Hex(t, v.Cipher))
	if err != nil || hex.EncodeToString(plain) != v.Plain {
		t.Fatalf("decrypt the reference's ciphertext: %x %v", plain, err)
	}
	pub, err := ParsePublicKey(testvec.Hex(t, v.Pubkey))
	if err != nil || pub.N.Cmp(n) != 0 || pub.E.Int64() != 3 {
		t.Fatalf("parse: %v", err)
	}
	enc, err := EncryptPKCS1v15(nil, pub, []byte("0123456789abcdef"))
	if err != nil || len(enc) != 64 {
		t.Fatalf("encrypt: %v", err)
	}
	if dec, err := DecryptPKCS1v15(priv, enc); err != nil || string(dec) != "0123456789abcdef" {
		t.Fatalf("round trip: %q %v", dec, err)
	}
}

func TestGenerateKey(t *testing.T) {
	k, err := GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if k.N.BitLen() != 512 || k.E.Int64() != 3 {
		t.Fatalf("key of %d bits, e=%v", k.N.BitLen(), k.E)
	}
	if len(k.PublicKey.Marshal()) != PublicKeyLen {
		t.Fatal("bad marshal size")
	}
	if _, err := DecryptPKCS1v15(k, []byte{1, 2, 3}); err == nil {
		t.Fatal("garbage decrypted")
	}
}

func FuzzXOR(f *testing.F) {
	f.Add([]byte("s1\x00[s1\x00]"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if got := XORDecrypt(XOREncrypt(b)); !bytes.Equal(got, b) {
			t.Fatalf("round trip of %x: %x", b, got)
		}
		XORDecrypt(b)
	})
}

func FuzzBlowfishDecrypt(f *testing.F) {
	bf := MustBlowfish([]byte("SKJDHF$0maoijfn4i8$aJdnv1jaldifar93-AS_dfo;hjhC4jhflasnF3fnd"))
	f.Add(make([]byte, 10))
	f.Fuzz(func(t *testing.T, b []byte) {
		bf.Decrypt(b)
	})
}
