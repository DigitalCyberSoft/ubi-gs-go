package gsm_test

import (
	"bytes"
	"strconv"
	"testing"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/crypto"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/dl"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/gsm"
)

func keyExchange(reqID string, buf []byte) *gsm.Message {
	return &gsm.Message{Header: gsm.Header{Type: gsm.KEY_EXCHANGE},
		Data: dl.List{dl.S(reqID), dl.L(dl.S("1"), dl.S(strconv.Itoa(len(buf))), dl.B(buf))}}
}

func replyKey(t *testing.T, res *gsm.Message) []byte {
	args, _ := res.Data.List(1)
	buf, ok := args.Bin(2)
	if !ok {
		t.Fatalf("no key in %v", res.Data)
	}
	return buf
}

// Every exchange answers with the same server key (generating one per exchange cost about 30 ms of CPU
// for anyone who asked), and each still ends with the game holding its session's Blowfish key.
func TestKeyExchangeSharedServerKey(t *testing.T) {
	game, err := crypto.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	var serverKeys [][]byte
	for range 2 {
		var s gsm.Session
		res, err := s.KeyExchange(keyExchange("1", game.PublicKey.Marshal()))
		if err != nil {
			t.Fatal(err)
		}
		svBuf := replyKey(t, res)
		serverKeys = append(serverKeys, svBuf)
		sv, err := crypto.ParsePublicKey(svBuf)
		if err != nil {
			t.Fatal(err)
		}
		enc, err := crypto.EncryptPKCS1v15(nil, sv, crypto.NewSessionKey())
		if err != nil {
			t.Fatal(err)
		}
		res, err = s.KeyExchange(keyExchange("2", enc))
		if err != nil {
			t.Fatal(err)
		}
		key, err := crypto.DecryptPKCS1v15(game, replyKey(t, res))
		if err != nil {
			t.Fatal(err)
		}
		bf, err := crypto.NewBlowfish(key)
		if err != nil {
			t.Fatal(err)
		}
		plain := []byte("8 bytes!")
		want, _ := bf.Encrypt(plain)
		got, _ := s.Blowfish.Encrypt(plain)
		if !bytes.Equal(got, want) {
			t.Fatal("the session's Blowfish key isn't the one sent to the game")
		}
	}
	if !bytes.Equal(serverKeys[0], serverKeys[1]) {
		t.Fatal("each exchange generated its own server key")
	}
}
