package gsm

import (
	"errors"
	"fmt"
	"strconv"
	"sync"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/crypto"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/dl"
)

// serverKey is the RSA key of every connection's key exchange. A key per exchange cost about 30 ms of
// CPU, asked for by anyone before logging in; the key only decrypts the game's key, which is checked
// and dropped, while the session's Blowfish key goes out encrypted to the game's own key.
var serverKey = sync.OnceValues(func() (*crypto.PrivateKey, error) { return crypto.GenerateKey(nil) })

// Session is the per-connection key exchange state of a GS TCP connection.
type Session struct {
	gamePub *crypto.PublicKey
	priv    *crypto.PrivateKey
	// Blowfish decrypts the connection's GS_ENCRYPT messages once the key exchange is done.
	Blowfish *crypto.Blowfish
}

// KeyExchange answers KEY_EXCHANGE:
//   - ['1', [?, ?, game public key]] -> ['1', ['1', len, server public key]] (RSA-512, e=3);
//   - ['2', [?, ?, encrypted key]] -> ['2', ['1', len, new Blowfish key encrypted to the game's key]],
//     and that key decrypts the connection's GS_ENCRYPT messages from then on.
func (s *Session) KeyExchange(req *Message) (*Message, error) {
	reqID, _ := req.Data.Str(0)
	args, _ := req.Data.List(1)
	buf, ok := args.Bin(2)
	switch reqID {
	case "1":
		if !ok {
			return nil, errors.New("KEY_EXCHANGE 1 without the game's key")
		}
		pub, err := crypto.ParsePublicKey(buf)
		if err != nil {
			return nil, err
		}
		priv, err := serverKey()
		if err != nil {
			return nil, err
		}
		s.gamePub, s.priv = pub, priv
		key := priv.PublicKey.Marshal()
		return s.reply(req, "1", key), nil
	case "2":
		if !ok {
			return nil, errors.New("KEY_EXCHANGE 2 without the encrypted key")
		}
		if s.priv == nil || s.gamePub == nil {
			return nil, errors.New("KEY_EXCHANGE 2 before 1")
		}
		// the game's key; the game uses the one sent back for its encrypted messages
		if _, err := crypto.DecryptPKCS1v15(s.priv, buf); err != nil {
			return nil, err
		}
		key := crypto.NewSessionKey()
		enc, err := crypto.EncryptPKCS1v15(nil, s.gamePub, key)
		if err != nil {
			return nil, err
		}
		bf, err := crypto.NewBlowfish(key)
		if err != nil {
			return nil, err
		}
		s.Blowfish = bf
		return s.reply(req, "2", enc), nil
	case "3":
		return nil, errors.New("KEY_EXCHANGE disconnections are not implemented")
	}
	return nil, fmt.Errorf("KEY_EXCHANGE request with reqId %q", reqID)
}

func (s *Session) reply(req *Message, reqID string, buf []byte) *Message {
	data := dl.List{dl.S(reqID), dl.L(dl.S("1"), dl.S(strconv.Itoa(len(buf))), dl.B(buf))}
	return Reply(req, KEY_EXCHANGE, data)
}
