// Package cdkey implements the CD-key service (UDP). Ubisoft's key service is gone, so every key is
// accepted: challenge, activation, authorization and validation all succeed.
package cdkey

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/crypto"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/dl"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/gsm"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/logx"
)

// Key is the static Blowfish key of the CD-key service.
var Key = []byte("SKJDHF$0maoijfn4i8$aJdnv1jaldifar93-AS_dfo;hjhC4jhflasnF3fnd")

var cipher = crypto.MustBlowfish(Key)

// HeaderSize is the message header: a type byte and the payload length (u32 big-endian).
const HeaderSize = 5

// Request types.
const (
	Challenge      = 1
	Activation     = 2
	Auth           = 3
	Validation     = 4
	PlayerStatus   = 5
	DisconnectUser = 6
	StillAlive     = 7
)

var requestNames = map[int]string{
	Challenge: "CHALLENGE", Activation: "ACTIVATION", Auth: "AUTH", Validation: "VALIDATION",
	PlayerStatus: "PLAYER_STATUS", DisconnectUser: "DISCONNECT_USER", StillAlive: "STILL_ALIVE",
}

// playerValid is the validation status of a valid player.
const playerValid = 2

// Message is a CD-key request.
type Message struct {
	Type    byte
	Data    dl.List
	MsgID   int
	ReqType int
	Unknown int
}

// Parse reads a request.
func Parse(b []byte) (*Message, error) {
	if len(b) < HeaderSize {
		return nil, errors.New("cdkey: short message")
	}
	plain, err := cipher.Decrypt(b[HeaderSize:])
	if err != nil {
		return nil, err
	}
	data, err := dl.Decode(plain)
	if err != nil {
		return nil, err
	}
	m := &Message{Type: b[0], Data: data}
	var ok bool
	if m.MsgID, ok = data.Int(0); !ok {
		return nil, errors.New("cdkey: no message id")
	}
	if m.ReqType, ok = data.Int(1); !ok || requestNames[m.ReqType] == "" {
		return nil, errors.New("cdkey: unknown request type")
	}
	if m.ReqType != StillAlive {
		if m.Unknown, ok = data.Int(2); !ok {
			return nil, errors.New("cdkey: malformed request")
		}
		if _, ok = data.At(3); !ok {
			return nil, errors.New("cdkey: malformed request")
		}
	}
	return m, nil
}

// keyData are the requests whose payload derives from the player's CD key, kept out of logs.
func keyData(t int) bool {
	return t == Activation || t == Auth || t == Validation || t == DisconnectUser
}

func (m *Message) String() string {
	name := requestNames[m.ReqType]
	if keyData(m.ReqType) && len(m.Data) > 3 {
		return fmt.Sprintf("<%s: %s>", name, append(append(dl.List{}, m.Data[:3]...), dl.S("<key data>")))
	}
	return fmt.Sprintf("<%s: %s>", name, m.Data)
}

// bin is a binary that holds a serialized binary, which gives the replies the sizes the game expects
// (16, 20 and 16 bytes).
func bin(b []byte) dl.Value { return dl.B(dl.EncodeValue(dl.B(b))) }

func repeat(c byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = c
	}
	return b
}

// Reply returns the response to a request, or nil for the ones that get none.
func Reply(m *Message) ([]byte, error) {
	var data dl.List
	switch m.ReqType {
	case Challenge:
		data = dl.List{bin([]byte("\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x01\x02\x03\x04"))}
	case Activation:
		data = dl.List{bin(repeat(0x33, 11)), bin(repeat(0x44, 11))}
	case Auth:
		data = dl.List{bin(repeat(0x55, 15))}
	case Validation:
		data = dl.List{dl.S(strconv.Itoa(playerValid)), bin(repeat(0x66, 11))}
	default:
		// player status requests are unsupported, the rest are notifications
		return nil, nil
	}
	payload := dl.List{dl.S(strconv.Itoa(m.MsgID)), dl.S(strconv.Itoa(m.ReqType)), dl.S(strconv.Itoa(m.Unknown)),
		dl.L(dl.S(gsm.ResultSuccess), dl.L(data...))}
	enc, err := cipher.Encrypt(payload.Encode())
	if err != nil {
		return nil, err
	}
	out := append([]byte{m.Type}, binary.BigEndian.AppendUint32(nil, uint32(len(enc)))...)
	return append(out, enc...), nil
}

// Request builds a request as the game sends it (for tests and the conformance client).
func Request(msgID, reqType int, data dl.List) []byte {
	l := dl.List{dl.S(strconv.Itoa(msgID)), dl.S(strconv.Itoa(reqType))}
	if data != nil {
		l = append(l, dl.S("1"), dl.L(data...))
	}
	enc, _ := cipher.Encrypt(l.Encode())
	out := append([]byte{1}, binary.BigEndian.AppendUint32(nil, uint32(len(enc)))...)
	return append(out, enc...)
}

// Serve answers requests on the socket until it is closed.
func Serve(conn net.PacketConn, log *logx.Logger) {
	buf := make([]byte, 2048)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Warnf("read: %v", err)
			continue
		}
		// one bad packet must not stop the service
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Errorf("bad packet from %s: internal error %v", addr, r)
				}
			}()
			m, err := Parse(buf[:n])
			if err != nil {
				log.Warnf("bad packet from %s: %v", addr, err)
				return
			}
			log.Debugf("<- %s %s", addr, m)
			res, err := Reply(m)
			if err != nil {
				log.Warnf("no reply to %s: %v", addr, err)
				return
			}
			if res == nil {
				if m.ReqType == PlayerStatus {
					log.Infof("unsupported request from %s: %s", addr, requestNames[m.ReqType])
				}
				return
			}
			if m.ReqType == Validation {
				log.Infof("validated the key of %s", addr)
			}
			conn.WriteTo(res, addr)
		}()
	}
}
