// Package gsm implements GS messages, the framing of every Game Service TCP connection: a 6-byte header
// (u24 big-endian size, property and priority, type, sender and receiver) and a data-list payload,
// scrambled with GS XOR or encrypted with the connection's Blowfish key.
package gsm

import (
	"errors"
	"fmt"
	"io"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/crypto"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/dl"
)

// HeaderSize is the length of the message header.
const HeaderSize = 6

// MaxSize is the largest message accepted from a client. The game's largest messages (room data,
// profile blobs up to 64 KiB) stay well below it.
const MaxSize = 256 * 1024

// Property tells how the payload is encoded.
type Property uint8

const (
	// PropGS is a GS XOR scrambled payload.
	PropGS Property = 0
	// PropGame is a game-specific payload (not used by Heroes V).
	PropGame Property = 1
	// PropGSEncrypt is a payload encrypted with the connection's Blowfish key.
	PropGSEncrypt Property = 2
)

func (p Property) String() string {
	switch p {
	case PropGS:
		return "GS"
	case PropGame:
		return "GAME"
	case PropGSEncrypt:
		return "GS_ENCRYPT"
	}
	return fmt.Sprintf("PROPERTY(%d)", uint8(p))
}

// Party is a message sender or receiver.
type Party uint8

// Senders and receivers.
const (
	PartyRouter Party = 1
	PartyServer Party = 2
	PartyW      Party = 3
	PartyPlayer Party = 4
	PartyAP     Party = 5
	PartyB      Party = 6
	PartyLP     Party = 7
	PartyUnk    Party = 8
	PartyG      Party = 9
	PartyA      Party = 10
	PartyProxy  Party = 11
)

var partyNames = map[Party]string{
	PartyRouter: "R", PartyServer: "S", PartyW: "W", PartyPlayer: "P", PartyAP: "AP", PartyB: "B",
	PartyLP: "LP", PartyUnk: "UNK", PartyG: "G", PartyA: "A", PartyProxy: "PROXY",
}

func (p Party) String() string {
	if n, ok := partyNames[p]; ok {
		return n
	}
	return fmt.Sprintf("PARTY(%d)", uint8(p))
}

// Header is the GS message header.
type Header struct {
	Size     int
	Property Property
	Priority uint8
	Type     Type
	Sender   Party
	Receiver Party
}

// ErrBadMessage is returned for a message that can't be parsed; the connection it came on can't be
// trusted to stay in sync and is closed.
var ErrBadMessage = errors.New("bad message")

func bad(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrBadMessage, fmt.Sprintf(format, args...))
}

// ParseHeader reads a header, checking every field the way the reference implementation's enums do.
func ParseHeader(b []byte) (Header, error) {
	if len(b) < HeaderSize {
		return Header{}, bad("message shorter than its header (%dB)", len(b))
	}
	h := Header{
		Size:     int(b[0])<<16 | int(b[1])<<8 | int(b[2]),
		Property: Property(b[3] >> 6),
		Priority: b[3] & 0x3f,
		Type:     Type(b[4]),
		Sender:   Party(b[5] >> 4),
		Receiver: Party(b[5] & 0x0f),
	}
	if h.Property > PropGSEncrypt {
		return h, bad("unknown property %d", h.Property)
	}
	if !h.Type.Known() {
		return h, bad("unknown message type %d", uint8(h.Type))
	}
	if _, ok := partyNames[h.Sender]; !ok {
		return h, bad("unknown sender %d", h.Sender)
	}
	if _, ok := partyNames[h.Receiver]; !ok {
		return h, bad("unknown receiver %d", h.Receiver)
	}
	if h.Size < HeaderSize {
		return h, bad("message size %dB is below the header size", h.Size)
	}
	return h, nil
}

// Bytes writes the header.
func (h Header) Bytes() []byte {
	return []byte{
		byte(h.Size >> 16), byte(h.Size >> 8), byte(h.Size),
		byte(h.Property)<<6 | h.Priority&0x3f,
		byte(h.Type),
		byte(h.Sender)<<4 | byte(h.Receiver)&0x0f,
	}
}

// Message is a GS message: its header and decoded payload (nil when there is none).
type Message struct {
	Header Header
	Data   dl.List
}

// Decode parses one complete message. bfKey is the connection's Blowfish key for GS_ENCRYPT payloads.
func Decode(buf []byte, bfKey *crypto.Blowfish) (*Message, error) {
	h, err := ParseHeader(buf)
	if err != nil {
		return nil, err
	}
	if h.Size > len(buf) {
		return nil, bad("message size %dB exceeds the data (%dB)", h.Size, len(buf))
	}
	m := &Message{Header: h}
	payload := buf[HeaderSize:h.Size]
	switch h.Property {
	case PropGS:
		if len(payload) > 0 {
			m.Data, err = dl.Decode(crypto.XORDecrypt(payload))
		}
	case PropGame:
		// not used by the game; the payload is left alone
	case PropGSEncrypt:
		if bfKey == nil {
			return nil, bad("Blowfish payload before the key exchange")
		}
		var plain []byte
		plain, err = bfKey.Decrypt(payload)
		if err == nil {
			m.Data, err = dl.Decode(plain)
		}
	}
	if err != nil {
		return nil, bad("%s payload: %v", h.Type, err)
	}
	return m, nil
}

// Encode writes the message with a GS XOR payload; the header's size is set from it.
func (m *Message) Encode() ([]byte, error) {
	var payload []byte
	if len(m.Data) > 0 {
		switch m.Header.Property {
		case PropGS:
			payload = crypto.XOREncrypt(m.Data.Encode())
		default:
			return nil, fmt.Errorf("gsm: %s payloads are not sent by this server", m.Header.Property)
		}
	}
	h := m.Header
	h.Size = HeaderSize + len(payload)
	if h.Size > 0xFFFFFF {
		return nil, errors.New("gsm: message too long")
	}
	return append(h.Bytes(), payload...), nil
}

// MustEncode is Encode for messages built by the server, which always encode.
func (m *Message) MustEncode() []byte {
	b, err := m.Encode()
	if err != nil {
		panic(err)
	}
	return b
}

// Read reads one message from a stream: the header, then as many bytes as it says.
func Read(r io.Reader, bfKey *crypto.Blowfish) (*Message, []byte, error) {
	head := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, head); err != nil {
		return nil, nil, err
	}
	h, err := ParseHeader(head)
	if err != nil {
		return nil, nil, err
	}
	if h.Size > MaxSize {
		return nil, nil, bad("message of %dB is over the %dB limit", h.Size, MaxSize)
	}
	buf := make([]byte, h.Size)
	copy(buf, head)
	if _, err := io.ReadFull(r, buf[HeaderSize:]); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, nil, err
	}
	m, err := Decode(buf, bfKey)
	return m, buf, err
}

// Reply returns a response to req: its header with sender and receiver swapped, the given type and a
// GS payload. Use req.Header.Type to keep the request's type.
func Reply(req *Message, t Type, data dl.List) *Message {
	h := req.Header
	h.Sender, h.Receiver = h.Receiver, h.Sender
	h.Type = t
	h.Property = PropGS
	return &Message{Header: h, Data: data}
}

// Notification returns a server-initiated message.
func Notification(t Type, sender, receiver Party, data dl.List) *Message {
	return &Message{
		Header: Header{Property: PropGS, Priority: 1, Type: t, Sender: sender, Receiver: receiver},
		Data:   data,
	}
}

// String formats the message for logs; passwords are left out.
func (m *Message) String() string {
	h := m.Header
	s := fmt.Sprintf("<%s %s %s->%s %dB>", h.Type, h.Property, h.Sender, h.Receiver, h.Size)
	if d := m.Redacted(); d != nil {
		s += " " + d.String()
	}
	return s
}

// Redacted returns the payload for logs: a router LOGIN (user, password, game id, ...) without the password.
func (m *Message) Redacted() dl.List {
	if m.Data == nil {
		return nil
	}
	if m.Header.Type == LOGIN && len(m.Data) >= 3 {
		out := append(dl.List{m.Data[0], dl.S("<password>")}, m.Data[2:]...)
		return out
	}
	return m.Data
}
