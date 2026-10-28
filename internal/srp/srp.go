// Package srp implements the game's SRP, the small reliable protocol over UDP the NAT service speaks:
// a 12-byte header (checksum, signature, data size, flags, segment and ack numbers, all u16 LE) and a
// window (on SYN) or a GS message.
package srp

import (
	"encoding/binary"
	"errors"
	"strings"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/gsm"
)

// Sizes.
const (
	HeaderSize = 12
	WindowSize = 8
)

// Header flags.
const (
	FlagFIN = 1
	FlagSYN = 2
	FlagACK = 4
	FlagURG = 8
	FlagID  = 0x3040 // always set
)

// Header is an SRP segment header.
type Header struct {
	Checksum  uint16
	Signature uint16
	DataSize  uint16
	Flags     uint16
	Seg       uint16
	Ack       uint16
}

// Window is the connection data a SYN carries.
type Window struct {
	Tail         uint16
	SenderSig    uint16
	ChecksumInit uint16
	BufSize      uint16
}

// Segment is a received SRP segment.
type Segment struct {
	Header Header
	Window *Window
	Msg    *gsm.Message
}

// Has reports whether the header has a flag.
func (h Header) Has(flag uint16) bool { return h.Flags&flag != 0 }

func u16(b []byte, i int) uint16 { return binary.LittleEndian.Uint16(b[i:]) }

// ParseHeader reads a header.
func ParseHeader(b []byte) (Header, error) {
	if len(b) < HeaderSize {
		return Header{}, errors.New("srp: short header")
	}
	return Header{u16(b, 0), u16(b, 2), u16(b, 4), u16(b, 6), u16(b, 8), u16(b, 10)}, nil
}

// Bytes writes the header.
func (h Header) Bytes() []byte {
	out := make([]byte, 0, HeaderSize)
	for _, v := range []uint16{h.Checksum, h.Signature, h.DataSize, h.Flags, h.Seg, h.Ack} {
		out = binary.LittleEndian.AppendUint16(out, v)
	}
	return out
}

// Bytes writes the window.
func (w Window) Bytes() []byte {
	out := make([]byte, 0, WindowSize)
	for _, v := range []uint16{w.Tail, w.SenderSig, w.ChecksumInit, w.BufSize} {
		out = binary.LittleEndian.AppendUint16(out, v)
	}
	return out
}

// Parse reads a segment: data of exactly a window's size is a window, other data a GS message.
func Parse(b []byte) (*Segment, error) {
	h, err := ParseHeader(b)
	if err != nil {
		return nil, err
	}
	s := &Segment{Header: h}
	if len(b) > HeaderSize {
		data := b[HeaderSize:]
		if int(h.DataSize) < len(data) {
			data = data[:h.DataSize]
		}
		if len(data) == WindowSize {
			s.Window = &Window{u16(data, 0), u16(data, 2), u16(data, 4), u16(data, 6)}
		} else {
			msg, err := gsm.Decode(data, nil)
			if err != nil {
				return nil, err
			}
			s.Msg = msg
		}
	}
	return s, nil
}

// FlagNames lists the flags for logs.
func FlagNames(flags uint16) string {
	var names []string
	for _, f := range []struct {
		bit  uint16
		name string
	}{{FlagFIN, "FIN"}, {FlagSYN, "SYN"}, {FlagACK, "ACK"}, {FlagURG, "URG"}} {
		if flags&f.bit != 0 {
			names = append(names, f.name)
		}
	}
	if len(names) == 0 {
		return "MSG"
	}
	return strings.Join(names, "+")
}

// Conn is the server's state of an SRP connection.
type Conn struct {
	ChecksumInit uint16
	SenderSig    uint16
	SegmentID    uint16
	LastSegment  uint16
}

// Respond builds a segment to the client. With req nil the segment is sent on the server's initiative
// and acknowledges the last segment received; msg is the GS message to carry, if any.
func (c *Conn) Respond(req *Segment, msg []byte) []byte {
	windowReq := req != nil && req.Window != nil
	// a SYN's window sets the connection's checksum seed and signature
	if windowReq {
		c.ChecksumInit = req.Window.ChecksumInit
		c.SenderSig = req.Window.SenderSig
	}
	if req != nil {
		c.LastSegment = req.Header.Seg
	}
	h := Header{Checksum: c.ChecksumInit, Signature: c.SenderSig, DataSize: WindowSize, Flags: FlagID | FlagACK,
		Seg: c.SegmentID, Ack: c.LastSegment}
	if msg != nil {
		h.DataSize = uint16(len(msg))
	}
	if req != nil && req.Header.Has(FlagSYN) {
		h.Flags |= FlagSYN
	}
	c.SegmentID++
	out := h.Bytes()
	switch {
	case msg != nil:
		out = append(out, msg...)
	case windowReq:
		out = append(out, Window{Tail: 10, SenderSig: 2, ChecksumInit: 0, BufSize: 0x218}.Bytes()...)
	}
	binary.LittleEndian.PutUint16(out, Checksum(out))
	return out
}

// Checksum is the game's segment checksum (0x0047afe0), computed with the seed in the checksum field:
// a 32-bit sum of the u16 words (an odd first byte added alone, sign-extended like the game's char),
// folded to 16 bits and inverted.
func Checksum(data []byte) uint16 {
	var sum uint32
	pos := 0
	if len(data)%2 == 1 {
		sum += uint32(int32(int8(data[0])))
		pos = 1
	}
	for ; pos+1 < len(data); pos += 2 {
		sum += uint32(binary.LittleEndian.Uint16(data[pos:]))
	}
	folded := sum&0xFFFF + sum>>16
	folded += folded >> 16
	return ^uint16(folded)
}
