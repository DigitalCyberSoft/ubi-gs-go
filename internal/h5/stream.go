// Package h5 reads and writes the Heroes V structures carried in lobby data: the room info (`CRoomInfo`)
// and player info (`PlayerInfo`) the game serializes with its `CStructureSaver`.
package h5

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Stream is one field of a serialized structure: an id byte, a size (7 bits in one byte, or 31 bits in
// four little-endian bytes when the low bit of the first is set) and the data.
type Stream struct {
	ID   byte
	Data []byte
}

// ErrInvalid is returned for a buffer that doesn't hold the expected structure.
var ErrInvalid = errors.New("invalid structure")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// readStream reads a stream at the start of buf and returns it with the number of bytes it took.
func readStream(buf []byte) (Stream, int, error) {
	if len(buf) < 2 {
		return Stream{}, 0, invalid("stream header truncated")
	}
	s := Stream{ID: buf[0]}
	var size, head int
	if buf[1]&1 == 1 {
		if len(buf) < 5 {
			return Stream{}, 0, invalid("stream size truncated")
		}
		size = int(binary.LittleEndian.Uint32(buf[1:5]) >> 1)
		head = 5
	} else {
		size = int(buf[1] >> 1)
		head = 2
	}
	if len(buf)-head < size {
		return Stream{}, 0, invalid("stream's declared size exceeds the buffer size")
	}
	s.Data = buf[head : head+size]
	return s, head + size, nil
}

// appendStream writes a stream, with a 4-byte size when the data is over 127 bytes.
func appendStream(out []byte, id byte, data []byte) []byte {
	out = append(out, id)
	if len(data) > 127 {
		out = binary.LittleEndian.AppendUint32(out, uint32(len(data))<<1|1)
	} else {
		out = append(out, byte(len(data)<<1))
	}
	return append(out, data...)
}

// Stream types of the outer structure; names assumed.
const (
	streamStructure     = 0
	streamData          = 1
	streamRawData       = 2
	streamSerialization = 4
	streamLookupTable   = 5
)

// wrap packs serialized fields into the outer streams, in the game's order: serialization mode (4),
// data, and the empty structure, raw data and lookup table streams.
func wrap(data []byte) []byte {
	out := appendStream(nil, streamSerialization, binary.LittleEndian.AppendUint32(nil, 4))
	out = appendStream(out, streamData, data)
	out = appendStream(out, streamStructure, nil)
	out = appendStream(out, streamRawData, nil)
	return appendStream(out, streamLookupTable, nil)
}

// unwrap returns the data stream of a serialized structure.
func unwrap(buf []byte) ([]byte, error) {
	var data []byte
	found := false
	for len(buf) > 0 {
		s, n, err := readStream(buf)
		if err != nil {
			return nil, err
		}
		if s.ID > streamLookupTable {
			return nil, invalid("unknown stream type %d", s.ID)
		}
		if s.ID == streamData {
			data, found = s.Data, true
		}
		buf = buf[n:]
	}
	if !found {
		return nil, invalid("data stream missing")
	}
	return data, nil
}

// fields reads consecutive streams.
type fields struct {
	buf []byte
	err error
}

// next reads the next field, which must have the id (and the size, unless size < 0).
func (f *fields) next(id byte, size int, name string) []byte {
	if f.err != nil {
		return nil
	}
	s, n, err := readStream(f.buf)
	if err != nil {
		f.err = fmt.Errorf("%s (%d): %w", name, id, err)
		return nil
	}
	if s.ID != id || (size >= 0 && len(s.Data) != size) {
		f.err = invalid("missing/invalid field - %s (%d)", name, id)
		return nil
	}
	f.buf = f.buf[n:]
	return s.Data
}

func u32(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }

func le32(v uint32) []byte { return binary.LittleEndian.AppendUint32(nil, v) }

func clone(b []byte) []byte { return append([]byte(nil), b...) }
