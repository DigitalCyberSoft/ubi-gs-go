// Package h5 reads and writes the Heroes V structures carried in lobby data: the room info (`CRoomInfo`)
// and player info (`PlayerInfo`) the game serializes with its `CStructureSaver`.
package h5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
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

// field is one field of a structure as it came.
type field struct {
	id    byte
	known bool   // read into the structure, and written from it
	data  []byte // the data of a field kept as it came
}

// codec reads and writes one field of a structure.
type codec[T any] struct {
	id       byte
	name     string
	size     int  // -1: any
	required bool // the lobby changes it, so it must be there and read
	read     func(v *T, b []byte) error
	write    func(v *T) []byte
}

func codecFor[T any](codecs []codec[T], id byte) *codec[T] {
	for i := range codecs {
		if codecs[i].id == id {
			return &codecs[i]
		}
	}
	return nil
}

// readFields reads a structure's fields into v by id and returns their layout, which writeFields keeps.
// The expansions don't lay out the room info like 1.60 (Hammers of Fate's differs after field 33, Tribes
// of the East's after field 11), so a field the codecs don't know, or not in the form they read, is kept
// as it came and written back unchanged. Only the required fields must be there and read.
func readFields[T any](buf []byte, v *T, codecs []codec[T], what string) ([]field, error) {
	var layout []field
	var state [256]byte // 1: seen, 2: read
	for len(buf) > 0 {
		s, n, err := readStream(buf)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", what, err)
		}
		buf = buf[n:]
		c := codecFor(codecs, s.ID)
		if c == nil {
			layout = append(layout, field{id: s.ID, data: clone(s.Data)})
			continue
		}
		if state[s.ID] != 0 {
			// the lobby must change every copy the game could read
			return nil, invalid("%s: field %s (%d) repeated", what, c.name, c.id)
		}
		state[s.ID] = 1
		if c.size >= 0 && len(s.Data) != c.size {
			err = invalid("missing/invalid field - %s: %s (%d)", what, c.name, c.id)
		} else {
			err = c.read(v, s.Data)
		}
		if err != nil {
			if c.required {
				return nil, err
			}
			layout = append(layout, field{id: s.ID, data: clone(s.Data)})
			continue
		}
		state[s.ID] = 2
		layout = append(layout, field{id: s.ID, known: true})
	}
	for _, c := range codecs {
		if c.required && state[c.id] != 2 {
			return nil, invalid("missing/invalid field - %s: %s (%d)", what, c.name, c.id)
		}
	}
	return layout, nil
}

// writeFields writes a structure's fields in its layout, or, for a structure made here, every codec's
// field in their order (1.60's).
func writeFields[T any](v *T, layout []field, codecs []codec[T]) []byte {
	var out []byte
	if layout == nil {
		for _, c := range codecs {
			out = appendStream(out, c.id, c.write(v))
		}
		return out
	}
	for _, f := range layout {
		data := f.data
		if f.known {
			data = codecFor(codecs, f.id).write(v)
		}
		out = appendStream(out, f.id, data)
	}
	return out
}

// differences describes how a layout differs from the codecs': the fields kept as they came (16 at most
// listed) and the codecs' fields it doesn't have.
func differences[T any](layout []field, codecs []codec[T]) string {
	if layout == nil {
		return ""
	}
	var have [256]bool
	var kept, missing []string
	more := 0
	for _, f := range layout {
		have[f.id] = true
		switch {
		case f.known:
		case len(kept) < 16:
			kept = append(kept, fmt.Sprintf("%d (size %d)", f.id, len(f.data)))
		default:
			more++
		}
	}
	if more > 0 {
		kept = append(kept, fmt.Sprintf("%d more", more))
	}
	for _, c := range codecs {
		if !have[c.id] {
			missing = append(missing, strconv.Itoa(int(c.id)))
		}
	}
	var parts []string
	if len(kept) > 0 {
		parts = append(parts, "kept as sent: "+strings.Join(kept, ", "))
	}
	if len(missing) > 0 {
		parts = append(parts, "missing: "+strings.Join(missing, ", "))
	}
	return strings.Join(parts, "; ")
}

func must[T any](c codec[T]) codec[T] {
	c.required = true
	return c
}

func u32Field[T any](id byte, name string, at func(*T) *uint32) codec[T] {
	return codec[T]{id: id, name: name, size: 4,
		read:  func(v *T, b []byte) error { *at(v) = u32(b); return nil },
		write: func(v *T) []byte { return le32(*at(v)) }}
}

func boolField[T any](id byte, name string, at func(*T) *bool) codec[T] {
	return codec[T]{id: id, name: name, size: 1,
		read:  func(v *T, b []byte) error { *at(v) = flag(b); return nil },
		write: func(v *T) []byte { return boolByte(*at(v)) }}
}

func bytesField[T any](id byte, name string, at func(*T) *[]byte) codec[T] {
	return codec[T]{id: id, name: name, size: -1,
		read:  func(v *T, b []byte) error { *at(v) = clone(b); return nil },
		write: func(v *T) []byte { return *at(v) }}
}

// nestedField is a string nested in an id 2 field.
func nestedField[T any](id byte, name string, at func(*T) *[]byte) codec[T] {
	return codec[T]{id: id, name: name, size: -1,
		read:  func(v *T, b []byte) (err error) { *at(v), err = readNestedString(b); return },
		write: func(v *T) []byte { return appendStream(nil, 2, *at(v)) }}
}

func u32(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }

func le32(v uint32) []byte { return binary.LittleEndian.AppendUint32(nil, v) }

func flag(b []byte) bool { return len(b) > 0 && b[0] != 0 }

func boolByte(v bool) []byte {
	if v {
		return []byte{1}
	}
	return []byte{0}
}

func clone(b []byte) []byte { return append([]byte(nil), b...) }
