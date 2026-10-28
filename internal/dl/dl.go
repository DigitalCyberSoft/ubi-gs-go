// Package dl implements the Game Service data list (`clDataList`), the payload format of every GS message:
// strings ('s' ... NUL), binaries ('b', u32 big-endian length, bytes) and nested lists ('[' ... ']').
//
// Strings are kept as raw bytes (a Go string holding exactly what the game sent) and written back unchanged.
package dl

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Kind is the type of a Value.
type Kind uint8

const (
	// KindString is a NUL-terminated string ('s').
	KindString Kind = iota + 1
	// KindBinary is a length-prefixed byte string ('b').
	KindBinary
	// KindList is a nested list ('[' ... ']').
	KindList
)

const (
	tagString = 's'
	tagBinary = 'b'
	tagLong   = 'L'
	tagOpen   = '['
	tagClose  = ']'
)

// MaxDepth bounds list nesting when decoding untrusted input.
const MaxDepth = 32

// Value is one element of a data list.
type Value struct {
	kind Kind
	str  string
	bin  []byte
	list List
}

// List is a data list.
type List []Value

// S returns a string value.
func S(s string) Value { return Value{kind: KindString, str: s} }

// B returns a binary value.
func B(b []byte) Value { return Value{kind: KindBinary, bin: b} }

// L returns a list value.
func L(items ...Value) Value {
	if items == nil {
		items = List{}
	}
	return Value{kind: KindList, list: items}
}

// Strs returns a list value of strings.
func Strs(items ...string) Value {
	l := make(List, len(items))
	for i, s := range items {
		l[i] = S(s)
	}
	return L(l...)
}

// Kind reports the value's type.
func (v Value) Kind() Kind { return v.kind }

// IsString reports whether the value is a string.
func (v Value) IsString() bool { return v.kind == KindString }

// IsBinary reports whether the value is a binary.
func (v Value) IsBinary() bool { return v.kind == KindBinary }

// IsList reports whether the value is a list.
func (v Value) IsList() bool { return v.kind == KindList }

// Str returns the string, or false if the value isn't one.
func (v Value) Str() (string, bool) { return v.str, v.kind == KindString }

// Bin returns the binary, or false if the value isn't one.
func (v Value) Bin() ([]byte, bool) { return v.bin, v.kind == KindBinary }

// List returns the list, or false if the value isn't one.
func (v Value) List() (List, bool) { return v.list, v.kind == KindList }

// Equal reports whether two values are the same.
func (v Value) Equal(o Value) bool {
	if v.kind != o.kind {
		return false
	}
	switch v.kind {
	case KindString:
		return v.str == o.str
	case KindBinary:
		return string(v.bin) == string(o.bin)
	case KindList:
		return v.list.Equal(o.list)
	}
	return true
}

// Equal reports whether two lists are the same.
func (l List) Equal(o List) bool {
	if len(l) != len(o) {
		return false
	}
	for i := range l {
		if !l[i].Equal(o[i]) {
			return false
		}
	}
	return true
}

// At returns the i-th value, or false if there's none.
func (l List) At(i int) (Value, bool) {
	if i < 0 || i >= len(l) {
		return Value{}, false
	}
	return l[i], true
}

// Str returns the i-th value as a string.
func (l List) Str(i int) (string, bool) {
	v, ok := l.At(i)
	if !ok {
		return "", false
	}
	return v.Str()
}

// Bin returns the i-th value as a binary.
func (l List) Bin(i int) ([]byte, bool) {
	v, ok := l.At(i)
	if !ok {
		return nil, false
	}
	return v.Bin()
}

// List returns the i-th value as a list.
func (l List) List(i int) (List, bool) {
	v, ok := l.At(i)
	if !ok {
		return nil, false
	}
	return v.List()
}

// Int returns the i-th value as an integer, parsed the way Python's int() parses a string.
func (l List) Int(i int) (int, bool) {
	s, ok := l.Str(i)
	if !ok {
		return 0, false
	}
	return ParseInt(s)
}

// ParseInt parses a decimal integer like Python's int(str): surrounding whitespace, a sign, and
// underscores between digits are accepted.
func ParseInt(s string) (int, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	digits := s
	if digits[0] == '+' || digits[0] == '-' {
		digits = digits[1:]
	}
	if digits == "" || digits[0] == '_' || digits[len(digits)-1] == '_' || strings.Contains(digits, "__") {
		return 0, false
	}
	clean := strings.ReplaceAll(s, "_", "")
	n, err := strconv.ParseInt(clean, 10, 64)
	if err != nil || n != int64(int(n)) {
		return 0, false
	}
	return int(n), true
}

// Encode writes the list without its outer brackets, as messages carry it.
func (l List) Encode() []byte {
	var out []byte
	for _, v := range l {
		out = v.appendTo(out)
	}
	return out
}

// EncodeValue writes a value, brackets included for a list.
func EncodeValue(v Value) []byte { return v.appendTo(nil) }

func (v Value) appendTo(out []byte) []byte {
	switch v.kind {
	case KindString:
		out = append(out, tagString)
		out = append(out, v.str...)
		out = append(out, 0)
	case KindBinary:
		out = append(out, tagBinary)
		out = binary.BigEndian.AppendUint32(out, uint32(len(v.bin)))
		out = append(out, v.bin...)
	case KindList:
		out = append(out, tagOpen)
		for _, item := range v.list {
			out = item.appendTo(out)
		}
		out = append(out, tagClose)
	default:
		// the zero Value: an empty string, never produced by the decoder
		out = append(out, tagString, 0)
	}
	return out
}

// ErrMalformed is returned for a buffer that isn't a valid data list.
var ErrMalformed = errors.New("malformed data list")

func malformed(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrMalformed, fmt.Sprintf(format, args...))
}

// Decode reads a message payload: a list without its outer brackets.
//
// It follows the reference implementation on well-formed input: decoding stops at a closing bracket
// or when a single byte is left, and that byte is ignored. Truncated values are errors.
func Decode(buf []byte) (List, error) {
	d := decoder{buf: buf}
	if len(d.buf) == 0 {
		return nil, malformed("empty payload")
	}
	if d.buf[0] == tagClose {
		return List{}, nil
	}
	l, err := d.items(0)
	if err != nil {
		return nil, err
	}
	return l, nil
}

type decoder struct {
	buf []byte
}

func (d *decoder) items(depth int) (List, error) {
	l := List{}
	for len(d.buf) > 1 && d.buf[0] != tagClose {
		v, err := d.value(depth)
		if err != nil {
			return nil, err
		}
		l = append(l, v)
	}
	return l, nil
}

func (d *decoder) value(depth int) (Value, error) {
	switch d.buf[0] {
	case tagString:
		d.buf = d.buf[1:]
		if len(d.buf) == 0 {
			return Value{}, malformed("string without data")
		}
		// up to the NUL; an unterminated string ends one byte before the buffer does
		end := 0
		for end < len(d.buf)-1 && d.buf[end] != 0 {
			end++
		}
		s := string(d.buf[:end])
		d.buf = d.buf[end+1:]
		return S(s), nil
	case tagBinary:
		if len(d.buf) < 5 {
			return Value{}, malformed("binary without length")
		}
		size := binary.BigEndian.Uint32(d.buf[1:5])
		d.buf = d.buf[5:]
		if uint64(size) > uint64(len(d.buf)) {
			return Value{}, malformed("binary size exceeds the buffer by %d", uint64(size)-uint64(len(d.buf)))
		}
		b := make([]byte, size)
		copy(b, d.buf[:size])
		d.buf = d.buf[size:]
		return B(b), nil
	case tagOpen:
		if depth >= MaxDepth {
			return Value{}, malformed("lists nested deeper than %d", MaxDepth)
		}
		d.buf = d.buf[1:]
		if len(d.buf) == 0 {
			return Value{}, malformed("unterminated list")
		}
		if d.buf[0] == tagClose {
			d.buf = d.buf[1:]
			return L(), nil
		}
		items, err := d.items(depth + 1)
		if err != nil {
			return Value{}, err
		}
		if len(d.buf) == 0 {
			return Value{}, malformed("unterminated list")
		}
		if d.buf[0] == tagClose {
			d.buf = d.buf[1:]
		}
		return L(items...), nil
	case tagLong:
		return Value{}, malformed("long values are not supported")
	default:
		return Value{}, malformed("unknown type tag 0x%02x", d.buf[0])
	}
}

// String formats the list like the reference implementation's logs (Python list syntax).
func (l List) String() string {
	var b strings.Builder
	writeList(&b, l)
	return b.String()
}

// String formats the value in Python syntax.
func (v Value) String() string {
	var b strings.Builder
	writeValue(&b, v)
	return b.String()
}

func writeList(b *strings.Builder, l List) {
	b.WriteByte('[')
	for i, v := range l {
		if i > 0 {
			b.WriteString(", ")
		}
		writeValue(b, v)
	}
	b.WriteByte(']')
}

func writeValue(b *strings.Builder, v Value) {
	switch v.kind {
	case KindString:
		b.WriteString(quote(v.str))
	case KindBinary:
		b.WriteByte('b')
		b.WriteString(quote(string(v.bin)))
	case KindList:
		writeList(b, v.list)
	default:
		b.WriteString("''")
	}
}

// quote renders printable ASCII as is and everything else escaped, so logs stay one line and plain.
func quote(s string) string {
	const q = '\''
	var b strings.Builder
	b.WriteByte(q)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == q || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c == '\n':
			b.WriteString(`\n`)
		case c == '\r':
			b.WriteString(`\r`)
		case c == '\t':
			b.WriteString(`\t`)
		case c >= 0x20 && c < 0x7f:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, `\x%02x`, c)
		}
	}
	b.WriteByte(q)
	return b.String()
}
