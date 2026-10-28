package crypto

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
)

// Blowfish is the block cipher with the game's key schedule: keys of any length, cycled over the
// P-array (longer keys than the standard's 56 bytes are used whole, as the game's CD-key key needs).
type Blowfish struct {
	p [18]uint32
	s [4][256]uint32
}

// NewBlowfish expands a key. The key must not be empty.
func NewBlowfish(key []byte) (*Blowfish, error) {
	if len(key) == 0 {
		return nil, errors.New("blowfish: empty key")
	}
	bf := &Blowfish{p: origP, s: origS}
	j := 0
	for i := range bf.p {
		var data uint32
		for k := 0; k < 4; k++ {
			data = data<<8 | uint32(key[j])
			j++
			if j >= len(key) {
				j = 0
			}
		}
		bf.p[i] = origP[i] ^ data
	}
	var l, r uint32
	for i := 0; i < 18; i += 2 {
		l, r = bf.EncryptBlock(l, r)
		bf.p[i], bf.p[i+1] = l, r
	}
	for i := 0; i < 4; i++ {
		for j := 0; j < 256; j += 2 {
			l, r = bf.EncryptBlock(l, r)
			bf.s[i][j], bf.s[i][j+1] = l, r
		}
	}
	return bf, nil
}

// MustBlowfish is NewBlowfish for the game's built-in keys.
func MustBlowfish(key []byte) *Blowfish {
	bf, err := NewBlowfish(key)
	if err != nil {
		panic(err)
	}
	return bf
}

func (bf *Blowfish) f(x uint32) uint32 {
	return ((bf.s[0][x>>24] + bf.s[1][x>>16&0xff]) ^ bf.s[2][x>>8&0xff]) + bf.s[3][x&0xff]
}

// EncryptBlock encrypts one 64-bit block given as two words.
func (bf *Blowfish) EncryptBlock(l, r uint32) (uint32, uint32) {
	for i := 0; i < 16; i++ {
		l ^= bf.p[i]
		r ^= bf.f(l)
		l, r = r, l
	}
	l, r = r, l
	r ^= bf.p[16]
	l ^= bf.p[17]
	return l, r
}

// DecryptBlock decrypts one 64-bit block given as two words.
func (bf *Blowfish) DecryptBlock(l, r uint32) (uint32, uint32) {
	for i := 17; i > 1; i-- {
		l ^= bf.p[i]
		r ^= bf.f(l)
		l, r = r, l
	}
	l, r = r, l
	r ^= bf.p[1]
	l ^= bf.p[0]
	return l, r
}

// MaxBlowfishPayload is the largest plaintext the GS framing can carry (its length is a u16).
const MaxBlowfishPayload = 0xFFFF

// ErrBlowfishSize is returned for a ciphertext whose length doesn't fit the GS framing.
var ErrBlowfishSize = errors.New("blowfish: bad ciphertext length")

// Encrypt encrypts data the GS way: zero-padded to 8 bytes, little-endian words, then the plaintext
// length as a little-endian u16.
func (bf *Blowfish) Encrypt(src []byte) ([]byte, error) {
	if len(src) > MaxBlowfishPayload {
		return nil, errors.New("blowfish: payload too long")
	}
	padded := (len(src) + 7) &^ 7
	out := make([]byte, padded, padded+2)
	copy(out, src)
	for i := 0; i < padded; i += 8 {
		l, r := bf.EncryptBlock(binary.LittleEndian.Uint32(out[i:]), binary.LittleEndian.Uint32(out[i+4:]))
		binary.LittleEndian.PutUint32(out[i:], l)
		binary.LittleEndian.PutUint32(out[i+4:], r)
	}
	return binary.LittleEndian.AppendUint16(out, uint16(len(src))), nil
}

// Decrypt reverses Encrypt.
func (bf *Blowfish) Decrypt(src []byte) ([]byte, error) {
	if len(src) < 2 || (len(src)-2)%8 != 0 {
		return nil, ErrBlowfishSize
	}
	n := len(src) - 2
	size := int(binary.LittleEndian.Uint16(src[n:]))
	if size > n {
		return nil, ErrBlowfishSize
	}
	out := make([]byte, n)
	for i := 0; i < n; i += 8 {
		l, r := bf.DecryptBlock(binary.LittleEndian.Uint32(src[i:]), binary.LittleEndian.Uint32(src[i+4:]))
		binary.LittleEndian.PutUint32(out[i:], l)
		binary.LittleEndian.PutUint32(out[i+4:], r)
	}
	return out[:size], nil
}

// NewSessionKey returns a random Blowfish key for a GS connection.
func NewSessionKey() []byte {
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	return key
}
