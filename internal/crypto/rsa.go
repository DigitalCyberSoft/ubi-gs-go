package crypto

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
)

// The GS key exchange uses RSA-512 with public exponent 3 and PKCS#1 v1.5 padding. Go's crypto/rsa
// refuses keys that small, so the few operations needed are done here with math/big.

const (
	// RSABits is the size of the server's key exchange key.
	RSABits = 512
	// RSAExponent is the public exponent the game expects.
	RSAExponent = 3
	// rsaFieldLen is the size of the modulus and exponent fields in the game's key buffer.
	rsaFieldLen = 128
	// PublicKeyLen is the size of the game's serialized public key: bits (u32 LE), modulus, exponent.
	PublicKeyLen = 4 + 2*rsaFieldLen
)

// PublicKey is an RSA public key.
type PublicKey struct {
	Bits int
	N    *big.Int
	E    *big.Int
}

// PrivateKey is an RSA private key.
type PrivateKey struct {
	PublicKey
	D *big.Int
}

var bigOne = big.NewInt(1)

// GenerateKey creates a 512-bit key with e = 3, as the game's own key exchange expects.
func GenerateKey(random io.Reader) (*PrivateKey, error) {
	if random == nil {
		random = rand.Reader
	}
	e := big.NewInt(RSAExponent)
	for {
		p, err := rand.Prime(random, RSABits/2)
		if err != nil {
			return nil, err
		}
		q, err := rand.Prime(random, RSABits/2)
		if err != nil {
			return nil, err
		}
		if p.Cmp(q) == 0 {
			continue
		}
		n := new(big.Int).Mul(p, q)
		if n.BitLen() != RSABits {
			continue
		}
		phi := new(big.Int).Mul(new(big.Int).Sub(p, bigOne), new(big.Int).Sub(q, bigOne))
		d := new(big.Int).ModInverse(e, phi)
		if d == nil {
			// 3 divides p-1 or q-1
			continue
		}
		return &PrivateKey{PublicKey: PublicKey{Bits: RSABits, N: n, E: e}, D: d}, nil
	}
}

// Marshal writes the key in the game's layout: bits (u32 LE), modulus and exponent (128-byte big-endian each).
func (k *PublicKey) Marshal() []byte {
	out := make([]byte, PublicKeyLen)
	binary.LittleEndian.PutUint32(out, uint32(k.Bits))
	k.N.FillBytes(out[4 : 4+rsaFieldLen])
	k.E.FillBytes(out[4+rsaFieldLen:])
	return out
}

// ParsePublicKey reads a key in the game's layout.
func ParsePublicKey(buf []byte) (*PublicKey, error) {
	if len(buf) < PublicKeyLen {
		return nil, errors.New("rsa: public key buffer too small")
	}
	k := &PublicKey{
		Bits: int(binary.LittleEndian.Uint32(buf)),
		N:    new(big.Int).SetBytes(buf[4 : 4+rsaFieldLen]),
		E:    new(big.Int).SetBytes(buf[4+rsaFieldLen : PublicKeyLen]),
	}
	if k.N.Sign() == 0 || k.E.Sign() == 0 {
		return nil, errors.New("rsa: empty public key")
	}
	return k, nil
}

func (k *PublicKey) size() int { return (k.N.BitLen() + 7) / 8 }

// ErrDecryption is returned for a ciphertext that doesn't decrypt to a valid PKCS#1 v1.5 block.
var ErrDecryption = errors.New("rsa: decryption error")

// EncryptPKCS1v15 encrypts a short message with PKCS#1 v1.5 type 2 padding.
func EncryptPKCS1v15(random io.Reader, pub *PublicKey, msg []byte) ([]byte, error) {
	if random == nil {
		random = rand.Reader
	}
	k := pub.size()
	if k < 11 || len(msg) > k-11 {
		return nil, errors.New("rsa: message too long for the key")
	}
	block := make([]byte, k)
	block[1] = 2
	ps := block[2 : k-len(msg)-1]
	for i := range ps {
		for ps[i] == 0 {
			if _, err := io.ReadFull(random, ps[i:i+1]); err != nil {
				return nil, err
			}
		}
	}
	copy(block[k-len(msg):], msg)
	m := new(big.Int).SetBytes(block)
	c := new(big.Int).Exp(m, pub.E, pub.N)
	return c.FillBytes(make([]byte, k)), nil
}

// DecryptPKCS1v15 decrypts a PKCS#1 v1.5 type 2 block.
func DecryptPKCS1v15(priv *PrivateKey, ciphertext []byte) ([]byte, error) {
	k := priv.size()
	if len(ciphertext) > k {
		return nil, ErrDecryption
	}
	c := new(big.Int).SetBytes(ciphertext)
	if c.Cmp(priv.N) >= 0 {
		return nil, ErrDecryption
	}
	m := new(big.Int).Exp(c, priv.D, priv.N)
	block := m.FillBytes(make([]byte, k))
	if block[0] != 0 || block[1] != 2 {
		return nil, ErrDecryption
	}
	// the separator after at least 8 bytes of padding
	sep := -1
	for i := 2; i < len(block); i++ {
		if block[i] == 0 {
			sep = i
			break
		}
	}
	if sep < 10 {
		return nil, ErrDecryption
	}
	return block[sep+1:], nil
}
