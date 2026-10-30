// Package challenge is the optional login challenge for HommaRe clients, which never send a player's
// real password: they register a token derived from it, then answer a single-use nonce from
// servers.ini with an HMAC. The original game keeps sending plain passwords, which work as before.
//
// Password formats in the router's LOGIN:
//   - RegisterPrefix + token: log in with the token as the password and store the verifier
//     V = HMAC-SHA256(token, VerifierLabel). A new name becomes a token account; a taken name logs in
//     only if it is a token account registered with this token, and is refused as a wrong password
//     otherwise;
//   - ChallengePrefix + base64url(HMAC-SHA256(V, nonce)[:MACLen]): valid once, for a nonce issued to the
//     same address that hasn't expired;
//   - anything else: a plain password.
package challenge

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"sync"
	"time"
)

// Wire constants; the markers and the MAC length follow the game's password field limits.
const (
	RegisterPrefix  = "~r:"
	ChallengePrefix = "~1:"
	// MACLen is how many bytes of the HMAC the response carries (16 base64url characters, 19 with
	// the prefix, which the game's LOGIN carries at full length: 0x0042a380).
	MACLen = 12
	// VerifierLabel is the HMAC message of the verifier.
	VerifierLabel = "ubi-gs verifier v1"
	// NonceTTL is how long an issued nonce stays valid.
	NonceTTL = 5 * time.Minute
	// MaxPerIP is how many unused nonces an address keeps; older ones are dropped.
	MaxPerIP = 8
	// MaxNonces bounds the table.
	MaxNonces = 65536
)

// Verifier is the value stored for a token account.
func Verifier(token string) []byte {
	m := hmac.New(sha256.New, []byte(token))
	m.Write([]byte(VerifierLabel))
	return m.Sum(nil)
}

// Response is the password a client sends for a nonce (the nonce's hex text as given in servers.ini).
func Response(verifier []byte, nonce string) string {
	m := hmac.New(sha256.New, verifier)
	m.Write([]byte(nonce))
	return ChallengePrefix + base64.RawURLEncoding.EncodeToString(m.Sum(nil)[:MACLen])
}

// Nonces are the issued nonces, per client address.
type Nonces struct {
	mu    sync.Mutex
	byIP  map[string][]nonce
	count int
	now   func() time.Time
}

type nonce struct {
	value   string
	expires time.Time
}

// NewNonces returns an empty table.
func NewNonces() *Nonces { return &Nonces{byIP: map[string][]nonce{}, now: time.Now} }

// SetClock replaces the clock, for tests.
func (n *Nonces) SetClock(now func() time.Time) { n.now = now }

// Issue returns a new nonce for the address.
func (n *Nonces) Issue(ip string) string {
	b := make([]byte, 16)
	rand.Read(b)
	v := hex.EncodeToString(b)
	n.mu.Lock()
	defer n.mu.Unlock()
	now := n.now()
	if n.count >= MaxNonces {
		n.sweep(now)
		if n.count >= MaxNonces {
			// still full: forget everything rather than grow
			n.byIP, n.count = map[string][]nonce{}, 0
		}
	}
	list := n.live(ip, now)
	if len(list) >= MaxPerIP {
		list = list[1:]
		n.count--
	}
	n.byIP[ip] = append(list, nonce{v, now.Add(NonceTTL)})
	n.count++
	return v
}

// live returns the address's unexpired nonces, dropping the rest. n.mu is held.
func (n *Nonces) live(ip string, now time.Time) []nonce {
	list := n.byIP[ip]
	kept := list[:0]
	for _, x := range list {
		if now.Before(x.expires) {
			kept = append(kept, x)
		}
	}
	n.count -= len(list) - len(kept)
	if len(kept) == 0 {
		delete(n.byIP, ip)
		return nil
	}
	n.byIP[ip] = kept
	return kept
}

func (n *Nonces) sweep(now time.Time) {
	for ip := range n.byIP {
		n.live(ip, now)
	}
}

// Redeem finds an unexpired nonce of the address for which match is true and uses it up. Without a
// match every outstanding nonce of the address is used up, so a response can't be tried twice.
func (n *Nonces) Redeem(ip string, match func(nonce string) bool) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	list := n.live(ip, n.now())
	for i, x := range list {
		if match(x.value) {
			n.byIP[ip] = append(list[:i], list[i+1:]...)
			n.count--
			if len(n.byIP[ip]) == 0 {
				delete(n.byIP, ip)
			}
			return true
		}
	}
	n.count -= len(list)
	delete(n.byIP, ip)
	return false
}

// Outstanding returns how many unused nonces the address has.
func (n *Nonces) Outstanding(ip string) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.live(ip, n.now()))
}

// Check reports whether a password is the response for the verifier and nonce, in constant time.
func Check(verifier []byte, nonce, password string) bool {
	return hmac.Equal([]byte(Response(verifier, nonce)), []byte(password))
}

// Kind tells a password's format.
func Kind(password string) string {
	switch {
	case strings.HasPrefix(password, RegisterPrefix):
		return "register"
	case strings.HasPrefix(password, ChallengePrefix):
		return "challenge"
	}
	return "plain"
}
