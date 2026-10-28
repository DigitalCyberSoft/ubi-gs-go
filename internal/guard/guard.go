// Package guard puts abuse limits around logins: new accounts per address and in total, login attempts
// per address with a growing back-off after password misses, and a bound on concurrent password hashes
// (scrypt is deliberately expensive, so unbounded logins would be a CPU denial of service).
package guard

import (
	"errors"
	"strings"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/challenge"
	"runtime"
	"sync"
	"time"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/accounts"
)

// Refusal reasons from the game's login error table (0x00b03490).
var (
	// ErrTooManyAccounts refuses a login that would create an account over a limit
	// (GSLGE_ERRORSECURE_USERNAMEFORBIDDEN).
	ErrTooManyAccounts = &accounts.LoginError{Reason: 3, Name: "USERNAME_FORBIDDEN (account limit)"}
	// ErrSlowDown refuses a login during a back-off (GSLGE_ERRORSECURE_LOCKEDACCOUNT).
	ErrSlowDown = &accounts.LoginError{Reason: 0x200, Name: "LOCKED_ACCOUNT (too many logins, try later)"}
)

// Config are the limits; zero disables a limit.
type Config struct {
	// NewAccountsPerIPHour caps accounts created from one address per hour.
	NewAccountsPerIPHour int
	// MaxAccounts caps the accounts stored in total.
	MaxAccounts int64
	// LoginsPerIPMinute caps login attempts from one address per minute.
	LoginsPerIPMinute int
	// MaxBackoff is the longest wait after repeated password misses from an address.
	MaxBackoff time.Duration
	// HashWorkers is how many password hashes run at once; 0 means the CPU count.
	HashWorkers int
}

// Defaults are the default limits.
func Defaults() Config {
	return Config{NewAccountsPerIPHour: 5, MaxAccounts: 100000, LoginsPerIPMinute: 20, MaxBackoff: 5 * time.Minute}
}

// Guard applies the limits.
type Guard struct {
	Accounts *accounts.Store
	// Nonces are the login challenges issued with servers.ini; nil refuses challenge logins.
	Nonces *challenge.Nonces
	cfg    Config
	now    func() time.Time
	sem    chan struct{}

	mu     sync.Mutex
	ips    map[string]*ipState
	sweeps time.Time
}

type ipState struct {
	created  []time.Time // account creations in the last hour
	attempts []time.Time // logins in the last minute
	misses   int         // password misses since the last good login
	until    time.Time   // no logins before this
	seen     time.Time
}

// New returns a guard.
func New(store *accounts.Store, cfg Config) *Guard {
	workers := cfg.HashWorkers
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	return &Guard{Accounts: store, cfg: cfg, now: time.Now, sem: make(chan struct{}, workers), ips: map[string]*ipState{}}
}

// SetClock replaces the clock, for tests.
func (g *Guard) SetClock(now func() time.Time) { g.now = now }

func (g *Guard) hash(fn func()) {
	g.sem <- struct{}{}
	defer func() { <-g.sem }()
	fn()
}

func trim(times []time.Time, after time.Time) []time.Time {
	i := 0
	for i < len(times) && !times[i].After(after) {
		i++
	}
	return times[i:]
}

// state returns the address's state, with old entries dropped. g.mu is held.
func (g *Guard) state(ip string, now time.Time) *ipState {
	if now.Sub(g.sweeps) > 10*time.Minute {
		g.sweeps = now
		for k, st := range g.ips {
			if now.Sub(st.seen) > time.Hour && now.After(st.until) {
				delete(g.ips, k)
			}
		}
	}
	st := g.ips[ip]
	if st == nil {
		st = &ipState{}
		g.ips[ip] = st
	}
	st.seen = now
	st.created = trim(st.created, now.Add(-time.Hour))
	st.attempts = trim(st.attempts, now.Add(-time.Minute))
	return st
}

// Login logs in with the limits applied. The password may be plain, or a HommaRe registration or
// challenge response (package challenge).
func (g *Guard) Login(ip, name, password string) (accounts.Account, error) {
	switch challenge.Kind(password) {
	case "register":
		token := strings.TrimPrefix(password, challenge.RegisterPrefix)
		if token == "" {
			return accounts.Account{}, accounts.ErrPasswordMalformed
		}
		return g.login(ip, name, token, challenge.Verifier(token))
	case "challenge":
		return g.challenge(ip, name, password)
	}
	return g.login(ip, name, password, nil)
}

// challenge checks a response to a nonce issued to the address; the nonce is used up.
func (g *Guard) challenge(ip, name, password string) (accounts.Account, error) {
	now := g.now()
	g.mu.Lock()
	st := g.state(ip, now)
	if now.Before(st.until) || (g.cfg.LoginsPerIPMinute > 0 && len(st.attempts) >= g.cfg.LoginsPerIPMinute) {
		g.mu.Unlock()
		return accounts.Account{}, ErrSlowDown
	}
	st.attempts = append(st.attempts, now)
	g.mu.Unlock()
	family, err := g.Accounts.FamilyVerifiers(name)
	if err != nil {
		var le *accounts.LoginError
		if errors.As(err, &le) {
			return accounts.Account{}, le
		}
		return accounts.Account{}, accounts.ErrDatabaseFailed
	}
	var found *accounts.Account
	if g.Nonces != nil {
		// on a miss every outstanding nonce of the address is used up: no guessing across nonces
		g.Nonces.Redeem(ip, func(nonce string) bool {
			for _, t := range family {
				if challenge.Check(t.Verifier, nonce, password) {
					a := t.Account
					found = &a
					return true
				}
			}
			return false
		})
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	st = g.state(ip, g.now())
	if found == nil {
		g.miss(st)
		return accounts.Account{}, accounts.ErrInvalidPassword
	}
	st.misses = 0
	return *found, nil
}

// miss counts a password miss and sets the back-off. g.mu is held.
func (g *Guard) miss(st *ipState) {
	st.misses++
	backoff := time.Second << min(st.misses-1, 20)
	if g.cfg.MaxBackoff > 0 && backoff > g.cfg.MaxBackoff {
		backoff = g.cfg.MaxBackoff
	}
	if st.misses > 1 {
		st.until = g.now().Add(backoff)
	}
}

func (g *Guard) login(ip, name, password string, verifier []byte) (accounts.Account, error) {
	if g == nil {
		return accounts.Account{}, accounts.ErrDatabaseFailed
	}
	now := g.now()
	g.mu.Lock()
	st := g.state(ip, now)
	if now.Before(st.until) || (g.cfg.LoginsPerIPMinute > 0 && len(st.attempts) >= g.cfg.LoginsPerIPMinute) {
		g.mu.Unlock()
		return accounts.Account{}, ErrSlowDown
	}
	st.attempts = append(st.attempts, now)
	g.mu.Unlock()

	res, err := g.Accounts.LoginWith(name, password, accounts.LoginOptions{
		Hash:     g.hash,
		Verifier: verifier,
		AllowCreate: func(stored int64) error {
			if g.cfg.MaxAccounts > 0 && stored >= g.cfg.MaxAccounts {
				return ErrTooManyAccounts
			}
			g.mu.Lock()
			defer g.mu.Unlock()
			st := g.state(ip, g.now())
			if g.cfg.NewAccountsPerIPHour > 0 && len(st.created) >= g.cfg.NewAccountsPerIPHour {
				return ErrTooManyAccounts
			}
			st.created = append(st.created, g.now())
			return nil
		},
	})

	g.mu.Lock()
	defer g.mu.Unlock()
	st = g.state(ip, g.now())
	switch {
	case err != nil:
	case res.Taken:
		// the name's own password didn't match: a new player picking a taken name, or a guess
		g.miss(st)
	default:
		st.misses = 0
	}
	return res.Account, err
}
