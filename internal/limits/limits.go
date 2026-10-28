// Package limits counts a service's open connections, in total and per address.
package limits

import "sync"

// Defaults, as in the reference implementation.
const (
	DefaultMaxConnections = 512
	DefaultMaxPerIP       = 16
	DefaultMaxNATClients  = 4096
	// DefaultSocketTimeout is in seconds; longer than the game's 105 s keepalive window.
	DefaultSocketTimeout = 180.0
)

// Limits counts open connections.
type Limits struct {
	MaxTotal int
	MaxPerIP int

	mu    sync.Mutex
	total int
	perIP map[string]int
}

// New returns limits with the given caps.
func New(maxTotal, maxPerIP int) *Limits {
	return &Limits{MaxTotal: maxTotal, MaxPerIP: maxPerIP, perIP: map[string]int{}}
}

// Acquire takes a slot for a connection from the address, if there is one.
func (l *Limits) Acquire(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.total >= l.MaxTotal || l.perIP[ip] >= l.MaxPerIP {
		return false
	}
	l.total++
	l.perIP[ip]++
	return true
}

// Release frees the slot of a closed connection.
func (l *Limits) Release(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.perIP[ip] == 0 {
		return
	}
	l.total--
	l.perIP[ip]--
	if l.perIP[ip] == 0 {
		delete(l.perIP, ip)
	}
}

// Counts returns the open connections in total and per address.
func (l *Limits) Counts() (int, map[string]int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	per := make(map[string]int, len(l.perIP))
	for k, v := range l.perIP {
		per[k] = v
	}
	return l.total, per
}
