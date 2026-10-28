// Package netsrv runs a TCP service: one goroutine per connection, connection limits, socket timeouts,
// an ordered send queue per connection, and a clean shutdown.
package netsrv

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"runtime/debug"
	"sync"
	"time"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/limits"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/logx"
)

// SendQueue is how many messages may wait for a slow client before it is dropped.
const SendQueue = 1024

// Conn is a client connection.
type Conn struct {
	net.Conn
	// IP is the client's address, without the port.
	IP string
	// Timeout is how long a read or write may wait.
	Timeout time.Duration

	log    *logx.Logger
	out    chan []byte
	done   chan struct{}
	once   sync.Once
	writer sync.WaitGroup
}

// NewConn wraps an accepted connection and starts its writer.
func NewConn(c net.Conn, timeout time.Duration, log *logx.Logger) *Conn {
	conn := &Conn{
		Conn:    c,
		IP:      HostIP(c.RemoteAddr()),
		Timeout: timeout,
		log:     log,
		out:     make(chan []byte, SendQueue),
		done:    make(chan struct{}),
	}
	conn.writer.Add(1)
	go conn.write()
	return conn
}

// HostIP returns the IP of a TCP or UDP address as text (IPv4-mapped addresses as IPv4).
func HostIP(a net.Addr) string {
	switch v := a.(type) {
	case *net.TCPAddr:
		return addrString(v.IP)
	case *net.UDPAddr:
		return addrString(v.IP)
	}
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	return host
}

func addrString(ip net.IP) string {
	if a, ok := netip.AddrFromSlice(ip); ok {
		return a.Unmap().String()
	}
	return ip.String()
}

// LocalIP returns the server address the client reached.
func (c *Conn) LocalIP() string { return HostIP(c.LocalAddr()) }

func (c *Conn) write() {
	defer c.writer.Done()
	for {
		select {
		case b := <-c.out:
			if c.Timeout > 0 {
				c.Conn.SetWriteDeadline(time.Now().Add(c.Timeout))
			}
			if _, err := c.Conn.Write(b); err != nil {
				c.Close()
				return
			}
		case <-c.done:
			// flush what was queued before the close, best effort
			for {
				select {
				case b := <-c.out:
					c.Conn.SetWriteDeadline(time.Now().Add(time.Second))
					if _, err := c.Conn.Write(b); err != nil {
						return
					}
				default:
					return
				}
			}
		}
	}
}

// Send queues data for the client, in order. A client too slow to take its messages is dropped.
func (c *Conn) Send(b []byte) bool {
	select {
	case <-c.done:
		return false
	default:
	}
	select {
	case c.out <- b:
		return true
	default:
		c.log.Warnf("closing %s: it doesn't take its messages", c.RemoteAddr())
		c.Close()
		return false
	}
}

// Close closes the connection; queued messages are still flushed briefly.
func (c *Conn) Close() {
	c.once.Do(func() {
		close(c.done)
		// wake up a blocked read now; the writer gets a moment to flush
		c.Conn.SetReadDeadline(time.Now())
		go func() {
			// let the writer flush, then close the socket
			done := make(chan struct{})
			go func() { c.writer.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
			}
			c.Conn.Close()
		}()
	})
}

// Closed reports whether Close was called.
func (c *Conn) Closed() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

// Done is closed when the connection is closed.
func (c *Conn) Done() <-chan struct{} { return c.done }

// ExtendRead sets the read deadline one timeout from now.
func (c *Conn) ExtendRead() {
	if c.Timeout > 0 {
		c.Conn.SetReadDeadline(time.Now().Add(c.Timeout))
	}
}

// IsTimeout reports whether err is a deadline expiry.
func IsTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// Server is a running TCP service.
type Server struct {
	Name    string
	Log     *logx.Logger
	Limits  *limits.Limits
	Timeout time.Duration
	// Handle serves one connection until it returns; the connection is then closed.
	Handle func(*Conn)

	mu    sync.Mutex
	conns map[*Conn]struct{}
	wg    sync.WaitGroup
}

// Serve accepts connections until ctx is done or the listener fails.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	s.mu.Lock()
	s.conns = map[*Conn]struct{}{}
	s.mu.Unlock()
	stop := context.AfterFunc(ctx, func() { ln.Close() })
	defer stop()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				s.closeAll()
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				s.closeAll()
				return nil
			}
			s.Log.Warnf("accept: %v", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		ip := HostIP(c.RemoteAddr())
		if s.Limits != nil && !s.Limits.Acquire(ip) {
			s.Log.Warnf("refused %s: connection limit reached", c.RemoteAddr())
			c.Close()
			continue
		}
		conn := NewConn(c, s.Timeout, s.Log)
		s.mu.Lock()
		s.conns[conn] = struct{}{}
		s.mu.Unlock()
		s.wg.Add(1)
		go s.serve(conn, ip)
	}
}

func (s *Server) serve(conn *Conn, ip string) {
	defer s.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			// a bug must cost one connection, not the server
			s.Log.Errorf("closed %s after an internal error: %v\n%s", conn.RemoteAddr(), r, debug.Stack())
		}
		conn.Close()
		s.mu.Lock()
		delete(s.conns, conn)
		s.mu.Unlock()
		if s.Limits != nil {
			s.Limits.Release(ip)
		}
	}()
	s.Log.Infof("connection from %s", conn.RemoteAddr())
	s.Handle(conn)
}

func (s *Server) closeAll() {
	s.mu.Lock()
	for c := range s.conns {
		c.Close()
	}
	s.mu.Unlock()
}

// Wait waits for the connections to finish, at most d.
func (s *Server) Wait(d time.Duration) {
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
	}
}
