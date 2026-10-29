package server

import (
	"net"
	"testing"
	"time"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/limits"
)

func TestLimitListener(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := limitListener{Listener: ln, limits: limits.New(10, 2)}
	t.Cleanup(func() { l.Close() })
	accepted := make(chan net.Conn, 10)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	dial := func() net.Conn {
		c, err := net.Dial("tcp4", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	next := func() net.Conn {
		select {
		case c := <-accepted:
			return c
		case <-time.After(time.Second):
			return nil
		}
	}
	dial()
	dial()
	first, second := next(), next()
	if first == nil || second == nil {
		t.Fatal("the first two connections weren't accepted")
	}
	// a third from the same address is closed as it arrives
	extra := dial()
	extra.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := extra.Read(make([]byte, 1)); err == nil {
		t.Fatal("read from a connection over the cap")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("a connection over the cap was kept open")
	}
	// closing one makes room again
	first.Close()
	dial()
	if next() == nil {
		t.Fatal("no room after a connection closed")
	}
	second.Close()
}
