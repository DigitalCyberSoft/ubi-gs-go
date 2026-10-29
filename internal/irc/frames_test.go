package irc_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/irc"
)

func frame(t *testing.T, payload string) []byte {
	f, err := irc.Frame([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestLineAcrossFrames(t *testing.T) {
	s := start(t, 30*time.Second, nil)
	c := s.player(t, "", "", false)
	// one line in three frames, its CRLF split between the last two
	for _, part := range []string{"NICK :al", "ice\r", "\nUSER HEROES_657d2c2ebadc6a1d +i 0 :alice\r\n"} {
		c.Conn.Write(frame(t, part))
		time.Sleep(50 * time.Millisecond)
	}
	if !has(c.Read(300*time.Millisecond), func(l string) bool { return strings.Contains(l, " 001 alice ") }) {
		t.Fatal("a line split across frames was lost")
	}
}

// A long unfinished line followed by a stream of tiny frames must not rescan the line for each frame:
// that took about 5 ms of CPU per 1-byte frame with 60 KB pending, so these 2000 frames kept the
// connection busy for about 10 s.
func TestTinyFramesAfterLongLine(t *testing.T) {
	s := start(t, 30*time.Second, nil)
	c := s.player(t, "", "", false)
	burst := bytes.Clone(frame(t, strings.Repeat("A", 60000)))
	tiny := frame(t, "A")
	for range 2000 {
		burst = append(burst, tiny...)
	}
	burst = append(burst, frame(t, "\r\n")...)
	if _, err := c.Conn.Write(burst); err != nil {
		t.Fatal(err)
	}
	if !alive(c) {
		t.Fatal("no PONG right after the frames")
	}
}
