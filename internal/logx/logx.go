// Package logx is a small leveled, timestamped logger shared by the services.
package logx

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// Level selects how much is logged.
type Level int

const (
	// Quiet logs warnings and errors only.
	Quiet Level = iota
	// Normal also logs connections, logins and lobby events.
	Normal
	// Verbose also logs every message with its (redacted) payload.
	Verbose
)

type sink struct {
	mu    sync.Mutex
	out   io.Writer
	level Level
	now   func() time.Time
}

// Logger writes lines "2006-01-02 15:04:05.000 service: message".
type Logger struct {
	sink   *sink
	prefix string
}

// New returns a logger writing to out.
func New(out io.Writer, level Level) *Logger {
	return &Logger{sink: &sink{out: out, level: level, now: time.Now}}
}

// Discard returns a logger that writes nothing.
func Discard() *Logger { return New(io.Discard, Quiet) }

// With returns a logger for a service.
func (l *Logger) With(prefix string) *Logger {
	return &Logger{sink: l.sink, prefix: prefix}
}

// Level returns the logger's level.
func (l *Logger) Level() Level { return l.sink.level }

// Enabled reports whether messages of the level are written.
func (l *Logger) Enabled(level Level) bool { return level <= l.sink.level }

func (l *Logger) write(level Level, tag, format string, args []any) {
	if !l.Enabled(level) {
		return
	}
	msg := fmt.Sprintf(format, args...)
	// one entry per line, whatever the message holds
	msg = strings.ReplaceAll(strings.TrimRight(msg, "\n"), "\n", "\n    ")
	var b strings.Builder
	b.WriteString(l.sink.now().Format("2006-01-02 15:04:05.000"))
	b.WriteByte(' ')
	if tag != "" {
		b.WriteString(tag)
		b.WriteByte(' ')
	}
	if l.prefix != "" {
		b.WriteString(l.prefix)
		b.WriteString(": ")
	}
	b.WriteString(msg)
	b.WriteByte('\n')
	l.sink.mu.Lock()
	defer l.sink.mu.Unlock()
	io.WriteString(l.sink.out, b.String())
}

// Errorf logs an error.
func (l *Logger) Errorf(format string, args ...any) { l.write(Quiet, "ERROR", format, args) }

// Warnf logs a warning.
func (l *Logger) Warnf(format string, args ...any) { l.write(Quiet, "WARN", format, args) }

// Infof logs an event.
func (l *Logger) Infof(format string, args ...any) { l.write(Normal, "", format, args) }

// Debugf logs protocol detail.
func (l *Logger) Debugf(format string, args ...any) { l.write(Verbose, "", format, args) }
