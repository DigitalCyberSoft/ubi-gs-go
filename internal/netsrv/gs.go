package netsrv

import (
	"errors"
	"io"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/gsm"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/logx"
)

// GSClient is a connection speaking GS messages.
type GSClient struct {
	*Conn
	// Session holds the connection's key exchange state.
	Session gsm.Session
	Log     *logx.Logger
}

// SendMsg encodes and queues a message.
func (c *GSClient) SendMsg(m *gsm.Message) bool {
	b, err := m.Encode()
	if err != nil {
		c.Log.Errorf("not sent to %s: %v", c.RemoteAddr(), err)
		return false
	}
	m.Header.Size = len(b)
	c.Log.Debugf("-> %s %s", c.RemoteAddr(), m)
	return c.Send(b)
}

// ServeGS reads messages until the connection ends and passes each to handle. A message that can't be
// parsed, or an error from handle, closes the connection.
func (c *GSClient) ServeGS(handle func(*gsm.Message) error) {
	for !c.Closed() {
		c.ExtendRead()
		msg, _, err := gsm.Read(c.Conn, c.Session.Blowfish)
		if err != nil {
			switch {
			case c.Closed():
			case errors.Is(err, io.EOF):
				c.Log.Infof("no more data from %s", c.RemoteAddr())
			case IsTimeout(err):
				c.Log.Infof("closed %s: silent for %.0fs", c.RemoteAddr(), c.Timeout.Seconds())
			case errors.Is(err, gsm.ErrBadMessage):
				c.Log.Warnf("closed %s: %v", c.RemoteAddr(), err)
			default:
				c.Log.Infof("closed %s: %v", c.RemoteAddr(), err)
			}
			return
		}
		c.Log.Debugf("<- %s %s", c.RemoteAddr(), msg)
		if err := handle(msg); err != nil {
			c.Log.Warnf("closed %s: %s: %v", c.RemoteAddr(), msg.Header.Type, err)
			return
		}
	}
}
