// Package gsclient is a minimal game-side client of the GS protocols, for tests.
package gsclient

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/crypto"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/dl"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/gsm"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/irc"
)

// Dial connects from a local address (e.g. 127.0.0.2 to look like another machine; "" for any).
func Dial(from, to string) (net.Conn, error) {
	d := net.Dialer{Timeout: 3 * time.Second}
	if from != "" {
		d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(from)}
	}
	return d.Dial("tcp4", to)
}

// Client speaks GS messages.
type Client struct {
	Conn net.Conn
	// Receiver is the party requests are addressed to (R for the router, S for the lobby).
	Receiver gsm.Party
	BF       *crypto.Blowfish
}

// New connects a GS client.
func New(from, to string, receiver gsm.Party) (*Client, error) {
	c, err := Dial(from, to)
	if err != nil {
		return nil, err
	}
	return &Client{Conn: c, Receiver: receiver}, nil
}

// Send sends a request.
func (c *Client) Send(t gsm.Type, data ...dl.Value) error {
	m := gsm.Notification(t, gsm.PartyPlayer, c.Receiver, dl.List(data))
	_, err := c.Conn.Write(m.MustEncode())
	return err
}

// SendRaw sends bytes.
func (c *Client) SendRaw(b []byte) error {
	_, err := c.Conn.Write(b)
	return err
}

// Recv reads one message, waiting at most d.
func (c *Client) Recv(d time.Duration) (*gsm.Message, error) {
	c.Conn.SetReadDeadline(time.Now().Add(d))
	m, _, err := gsm.Read(c.Conn, nil)
	return m, err
}

// All reads messages until none arrives for d.
func (c *Client) All(d time.Duration) []*gsm.Message {
	var out []*gsm.Message
	for {
		m, err := c.Recv(d)
		if err != nil {
			return out
		}
		out = append(out, m)
	}
}

// Request sends a request and returns the first message back.
func (c *Client) Request(t gsm.Type, data ...dl.Value) (*gsm.Message, error) {
	if err := c.Send(t, data...); err != nil {
		return nil, err
	}
	return c.Recv(3 * time.Second)
}

// Close closes the connection.
func (c *Client) Close() { c.Conn.Close() }

// KeyExchange runs the RSA key exchange; afterwards SendEncrypted works.
func (c *Client) KeyExchange() error {
	game, err := crypto.GenerateKey(nil)
	if err != nil {
		return err
	}
	pub := game.PublicKey.Marshal()
	res, err := c.Request(gsm.KEY_EXCHANGE, dl.S("1"), dl.L(dl.S("1"), dl.S(fmt.Sprint(len(pub))), dl.B(pub)))
	if err != nil {
		return err
	}
	args, _ := res.Data.List(1)
	svBuf, _ := args.Bin(2)
	sv, err := crypto.ParsePublicKey(svBuf)
	if err != nil {
		return err
	}
	enc, err := crypto.EncryptPKCS1v15(nil, sv, crypto.NewSessionKey())
	if err != nil {
		return err
	}
	res, err = c.Request(gsm.KEY_EXCHANGE, dl.S("2"), dl.L(dl.S("1"), dl.S(fmt.Sprint(len(enc))), dl.B(enc)))
	if err != nil {
		return err
	}
	args, _ = res.Data.List(1)
	encKey, _ := args.Bin(2)
	key, err := crypto.DecryptPKCS1v15(game, encKey)
	if err != nil {
		return err
	}
	c.BF, err = crypto.NewBlowfish(key)
	return err
}

// SendEncrypted sends a GS_ENCRYPT request with the exchanged key.
func (c *Client) SendEncrypted(t gsm.Type, data ...dl.Value) error {
	enc, err := c.BF.Encrypt(dl.List(data).Encode())
	if err != nil {
		return err
	}
	h := gsm.Header{Size: gsm.HeaderSize + len(enc), Property: gsm.PropGSEncrypt, Priority: 1, Type: t, Sender: gsm.PartyPlayer, Receiver: c.Receiver}
	_, err = c.Conn.Write(append(h.Bytes(), enc...))
	return err
}

// IRC is an IRC chat client.
type IRC struct {
	Conn  net.Conn
	buf   []byte
	lines []string
}

// NewIRC connects and, with a nick, registers it.
func NewIRC(from, to, nick string) (*IRC, error) {
	c, err := Dial(from, to)
	if err != nil {
		return nil, err
	}
	i := &IRC{Conn: c}
	if nick != "" {
		i.Send("NICK :"+nick, "USER HEROES_657d2c2ebadc6a1d +i 0 :"+nick)
	}
	return i, nil
}

// Send sends lines, one frame each.
func (i *IRC) Send(lines ...string) error {
	var out []byte
	for _, l := range lines {
		f, err := irc.Frame([]byte(l + "\r\n"))
		if err != nil {
			return err
		}
		out = append(out, f...)
	}
	_, err := i.Conn.Write(out)
	return err
}

// Read returns the lines received within d.
func (i *IRC) Read(d time.Duration) []string {
	end := time.Now().Add(d)
	tmp := make([]byte, 4096)
	for time.Now().Before(end) {
		i.Conn.SetReadDeadline(end)
		n, err := i.Conn.Read(tmp)
		i.buf = append(i.buf, tmp[:n]...)
		for len(i.buf) >= 2 {
			size := int(i.buf[0])<<8 | int(i.buf[1])
			if len(i.buf) < 2+size {
				break
			}
			p, derr := irc.Unframe(i.buf[2 : 2+size])
			i.buf = i.buf[2+size:]
			if derr == nil {
				for _, l := range strings.Split(string(p), "\r\n") {
					if l != "" {
						i.lines = append(i.lines, l)
					}
				}
			}
		}
		if err != nil {
			break
		}
	}
	out := i.lines
	i.lines = nil
	return out
}

// Close closes the connection.
func (i *IRC) Close() { i.Conn.Close() }
