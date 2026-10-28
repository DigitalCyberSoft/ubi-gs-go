// Package irc implements the Game Service IRC chat: IRC lines in frames of a big-endian u16 length and a
// payload encrypted with the game's static Blowfish key. The game uses it for lobby and room chat.
package irc

import (
	"encoding/binary"
	"errors"
	"io"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/crypto"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/logx"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/netsrv"
)

// Key is the static Blowfish key of the IRC service.
var Key = []byte{0x06, 0xE2, 0xC8, 0x46, 0x01, 0x90, 0x55, 0x7C, 0x3C, 0xA1, 0xCD, 0xA3, 0xE3, 0xA1, 0x10, 0x6C}

var cipher = crypto.MustBlowfish(Key)

// HeaderSize is the frame header (the payload length).
const HeaderSize = 2

// ServerName is the server's name in replies.
const ServerName = "localhost"

// Frame encrypts an IRC line (with its line ending) into a frame.
func Frame(line []byte) ([]byte, error) {
	enc, err := cipher.Encrypt(line)
	if err != nil {
		return nil, err
	}
	if len(enc) > 0xFFFF {
		return nil, errors.New("irc: line too long")
	}
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(enc))), enc...), nil
}

// Unframe decrypts a frame's payload (without its header).
func Unframe(payload []byte) ([]byte, error) { return cipher.Decrypt(payload) }

// ReadFrame reads one frame's decrypted payload from a stream.
func ReadFrame(r io.Reader) ([]byte, error) {
	var head [HeaderSize]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, err
	}
	payload := make([]byte, binary.BigEndian.Uint16(head[:]))
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return Unframe(payload)
}

// Numeric replies.
const (
	rplWelcome          = "001"
	rplIsOn             = "303"
	rplNameReply        = "353"
	rplEndOfNames       = "366"
	rplEndOfMOTD        = "376"
	errNoSuchNick       = "401"
	errNoSuchChannel    = "403"
	errCannotSendToChan = "404"
	errUnknownCommand   = "421"
	errNoNicknameGiven  = "431"
	errErroneusNickname = "432"
	errNicknameInUse    = "433"
	errNotOnChannel     = "442"
	errNotRegistered    = "451"
	errNeedMoreParams   = "461"
)

// NickPolicy decides which nicks a connection may use: with the router in the same process, only the
// name of an account logged in from the connection's address.
type NickPolicy func(nick, ip string) bool

// Server is the IRC service.
type Server struct {
	Log *logx.Logger
	// Allowed, if set, restricts nicks.
	Allowed NickPolicy
	// Timeout drops a client silent this long; a PING goes out at half of it.
	Timeout time.Duration

	mu       sync.Mutex
	clients  map[string]*client
	channels map[string]*channel
}

type channel struct {
	name    string
	topic   string
	topicBy string
	members []*client // join order
}

func (ch *channel) has(c *client) bool {
	for _, m := range ch.members {
		if m == c {
			return true
		}
	}
	return false
}

func (ch *channel) remove(c *client) {
	for i, m := range ch.members {
		if m == c {
			ch.members = append(ch.members[:i], ch.members[i+1:]...)
			return
		}
	}
}

type client struct {
	conn     *netsrv.Conn
	nick     string
	user     string
	realname string
	channels map[string]*channel
	order    []string // channel names in join order
}

// New returns an IRC server.
func New(log *logx.Logger, timeout time.Duration) *Server {
	return &Server{Log: log, Timeout: timeout, clients: map[string]*client{}, channels: map[string]*channel{}}
}

func (c *client) ident() string {
	nick, user := c.nick, c.user
	if nick == "" {
		nick = "None"
	}
	if user == "" {
		user = "None"
	}
	return nick + "!" + user + "@" + ServerName
}

func (s *Server) sendTo(c *client, line string) {
	s.Log.Debugf("-> %s %s", c.ident(), line)
	frame, err := Frame([]byte(line + "\r\n"))
	if err != nil {
		s.Log.Warnf("not sent to %s: %v", c.ident(), err)
		return
	}
	c.conn.Send(frame)
}

var lineSep = regexp.MustCompile("\r?\n")

// Serve serves an IRC connection.
func (s *Server) Serve(conn *netsrv.Conn) {
	c := &client{conn: conn, channels: map[string]*channel{}}
	s.Log.Infof("client connected: %s", conn.RemoteAddr())
	defer s.finish(c)
	var pending []byte
	lastSeen := time.Now()
	pinged := false
	buf := make([]byte, 4096)
	var frames []byte
	for !conn.Closed() {
		// a quiet client gets a PING at half the timeout and is dropped at the timeout
		deadline := lastSeen.Add(s.Timeout / 2)
		if pinged {
			deadline = lastSeen.Add(s.Timeout)
		}
		if s.Timeout > 0 {
			conn.SetReadDeadline(deadline)
		}
		n, err := conn.Read(buf)
		if n > 0 {
			lastSeen, pinged = time.Now(), false
			frames = append(frames, buf[:n]...)
			// frames can be split across reads or share one; a frame is at most 2 + 0xFFFF bytes
			for len(frames) >= HeaderSize {
				end := HeaderSize + int(binary.BigEndian.Uint16(frames))
				if len(frames) < end {
					break
				}
				payload, derr := Unframe(frames[HeaderSize:end])
				frames = frames[end:]
				if derr != nil {
					s.Log.Warnf("bad frame from %s: %v", c.ident(), derr)
					continue
				}
				pending = append(pending, payload...)
				lines := lineSep.Split(string(pending), -1)
				pending = []byte(lines[len(lines)-1])
				for _, line := range lines[:len(lines)-1] {
					s.handleLine(c, line)
				}
				if len(pending) > 0xFFFF {
					s.Log.Warnf("closing %s: line too long", c.ident())
					return
				}
			}
			if len(frames) > 2*0x10000 {
				return
			}
		}
		if err != nil {
			if conn.Closed() {
				return
			}
			if netsrv.IsTimeout(err) && s.Timeout > 0 {
				if !pinged {
					pinged = true
					s.sendTo(c, "PING :"+ServerName)
					continue
				}
				s.Log.Infof("client timed out: %s", c.ident())
			}
			return
		}
	}
}

func (s *Server) handleLine(c *client, line string) {
	s.Log.Debugf("<- %s %s", c.ident(), line)
	command, params, _ := strings.Cut(line, " ")
	s.mu.Lock()
	defer s.mu.Unlock()
	var reply string
	var ircErr *ircError
	switch strings.ToLower(command) {
	case "nick":
		reply, ircErr = s.nick(c, params)
	case "user":
		ircErr = s.user(c, params)
	case "pong":
	case "ping":
		reply = ":" + ServerName + " PONG :" + ServerName
	case "join":
		ircErr = s.join(c, params)
	case "privmsg", "notice":
		ircErr = s.message(c, strings.ToUpper(command), params)
	case "topic":
		reply, ircErr = s.topic(c, params)
	case "part":
		ircErr = s.part(c, params)
	case "quit":
		s.quit(c, params)
	case "ison":
		reply = s.ison(c, params)
	case "mode":
		reply, ircErr = s.mode(c, params)
	case "dump":
		s.dump()
	default:
		s.Log.Infof("no handler for command: %s. Full line: %q", command, line)
		ircErr = &ircError{errUnknownCommand, command + " :Unknown command"}
	}
	if ircErr != nil {
		reply = ":" + ServerName + " " + ircErr.code + " " + ircErr.value
		s.Log.Infof("%s: %s", c.ident(), reply)
	}
	if reply != "" {
		s.sendTo(c, reply)
	}
}

type ircError struct{ code, value string }

var badNick = regexp.MustCompile(`[^a-zA-Z0-9\-\[\]'` + "`" + `^{}_.]`)

// nick handles the first nick (registration) and nick changes.
func (s *Server) nick(c *client, params string) (string, *ircError) {
	nick := strings.TrimSpace(params)
	nick = strings.TrimPrefix(nick, ":")
	if nick == "" {
		return "", &ircError{errNoNicknameGiven, ":No nickname given"}
	}
	if badNick.MatchString(nick) {
		return "", &ircError{errErroneusNickname, ":" + nick}
	}
	if s.clients[nick] == c {
		return "", nil
	}
	if s.Allowed != nil && !s.Allowed(nick, c.conn.IP) {
		s.Log.Warnf("refused nick %s from %s: no such account logged in from there", nick, c.conn.IP)
		return "", &ircError{errErroneusNickname, nick + " :Nickname is not your account name"}
	}
	if holder := s.clients[nick]; holder != nil {
		if holder.conn.IP != c.conn.IP {
			return "", &ircError{errNicknameInUse, "NICK :" + nick}
		}
		// the same player reconnecting (game restart, dropped link): the old connection is stale
		s.Log.Infof("%s reconnected from %s, dropping the old connection", nick, c.conn.IP)
		s.drop(holder)
	}
	if c.nick == "" {
		c.nick = nick
		s.clients[nick] = c
		s.sendTo(c, ":"+ServerName+" "+rplWelcome+" "+nick+" :Welcome to GS IRC v1.0.0.")
		s.sendTo(c, ":"+ServerName+" "+rplEndOfMOTD+" "+nick+" :End of MOTD command.")
		return "", nil
	}
	msg := ":" + c.ident() + " NICK :" + nick
	delete(s.clients, c.nick)
	c.nick = nick
	s.clients[nick] = c
	for _, name := range c.order {
		s.toOthers(c, c.channels[name], msg)
	}
	return msg, nil
}

func (s *Server) user(c *client, params string) *ircError {
	parts := strings.SplitN(params, " ", 4)
	if len(parts) != 4 {
		return &ircError{errNeedMoreParams, "USER :Not enough parameters"}
	}
	c.user, c.realname = parts[0], parts[3]
	return nil
}

var channelName = regexp.MustCompile(`^#([a-zA-Z0-9_\.])+$`)

func (s *Server) join(c *client, params string) *ircError {
	names, _, _ := strings.Cut(params, " ")
	for _, name := range strings.Split(names, ",") {
		name = strings.TrimPrefix(strings.TrimSpace(name), ":")
		if name == "" {
			return &ircError{errNeedMoreParams, "JOIN :Not enough parameters"}
		}
		if !channelName.MatchString(name) {
			return &ircError{errNoSuchChannel, name + " :No such channel"}
		}
		ch := s.channels[name]
		if ch == nil {
			ch = &channel{name: name, topic: "No topic", topicBy: "Unknown"}
			s.channels[name] = ch
		}
		if !ch.has(c) {
			ch.members = append(ch.members, c)
		}
		if _, ok := c.channels[name]; !ok {
			c.order = append(c.order, name)
		}
		c.channels[name] = ch
		s.sendTo(c, ":"+ch.topicBy+" TOPIC "+ch.name+" :"+ch.topic)
		joined := ":" + c.ident() + " JOIN :" + name
		for _, m := range ch.members {
			s.sendTo(m, joined)
		}
		nicks := make([]string, len(ch.members))
		for i, m := range ch.members {
			nicks[i] = m.nick
		}
		s.sendTo(c, ":"+ServerName+" "+rplNameReply+" "+c.nick+" = "+ch.name+" :"+strings.Join(nicks, " "))
		s.sendTo(c, ":"+ServerName+" "+rplEndOfNames+" "+c.nick+" "+ch.name+" :End of /NAMES list")
	}
	return nil
}

var (
	chatNumber  = regexp.MustCompile(`^[0-9]{1,10}$`)
	chatFont    = regexp.MustCompile(`^[A-Za-z0-9 _\-]{1,32}$`)
	controlChar = regexp.MustCompile(`[\x00-\x1f\x7f]`)
)

// ChatFields are the fields of the game's chat payload `name%color%size%n%n%font%text`
// (e.g. `alice%16777215%9%0%0%Arial%2alice has joined the game`).
const ChatFields = 7

// SanitizeChat returns the chat payload as it may be relayed from nick, or false to drop it. The game
// shows the name and formatting from the payload, not the IRC nick, so the name is forced to the
// sender's, the formatting fields must be plain numbers and a font name, and the game's own
// announcements (type digit 2) must be about the sender.
func SanitizeChat(nick, payload string) (string, bool) {
	payload = strings.TrimPrefix(payload, ":")
	fields := strings.SplitN(payload, "%", ChatFields)
	if len(fields) != ChatFields {
		return "", false
	}
	for _, f := range fields[1:5] {
		if !chatNumber.MatchString(f) {
			return "", false
		}
	}
	if !chatFont.MatchString(fields[5]) {
		return "", false
	}
	// control characters could end the line or confuse the game's text renderer
	text := controlChar.ReplaceAllString(fields[6], "")
	if strings.HasPrefix(text, "2") && !strings.HasPrefix(text[1:], nick+" ") {
		return "", false
	}
	fields[0], fields[6] = nick, text
	return ":" + strings.Join(fields, "%"), true
}

func (s *Server) message(c *client, cmd, params string) *ircError {
	target, msg, _ := strings.Cut(params, " ")
	if target == "" || msg == "" {
		return &ircError{errNeedMoreParams, cmd + " :Not enough parameters"}
	}
	if c.nick == "" {
		return &ircError{errNotRegistered, ":You have not registered"}
	}
	chat, ok := SanitizeChat(c.nick, msg)
	if !ok {
		s.Log.Warnf("dropped %s from %s: %q", cmd, c.ident(), msg)
		return nil
	}
	line := ":" + c.ident() + " " + cmd + " " + target + " " + chat
	if strings.HasPrefix(target, "#") || strings.HasPrefix(target, "$") {
		ch := s.channels[target]
		if ch == nil {
			return &ircError{errNoSuchNick, cmd + " :" + target}
		}
		if c.channels[ch.name] == nil {
			return &ircError{errCannotSendToChan, ch.name + " :Cannot send to channel"}
		}
		s.toOthers(c, ch, line)
		return nil
	}
	to := s.clients[target]
	if to == nil {
		return &ircError{errNoSuchNick, cmd + " :" + target}
	}
	s.sendTo(to, line)
	return nil
}

func (s *Server) toOthers(c *client, ch *channel, line string) {
	if ch == nil {
		return
	}
	for _, m := range ch.members {
		if m != c {
			s.sendTo(m, line)
		}
	}
}

func (s *Server) topic(c *client, params string) (string, *ircError) {
	name, topic, _ := strings.Cut(params, " ")
	ch := s.channels[name]
	if ch == nil {
		return "", &ircError{errNoSuchNick, "PRIVMSG :" + name}
	}
	if c.channels[ch.name] == nil {
		return "", &ircError{errCannotSendToChan, ch.name + " :Cannot send to channel"}
	}
	if topic != "" {
		ch.topic = strings.TrimLeft(topic, ":")
		ch.topicBy = c.nick
	}
	return ":" + c.ident() + " TOPIC " + name + " :" + ch.topic, nil
}

// part handles `PART <channel>[,<channel>] [:<reason>]` (the game sends `PART #chan :`).
func (s *Server) part(c *client, params string) *ircError {
	names, reason, _ := strings.Cut(strings.TrimSpace(params), " ")
	reason = strings.TrimLeft(reason, ":")
	if names == "" {
		return &ircError{errNeedMoreParams, "PART :Not enough parameters"}
	}
	for _, name := range strings.Split(names, ",") {
		name = strings.TrimSpace(name)
		ch := c.channels[name]
		if ch == nil {
			code, text := errNoSuchChannel, ":No such channel"
			if s.channels[name] != nil {
				code, text = errNotOnChannel, ":You're not on that channel"
			}
			s.sendTo(c, ":"+ServerName+" "+code+" "+c.nick+" "+name+" "+text)
			continue
		}
		line := ":" + c.ident() + " PART " + name + " :" + reason
		for _, m := range ch.members {
			s.sendTo(m, line)
		}
		ch.remove(c)
		s.leftChannel(c, name)
	}
	return nil
}

func (s *Server) leftChannel(c *client, name string) {
	delete(c.channels, name)
	for i, n := range c.order {
		if n == name {
			c.order = append(c.order[:i], c.order[i+1:]...)
			break
		}
	}
	if ch := s.channels[name]; ch != nil && len(ch.members) == 0 {
		delete(s.channels, name)
	}
}

func (s *Server) quit(c *client, params string) {
	line := ":" + c.ident() + " QUIT :" + strings.TrimLeft(params, ":")
	for _, name := range append([]string(nil), c.order...) {
		ch := c.channels[name]
		for _, m := range ch.members {
			s.sendTo(m, line)
		}
		ch.remove(c)
		s.leftChannel(c, name)
	}
}

func (s *Server) ison(c *client, params string) string {
	if strings.TrimSpace(params) == "" {
		return ":" + ServerName + " " + errNeedMoreParams + " " + c.nick + " ISON :Not enough parameters"
	}
	var online []string
	for _, n := range strings.Split(params, " ") {
		if s.clients[n] != nil {
			online = append(online, n)
		}
	}
	return ":" + ServerName + " " + rplIsOn + " " + c.nick + " :" + strings.Join(online, " ")
}

func (s *Server) mode(c *client, params string) (string, *ircError) {
	target, mode, _ := strings.Cut(params, " ")
	mode = strings.TrimPrefix(mode, ":")
	if target == "" || mode == "" {
		return "", &ircError{errNeedMoreParams, "MODE :Not enough parameters"}
	}
	if target[0] == '#' || target[0] == '&' {
		return "", nil
	}
	return ":" + ServerName + " MODE " + target + " " + mode, nil
}

func (s *Server) dump() {
	nicks := make([]string, 0, len(s.clients))
	for n := range s.clients {
		nicks = append(nicks, n)
	}
	sort.Strings(nicks)
	s.Log.Infof("clients: %v", nicks)
	for name, ch := range s.channels {
		var members []string
		for _, m := range ch.members {
			members = append(members, m.nick)
		}
		s.Log.Infof("channel %s: %v", name, members)
	}
}

// finish removes a gone client from its channels and the nick table.
func (s *Server) finish(c *client) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.release(c)
	s.Log.Infof("connection finished: %s", c.ident())
}

// release tells the client's channels it quit and frees its nick. s.mu is held.
func (s *Server) release(c *client) {
	line := ":" + c.ident() + " QUIT :EOF from client"
	for _, name := range append([]string(nil), c.order...) {
		ch := c.channels[name]
		if ch.has(c) {
			for _, m := range ch.members {
				if m != c {
					s.sendTo(m, line)
				}
			}
			ch.remove(c)
		}
		s.leftChannel(c, name)
	}
	if c.nick != "" && s.clients[c.nick] == c {
		delete(s.clients, c.nick)
	}
}

// drop closes a stale connection whose nick a reconnect takes over. s.mu is held.
func (s *Server) drop(c *client) {
	s.release(c)
	c.conn.Close()
}
