// Package lobby implements the lobby server: channels, rooms, members and the match flow.
//
// Players' addresses only go where the game needs them for its peer-to-peer connection: to the members
// of the same room. Lobby-wide member lists and room lists carry a placeholder (0.0.0.0) instead, and
// with the relay on every address a player is shown is a relay address.
package lobby

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/accounts"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/dl"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/env"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/gsm"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/h5"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/logx"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/netsrv"
)

// MemberNameSize is the game's buffer for a member name, terminator included (0x004242d0, 0x00424f00).
const MemberNameSize = 36

// FirstRoomID is the id of the first room created.
const FirstRoomID = 1000

// MaxRooms caps the rooms open at once; a room holds up to a message's worth of its creator's data.
const MaxRooms = 512

// MaxRoomMembers caps a room's players and visitors together (a Heroes V game has up to 8 players), so
// a room and its chat channel can't gather a crowd of connections.
const MaxRoomMembers = 16

// Placeholder stands in for an address a player must not see.
const Placeholder = "0.0.0.0"

// Relay maps players to relay addresses when the relay is on.
type Relay interface {
	// PeerAddr returns the relay address standing for the player at playerIP, as the player at
	// viewerIP reaches it. hint is an address the player's own data names, which picks the player's
	// relay port when several players share an address.
	PeerAddr(playerIP string, hint netip.AddrPort, viewerIP string) (netip.AddrPort, bool)
}

// Results receives the results of finished rated matches.
type Results interface {
	MatchFinished(m *Match)
}

// Match is a rated match: its room and the values each player submitted.
type Match struct {
	ID   int
	Room int
	Game string // the game id of the room (its title)
	// Players are the room's players when the match started, by account name.
	Players []string
	// Accounts resolve the names the games use for the players (account and typed names).
	Accounts map[string]*accounts.Account
	// Order and Values are the submitted results by player name, in submission order.
	Order  []string
	Values map[string]dl.List
	// Disputed are the players whose result (value 0) the clients reported differently, without a
	// report from the client that finished the match to settle it.
	Disputed map[string]bool
	reports  map[string]map[*client]dl.List
}

// settle decides each player's values from the clients' reports: the values all reports agree on (by
// result), else the report of the client that finished the match (the host, which stayed to the end;
// a client that quits early reports itself as the winner, as seen in the real game), else none: the
// player is disputed and not rated.
func (m *Match) settle(finisher *client) {
	for name, reports := range m.reports {
		results := map[string]bool{}
		for _, v := range reports {
			r := ""
			if len(v) > 0 {
				r = v[0].String()
			}
			results[r] = true
		}
		if len(results) <= 1 {
			continue
		}
		if v, ok := reports[finisher]; ok {
			m.Values[name] = v
			continue
		}
		m.Disputed[name] = true
	}
}

// Lobby is the lobby server's state.
type Lobby struct {
	Env     *env.Env
	Log     *logx.Logger
	Relay   Relay   // nil: relay off
	Results Results // nil: results are only relayed
	// Left is told a player address that has no lobby connection left (the relay frees its ports).
	Left func(ip string)

	mu          sync.Mutex
	clients     []*client
	rooms       []*room
	nextRoomID  int
	nextMatchID int
	matches     map[int]*Match
	// peers are groups of player addresses allowed to reach each other through the relay: rooms, and
	// started games for a while after their room is gone
	games []*game
}

type game struct {
	ips   map[string]bool
	until time.Time
}

type client struct {
	*netsrv.GSClient
	typed    string
	username string
	account  *accounts.Account
	localIP  string
	lobbyID  int // 0: none
	roomID   int // 0: none
	visitor  bool
	// playerInfo is the data the game set with SET_PLAYER_INFO
	playerInfo []byte
}

// New returns a lobby.
func New(e *env.Env, log *logx.Logger) *Lobby {
	return &Lobby{Env: e, Log: log, nextRoomID: FirstRoomID, nextMatchID: 1, matches: map[int]*Match{}}
}

// Serve serves a lobby connection.
func (l *Lobby) Serve(conn *netsrv.Conn) {
	c := &client{GSClient: &netsrv.GSClient{Conn: conn, Log: l.Log}}
	l.mu.Lock()
	l.clients = append(l.clients, c)
	l.mu.Unlock()
	defer func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		for i, o := range l.clients {
			if o == c {
				l.clients = append(l.clients[:i], l.clients[i+1:]...)
				break
			}
		}
		l.leaveLobby(c)
		l.closeUnjoined(c)
		for _, o := range l.clients {
			if o.IP == c.IP {
				return
			}
		}
		l.endGame(c)
		if l.Left != nil {
			l.Left(c.IP)
		}
	}()
	c.ServeGS(func(req *gsm.Message) error {
		// shared lobby state and other players' connections
		l.mu.Lock()
		defer l.mu.Unlock()
		res, after, err := l.handle(c, req)
		if err != nil {
			var bad *badRequest
			if errors.As(err, &bad) {
				// an unknown or malformed request must not drop the player
				l.Log.Warnf("unhandled request from %s: %v", c.name(), err)
				return nil
			}
			return err
		}
		if res != nil {
			c.SendMsg(res)
		}
		if after != nil {
			after()
		}
		return nil
	})
}

func (c *client) name() string {
	if c.username != "" {
		return c.username
	}
	return c.RemoteAddr().String()
}

// badRequest is a request the lobby ignores (logged, the connection stays).
type badRequest struct{ msg string }

func (e *badRequest) Error() string { return e.msg }

func bad(format string, args ...any) error { return &badRequest{fmt.Sprintf(format, args...)} }

func (l *Lobby) send(c *client, sub gsm.LobbyMsg, data dl.List) {
	m := gsm.LobbyNotification(sub, data)
	l.Log.Debugf("-> %s %s", c.name(), m)
	c.SendMsg(m)
}

func (l *Lobby) findRoom(id int) *room {
	if id == 0 {
		return nil
	}
	for _, r := range l.rooms {
		if r.id == id {
			return r
		}
	}
	return nil
}

// lobbyMembers are the clients in the lobby, the ones in its rooms included.
func (l *Lobby) lobbyMembers(id int) []*client {
	var out []*client
	for _, c := range l.clients {
		if id != 0 && c.lobbyID == id {
			out = append(out, c)
		}
	}
	return out
}

func (l *Lobby) roomMembers(id int) []*client {
	var out []*client
	for _, c := range l.clients {
		if id != 0 && c.roomID == id {
			out = append(out, c)
		}
	}
	return out
}

// shownName is the member's name for a player: the account name, but the typed one for the player
// itself (the game knows itself by it).
func shownName(member, to *client) string {
	if member == to && member.typed != "" {
		return member.typed
	}
	return member.username
}

// inRoom reports whether the viewer sees the subject from inside the same room.
func inRoom(subject, viewer *client, groupID int) bool {
	return viewer == subject || (groupID != 0 && groupID >= FirstRoomID && viewer.roomID == groupID && subject.roomID == groupID)
}

// memberAddrs returns the subject's public and local address as the viewer sees them in a group.
func (l *Lobby) memberAddrs(subject, viewer *client, groupID int) (string, string) {
	real, alt := subject.IP, subject.localIP
	if alt == "" {
		alt = real
	}
	if viewer == subject {
		return real, alt
	}
	if l.Relay != nil {
		if a, ok := l.Relay.PeerAddr(subject.IP, l.ownHint(subject), viewer.IP); ok {
			return a.Addr().String(), a.Addr().String()
		}
		return Placeholder, Placeholder
	}
	if inRoom(subject, viewer, groupID) {
		return real, alt
	}
	return Placeholder, Placeholder
}

// ownHint is the address the subject's own player data names (with the relay on, its relay address).
func (l *Lobby) ownHint(subject *client) netip.AddrPort {
	if len(subject.playerInfo) == 0 {
		return netip.AddrPort{}
	}
	p, err := h5.DeserializePlayerInfo(subject.playerInfo)
	if err != nil {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(p.ExtIP.Addr(), p.ExtIP.Port)
}

// playerInfoFor returns a player info entry with the addresses the viewer may see. owner is the
// player the entry is about (nil if unknown).
func (l *Lobby) playerInfoFor(p *h5.PlayerInfo, owner, viewer *client, groupID int) *h5.PlayerInfo {
	if owner != nil && owner == viewer {
		return p
	}
	if l.Relay != nil {
		if owner == nil {
			return p.WithoutAddresses()
		}
		a, ok := l.Relay.PeerAddr(owner.IP, netip.AddrPortFrom(p.ExtIP.Addr(), p.ExtIP.Port), viewer.IP)
		if !ok {
			return p.WithoutAddresses()
		}
		c := p.WithoutAddresses()
		c.ExtIP.IP = a.Addr().As4()
		c.ExtIP.Port = a.Port()
		c.LocalIP = a.Addr().As4()
		c.LocalPort = a.Port()
		return c
	}
	if owner != nil && inRoom(owner, viewer, groupID) {
		return p
	}
	return p.WithoutAddresses()
}

// memberData returns the subject's member data blob as the viewer sees it.
func (l *Lobby) memberData(subject, viewer *client, groupID int) []byte {
	data := subject.playerInfo
	if len(data) == 0 {
		// the game sets it only after a ladder query; until then use its entry in the room info
		if r := l.findRoom(groupID); r != nil {
			if p := l.roomEntry(r, subject); p != nil {
				return l.playerInfoFor(p, subject, viewer, groupID).Serialize()
			}
		}
		return []byte{}
	}
	if subject == viewer {
		return data
	}
	p, err := h5.DeserializePlayerInfo(data)
	if err != nil {
		// not the structure we know: don't pass on what we can't check for addresses
		if l.Relay == nil && inRoom(subject, viewer, groupID) {
			return data
		}
		return []byte{}
	}
	return l.playerInfoFor(p, subject, viewer, groupID).Serialize()
}

// roomEntry is the subject's entry in the room info, if any.
func (l *Lobby) roomEntry(r *room, subject *client) *h5.PlayerInfo {
	for _, p := range r.info.PlayerInfos {
		if name := string(p.Username); name == subject.username || (subject.typed != "" && name == subject.typed) {
			return p
		}
	}
	return nil
}

// entryOwner finds the room member a room info entry is about.
func (l *Lobby) entryOwner(r *room, p *h5.PlayerInfo) *client {
	name := string(p.Username)
	for _, c := range l.roomMembers(r.id) {
		if c.username == name || (c.typed != "" && c.typed == name) {
			return c
		}
	}
	return nil
}

func (l *Lobby) master(r *room) *client {
	for _, c := range l.roomMembers(r.id) {
		if c.username == r.master {
			return c
		}
	}
	return nil
}

// roomList is the room's data as the viewer sees it, with its group info rebuilt from the room info.
func (l *Lobby) roomList(r *room, viewer *client) dl.Value {
	r.groupInfo = r.info.Serialize()
	master := l.master(r)
	inside := viewer != nil && viewer.roomID == r.id
	ip := r.ip
	info := r.info
	switch {
	case l.Relay != nil:
		ip = Placeholder
		info = l.relayView(r, r.info, viewer)
		if master != nil && viewer != nil {
			if master == viewer {
				ip = r.ip
			} else if a, ok := l.Relay.PeerAddr(master.IP, netip.AddrPortFrom(r.info.HostIP.Addr(), r.info.HostIP.Port), viewer.IP); ok {
				ip = a.Addr().String()
			}
		}
	case inside || (master != nil && master == viewer):
	default:
		ip = Placeholder
		info = r.info.WithoutAddresses()
	}
	return r.list(info.Serialize(), ip)
}

// relayView is a room info as the viewer sees it with the relay on: every player's addresses, the
// host's included, are relay addresses (the viewer's own entry stays as it is).
func (l *Lobby) relayView(r *room, src *h5.RoomInfo, viewer *client) *h5.RoomInfo {
	c := *src
	c.PlayerInfos = make([]*h5.PlayerInfo, len(src.PlayerInfos))
	for i, p := range src.PlayerInfos {
		c.PlayerInfos[i] = l.playerInfoFor(p, l.entryOwner(r, p), viewer, r.id)
	}
	c.HostIP.IP = [4]byte{}
	master := l.master(r)
	if master != nil && viewer != nil {
		if master == viewer {
			c.HostIP = src.HostIP
		} else if a, ok := l.Relay.PeerAddr(master.IP, netip.AddrPortFrom(src.HostIP.Addr(), src.HostIP.Port), viewer.IP); ok {
			c.HostIP.IP = a.Addr().As4()
			c.HostIP.Port = a.Port()
		}
	}
	return &c
}

// gameData is GAME_STARTED's data for a viewer: the host's room info, with relay addresses when the
// relay is on (the game puts its own private address in it).
func (l *Lobby) gameData(r *room, data dl.Value, viewer *client) dl.Value {
	b, ok := data.Bin()
	if l.Relay == nil || !ok || len(b) == 0 {
		return data
	}
	info, err := h5.DeserializeRoomInfo(b)
	if err != nil {
		// not the structure we know: it can't be checked for addresses
		l.Log.Warnf("GAME_READY data of room %d isn't a room info (%v); not passed on with the relay on", r.id, err)
		return dl.B([]byte{})
	}
	return dl.B(l.relayView(r, info, viewer).Serialize())
}

// memberInfo is the subject's entry in a GROUP_INFO member list (`MemberJoined` struct).
func (l *Lobby) memberInfo(subject, viewer *client, groupID int) dl.Value {
	ip, alt := l.memberAddrs(subject, viewer, groupID)
	visitor := "0"
	if subject.visitor {
		visitor = "1"
	}
	return dl.L(dl.S(gsm.Cap(shownName(subject, viewer), MemberNameSize)), dl.S(visitor), dl.S(ip), dl.S(alt),
		dl.B(l.memberData(subject, viewer, groupID)), dl.Strs(strconv.Itoa(groupID)), dl.S("-1"),
		dl.S(strconv.Itoa(l.status(groupID))))
}

func (l *Lobby) status(groupID int) int {
	if l.findRoom(groupID) != nil {
		return statusGameConnected
	}
	return statusNone
}

// memberJoin is MEMBER_JOIN data of the subject for the viewer.
func (l *Lobby) memberJoin(subject, viewer *client, groupID int) dl.List {
	ip, alt := l.memberAddrs(subject, viewer, groupID)
	visitor := "0"
	if subject.visitor {
		visitor = "1"
	}
	return dl.List{dl.S(gsm.Cap(shownName(subject, viewer), MemberNameSize)), dl.S(visitor), dl.S(strconv.Itoa(groupID)),
		dl.S(ip), dl.S(alt), dl.B(l.memberData(subject, viewer, groupID)), dl.S(strconv.Itoa(l.status(groupID)))}
}

// sendGroupInfo sends GROUP_INFO of a lobby (its rooms and members) or a room (its data and members).
func (l *Lobby) sendGroupInfo(c *client, groupID, flags int) {
	var data dl.Value
	var children []dl.Value
	var members []*client
	if r := l.findRoom(groupID); r != nil {
		data = l.roomList(r, c)
		members = l.roomMembers(groupID)
	} else {
		data = dl.L()
		for _, r := range l.rooms {
			if r.parentID == groupID {
				children = append(children, l.roomList(r, c))
			}
		}
		members = l.lobbyMembers(groupID)
	}
	list := make([]dl.Value, len(members))
	for i, m := range members {
		list[i] = l.memberInfo(m, c, groupID)
	}
	l.send(c, gsm.LobbyGroupInfo, dl.List{dl.S(strconv.Itoa(groupID)), dl.S(strconv.Itoa(flags)), data,
		dl.L(children...), dl.L(list...)})
}

// sendRoomUpdate sends the room data (members come with MEMBER_JOIN/MEMBER_LEAVE) to its lobby's
// players who are not in another room.
func (l *Lobby) sendRoomUpdate(r *room, exclude *client) {
	for _, m := range l.lobbyMembers(r.parentID) {
		if m != exclude && (m.roomID == 0 || m.roomID == r.id) {
			l.send(m, gsm.LobbyGroupInfo, dl.List{dl.S(strconv.Itoa(r.id)), dl.S(strconv.Itoa(LSMGroupInfo)),
				l.roomList(r, m), dl.L(), dl.L()})
		}
	}
}

func (l *Lobby) sendMemberJoin(c *client, groupID int, members []*client) {
	for _, m := range members {
		if m != c {
			l.send(m, gsm.LobbyMemberJoin, l.memberJoin(c, m, groupID))
		}
	}
}

func (l *Lobby) sendMemberLeave(c *client, groupID int, members []*client) {
	for _, m := range members {
		if m != c {
			l.send(m, gsm.LobbyMemberLeave, dl.List{dl.S(c.username), dl.S(strconv.Itoa(groupID))})
		}
	}
}

// joinRoomMembers runs after the join reply: the room's members (the player included) to the player,
// the player to the members.
func (l *Lobby) joinRoomMembers(c *client, r *room) {
	for _, m := range l.roomMembers(r.id) {
		l.send(c, gsm.LobbyMemberJoin, l.memberJoin(m, c, r.id))
	}
	l.sendMemberJoin(c, r.id, l.roomMembers(r.id))
	l.sendRoomUpdate(r, c)
}

// leaveRoom removes the client from its room; the room goes away with its master or last player.
func (l *Lobby) leaveRoom(c *client) {
	r := l.findRoom(c.roomID)
	c.roomID = 0
	if r == nil {
		return
	}
	if c.visitor {
		r.nbVisitors = max(0, r.nbVisitors-1)
	} else {
		r.nbPlayers = max(0, r.nbPlayers-1)
	}
	c.visitor = false
	remaining := l.roomMembers(r.id)
	if r.master == c.username || len(remaining) == 0 {
		l.closeRoom(r, remaining)
		return
	}
	l.sendMemberLeave(c, r.id, remaining)
	l.sendRoomUpdate(r, nil)
}

// closeRoom removes a room; its remaining members are back in the lobby, which is told.
func (l *Lobby) closeRoom(r *room, remaining []*client) {
	for i, o := range l.rooms {
		if o == r {
			l.rooms = append(l.rooms[:i], l.rooms[i+1:]...)
			break
		}
	}
	for _, m := range remaining {
		m.roomID = 0
	}
	for _, m := range l.lobbyMembers(r.parentID) {
		l.send(m, gsm.LobbyGroupRemove, dl.List{dl.S(strconv.Itoa(r.id))})
	}
	l.Log.Infof("room %d closed", r.id)
}

// closeUnjoined closes the rooms the client created but isn't in. The game joins its room right after
// creating it, and leaveRoom closes a room only for a member, so these would stay for good.
func (l *Lobby) closeUnjoined(c *client) {
	for _, r := range slices.Clone(l.rooms) {
		if r.creator == c && r.id != c.roomID {
			l.closeRoom(r, l.roomMembers(r.id))
		}
	}
}

// leaveLobby removes the client from its lobby (and room).
func (l *Lobby) leaveLobby(c *client) {
	l.leaveRoom(c)
	id := c.lobbyID
	c.lobbyID = 0
	if id != 0 {
		l.sendMemberLeave(c, id, l.lobbyMembers(id))
	}
}

// Peers reports whether two player addresses are in the same room, or played a game together
// recently; the relay forwards only between such players.
func (l *Lobby) Peers(a, b string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	for _, r := range l.rooms {
		hasA, hasB := false, false
		for _, m := range l.roomMembers(r.id) {
			hasA = hasA || m.IP == a
			hasB = hasB || m.IP == b
		}
		if hasA && hasB {
			return true
		}
	}
	kept := l.games[:0]
	found := false
	for _, g := range l.games {
		if now.Before(g.until) {
			kept = append(kept, g)
			found = found || (g.ips[a] && g.ips[b])
		}
	}
	l.games = kept
	return found
}

// gameLinger is how long the players of a started game may still reach each other through the relay
// after leaving their room, while their match goes on.
const gameLinger = 6 * time.Hour

// noteGame records a started game's players for the relay. l.mu is held.
func (l *Lobby) noteGame(r *room) {
	g := &game{ips: map[string]bool{}, until: time.Now().Add(gameLinger)}
	for _, m := range l.roomMembers(r.id) {
		g.ips[m.IP] = true
	}
	l.games = append(l.games, g)
}

// endGame forgets the started games with the client's address. l.mu is held.
func (l *Lobby) endGame(c *client) {
	kept := l.games[:0]
	for _, g := range l.games {
		if !g.ips[c.IP] {
			kept = append(kept, g)
		}
	}
	l.games = kept
}
