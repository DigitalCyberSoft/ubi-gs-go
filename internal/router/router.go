// Package router implements the router (login, key exchange) and the router wait module (player info,
// friends, proxy modules, lobby list) of the Heroes V Game Service.
package router

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/accounts"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/dl"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/env"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/gsm"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/guard"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/logx"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/netsrv"
)

// FriendUnknown is the ADDFRIEND failure reason for a player that doesn't exist.
const FriendUnknown = 1

// Lobby is a top-level group (a channel of the lobby list).
type Lobby struct {
	ID      int
	Name    string
	EventID int // the game mode
}

// Lobbies are the channels: Casual (standard), Ranked (rating) and 1v1 (duel).
var Lobbies = []Lobby{{1, "Casual", 0}, {2, "Ranked", 1}, {3, "1v1", 2}}

// list is the lobby's group data, ending with the most members it takes and the members it has.
func (l Lobby) list(capacity, members int) dl.Value {
	return dl.L(dl.S("0"), dl.S(l.Name), dl.S(strconv.Itoa(l.ID)), dl.S("1"), dl.S("0"), dl.S("0"), dl.S("1"),
		dl.S(""), dl.S(""), dl.S(""), dl.B([]byte{}), dl.S(strconv.Itoa(l.EventID)), dl.S(strconv.Itoa(capacity)),
		dl.S(strconv.Itoa(members)))
}

// Router serves the router and its wait module, and knows who is logged in.
type Router struct {
	Env   *env.Env
	Log   *logx.Logger // router
	WMLog *logx.Logger // router wait module
	Guard *guard.Guard
	// LobbyMembers, if set, counts a lobby's players for the lobby list (the game shows them per channel).
	LobbyMembers func(lobbyID int) int
	// MaxLobbyMembers is the most players the lobby list says a lobby takes (8 if unset): as many players
	// as that may read as a full channel, so it is the lobby service's real cap.
	MaxLobbyMembers int

	mu     sync.Mutex
	logins map[*client]struct{} // router connections
	wm     map[*client]struct{} // wait module connections
}

type client struct {
	*netsrv.GSClient
	account *accounts.Account
	// username is the account name, or the typed name without a session
	username string
}

// New returns a router.
func New(e *env.Env, log, wmLog *logx.Logger, g *guard.Guard) *Router {
	return &Router{Env: e, Log: log, WMLog: wmLog, Guard: g, logins: map[*client]struct{}{}, wm: map[*client]struct{}{}}
}

var errUnhandled = errors.New("no request handler")

func unhandled(req *gsm.Message) error {
	return fmt.Errorf("%w for %s messages", errUnhandled, req.Header.Type)
}

func needStr(l dl.List, i int, what string) (string, error) {
	s, ok := l.Str(i)
	if !ok {
		return "", fmt.Errorf("malformed request: no %s", what)
	}
	return s, nil
}

// ServeRouter serves a router connection.
func (r *Router) ServeRouter(conn *netsrv.Conn) {
	c := &client{GSClient: &netsrv.GSClient{Conn: conn, Log: r.Log}}
	r.mu.Lock()
	r.logins[c] = struct{}{}
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(r.logins, c)
		r.mu.Unlock()
	}()
	c.ServeGS(func(req *gsm.Message) error {
		res, err := r.handleRouter(c, req)
		if err != nil {
			return err
		}
		if res != nil {
			c.SendMsg(res)
		}
		return nil
	})
}

func (r *Router) handleRouter(c *client, req *gsm.Message) (*gsm.Message, error) {
	switch req.Header.Type {
	case gsm.STILLALIVE:
		return gsm.StillAlive(req), nil
	case gsm.JOINWAITMODULE:
		return gsm.JoinWaitModule(req, r.Env.Advertise(c.Conn), r.Env.Ports.RouterWM), nil
	case gsm.LOGIN:
		// username, password, game id, ...
		typed, err := needStr(req.Data, 0, "user name")
		if err != nil {
			return nil, err
		}
		password, err := needStr(req.Data, 1, "password")
		if err != nil {
			return nil, err
		}
		account, err := r.Guard.Login(c.IP, typed, password)
		if err != nil {
			var le *accounts.LoginError
			if errors.As(err, &le) {
				r.Log.Infof("login of %s from %s refused: %s", typed, c.IP, le.Name)
				return gsm.Fail(req, le.Reason), nil
			}
			return nil, err
		}
		// the game keeps using the typed name in its later connections
		if err := r.Env.Accounts.BindSession(typed, c.IP, account); err != nil {
			return nil, err
		}
		r.mu.Lock()
		c.account, c.username = &account, account.Name
		r.replaceOlder(c)
		r.mu.Unlock()
		r.Log.Infof("%s logged in as %s from %s", typed, account.Name, c.IP)
		return gsm.Success(req), nil
	case gsm.KEY_EXCHANGE:
		return c.Session.KeyExchange(req)
	}
	return nil, unhandled(req)
}

// replaceOlder closes an older router connection of the same account (a crashed or stale game).
// r.mu is held.
func (r *Router) replaceOlder(c *client) {
	for other := range r.logins {
		if other != c && other.account != nil && other.account.ID == c.account.ID {
			r.Log.Infof("%s logged in again, closing the older connection from %s", c.username, other.RemoteAddr())
			other.Close()
		}
	}
}

// LoggedIn reports whether an account of that name is logged in from the address (router or wait
// module connection). The IRC service lets a game use only such a name as its nick.
func (r *Router) LoggedIn(name, ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, set := range []map[*client]struct{}{r.logins, r.wm} {
		for c := range set {
			if c.account != nil && c.IP == ip && strings.EqualFold(c.account.Name, name) && !c.Closed() {
				return true
			}
		}
	}
	return false
}

// online reports whether the account has a wait module connection. r.mu is held.
func (r *Router) online(a accounts.Account) bool {
	for c := range r.wm {
		if c.account != nil && c.account.ID == a.ID {
			return true
		}
	}
	return false
}

// ServeWaitModule serves a router wait module connection.
func (r *Router) ServeWaitModule(conn *netsrv.Conn) {
	c := &client{GSClient: &netsrv.GSClient{Conn: conn, Log: r.WMLog}}
	r.mu.Lock()
	r.wm[c] = struct{}{}
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		delete(r.wm, c)
		if c.account != nil && !r.online(*c.account) {
			r.notifyFriendOf(c, false)
		}
	}()
	c.ServeGS(func(req *gsm.Message) error {
		// friend updates go to other players' connections
		r.mu.Lock()
		defer r.mu.Unlock()
		res, after, err := r.handleWM(c, req)
		if err != nil {
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

func (r *Router) send(c *client, m *gsm.Message) {
	r.WMLog.Debugf("-> %s %s", c.username, m)
	c.SendMsg(m)
}

// sendFriendList sends UPDATEFRIEND for each of the player's friends. r.mu is held.
func (r *Router) sendFriendList(c *client) {
	if c.account == nil {
		return
	}
	friends, err := r.Env.Accounts.Friends(*c.account)
	if err != nil {
		r.WMLog.Errorf("friends of %s: %v", c.username, err)
		return
	}
	for _, f := range friends {
		r.send(c, gsm.UpdateFriend(f.Name, r.online(f)))
	}
}

// notifyFriendOf tells the players who have this one as a friend that it came online or went offline.
// r.mu is held.
func (r *Router) notifyFriendOf(c *client, online bool) {
	if c.account == nil {
		return
	}
	others, err := r.Env.Accounts.FriendOf(*c.account)
	if err != nil {
		r.WMLog.Errorf("friends of %s: %v", c.username, err)
		return
	}
	ids := map[int64]bool{}
	for _, o := range others {
		ids[o.ID] = true
	}
	for other := range r.wm {
		if other != c && other.account != nil && ids[other.account.ID] {
			r.send(other, gsm.UpdateFriend(c.account.Name, online))
		}
	}
}

// handleWM handles a wait module request; after runs once the reply is sent. r.mu is held.
func (r *Router) handleWM(c *client, req *gsm.Message) (*gsm.Message, func(), error) {
	switch req.Header.Type {
	case gsm.PLAYERINFO:
		if c.username == "" {
			return nil, nil, errors.New("PLAYERINFO before LOGINWAITMODULE")
		}
		return gsm.PlayerInfo(req, c.username), nil, nil
	case gsm.STILLALIVE:
		return gsm.StillAlive(req), nil, nil
	case gsm.LOGINWAITMODULE:
		// the name typed at login; the router knows its account
		typed, err := needStr(req.Data, 0, "user name")
		if err != nil {
			return nil, nil, err
		}
		account, err := r.Env.Accounts.Session(typed, c.IP)
		if err != nil {
			return nil, nil, err
		}
		c.account, c.username = account, typed
		if account != nil {
			c.username = account.Name
		}
		return gsm.Success(req), nil, nil
	case gsm.LOGINFRIENDS:
		// the friend list, and this player online for whoever has them as a friend
		return gsm.Success(req), func() {
			r.sendFriendList(c)
			r.notifyFriendOf(c, true)
		}, nil
	case gsm.ADDFRIEND:
		// [name, group, ?]
		name, err := needStr(req.Data, 0, "friend name")
		if err != nil {
			return nil, nil, err
		}
		friend, err := r.Env.Accounts.Find(name)
		if err != nil {
			return nil, nil, err
		}
		if c.account == nil || friend == nil || friend.ID == c.account.ID {
			return gsm.Fail(req, FriendUnknown), nil, nil
		}
		if err := r.Env.Accounts.AddFriend(*c.account, *friend); err != nil {
			return nil, nil, err
		}
		r.WMLog.Infof("%s added friend %s", c.username, friend.Name)
		// the game adds the friend to its list on this update, not on the reply
		return gsm.Success(req, dl.S(friend.Name)), func() {
			r.send(c, gsm.UpdateFriend(friend.Name, r.online(*friend)))
		}, nil
	case gsm.DELFRIEND:
		// [name]
		v, ok := req.Data.At(0)
		if !ok {
			return nil, nil, errors.New("malformed request: no friend name")
		}
		if name, ok := v.Str(); ok && c.account != nil {
			friend, err := r.Env.Accounts.Find(name)
			if err != nil {
				return nil, nil, err
			}
			if friend != nil {
				if err := r.Env.Accounts.RemoveFriend(*c.account, *friend); err != nil {
					return nil, nil, err
				}
			}
		}
		return gsm.Success(req, v), nil, nil
	case gsm.FRIENDLIST:
		return gsm.Success(req), func() { r.sendFriendList(c) }, nil
	case gsm.PROXY_HANDLER:
		res, err := r.proxyHandler(c, req)
		return res, nil, err
	case gsm.LOBBY_MSG:
		res, err := r.lobbyMsg(c, req)
		return res, nil, err
	case gsm.KEY_EXCHANGE:
		res, err := c.Session.KeyExchange(req)
		return res, nil, err
	}
	return nil, nil, unhandled(req)
}

// proxyHandler answers proxy module requests: ['1', [module, ...]] with the module's proxy, ['2', [id]]
// with a plain success. [[3|4, id]] is the game's notice that a module logged in (or failed): no reply.
func (r *Router) proxyHandler(c *client, req *gsm.Message) (*gsm.Message, error) {
	first, ok := req.Data.At(0)
	if !ok {
		return nil, errors.New("malformed PROXY_HANDLER")
	}
	if first.IsList() {
		return nil, nil
	}
	sub, _ := first.Str()
	args, _ := req.Data.List(1)
	switch sub {
	case "1":
		module, ok := args.Str(0)
		if !ok {
			return nil, errors.New("malformed PROXY_HANDLER 1")
		}
		var id string
		switch module {
		case "persistantdata":
			id = "1"
		case "ladderquery":
			id = "2"
		default:
			return nil, fmt.Errorf("request for unsupported proxy module %q", module)
		}
		proxy := dl.Strs(id, r.Env.Advertise(c.Conn), strconv.Itoa(r.Env.Ports.Proxy))
		info := dl.L(dl.S(module), dl.S("0"), dl.S("0"), dl.L(proxy))
		return gsm.Reply(req, gsm.PROXY_HANDLER, dl.List{dl.S(gsm.ResultSuccess), dl.L(dl.S(sub), info)}), nil
	case "2":
		id, ok := args.At(0)
		if !ok {
			return nil, errors.New("malformed PROXY_HANDLER 2")
		}
		return gsm.Reply(req, gsm.PROXY_HANDLER, dl.List{dl.S(gsm.ResultSuccess), dl.L(dl.S(sub), dl.L(id))}), nil
	}
	return nil, fmt.Errorf("unknown PROXY_HANDLER subtype %q", sub)
}

// lobbyMsg answers the lobby messages the game sends through the router.
func (r *Router) lobbyMsg(c *client, req *gsm.Message) (*gsm.Message, error) {
	n, ok := req.Data.Int(0)
	sub := gsm.LobbyMsg(n)
	if !ok || !sub.Known() {
		return nil, errors.New("unknown lobby message subtype")
	}
	args, _ := req.Data.List(1)
	switch sub {
	case gsm.LobbyJoinServer:
		id, ok := args.At(0)
		if !ok {
			return nil, errors.New("malformed JOIN_SERVER")
		}
		return JoinServer(req, id, r.Env.Advertise(c.Conn), r.Env.Ports.Lobby), nil
	case gsm.LobbyLogin:
		if _, ok := args.At(0); !ok {
			return nil, errors.New("malformed lobby LOGIN")
		}
		return gsm.LobbyReply(req, dl.List{dl.S(gsm.ResultSuccess), dl.Strs(strconv.Itoa(int(gsm.LobbyLogin)))}), nil
	case gsm.LobbyChangeRequestedLobbies:
		if _, ok := args.At(0); !ok {
			return nil, errors.New("malformed CHANGE_REQUESTED_LOBBIES")
		}
		capacity := r.MaxLobbyMembers
		if capacity <= 0 {
			capacity = 8
		}
		lists := make([]dl.Value, len(Lobbies))
		for i, l := range Lobbies {
			members := 0
			if r.LobbyMembers != nil {
				members = r.LobbyMembers(l.ID)
			}
			lists[i] = l.list(capacity, members)
		}
		data := dl.L(dl.S("1"), dl.S(strconv.Itoa(0x100)), dl.Strs("0"), dl.L(lists...))
		return gsm.LobbyReply(req, dl.List{dl.S(strconv.Itoa(int(gsm.LobbyGroupInfo))), data}), nil
	}
	return nil, fmt.Errorf("no request handler for %s lobby message", sub)
}

// JoinServer answers JOIN_SERVER: ['38', ['3', [server id, ip, port]]].
func JoinServer(req *gsm.Message, id dl.Value, ip string, port int) *gsm.Message {
	return gsm.LobbyReply(req, dl.List{dl.S(gsm.ResultSuccess),
		dl.L(dl.S(strconv.Itoa(int(gsm.LobbyJoinServer))), dl.L(id, dl.S(ip), dl.S(strconv.Itoa(port))))})
}
