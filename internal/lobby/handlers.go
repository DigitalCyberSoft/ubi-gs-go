package lobby

import (
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/accounts"
	"net/netip"
	"strconv"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/dl"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/gsm"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/h5"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/router"
)

// handle handles a request; after runs once the reply is sent. l.mu is held.
func (l *Lobby) handle(c *client, req *gsm.Message) (*gsm.Message, func(), error) {
	switch req.Header.Type {
	case gsm.STILLALIVE:
		return gsm.StillAlive(req), nil, nil
	case gsm.LOGINWAITMODULE:
		typed, ok := req.Data.Str(0)
		if !ok {
			return nil, nil, bad("malformed LOGINWAITMODULE")
		}
		l.login(c, typed)
		return gsm.Success(req), nil, nil
	case gsm.LOBBYSERVERLOGIN:
		// [user, flag, local ip, netmask, '0']; other players see the account name
		typed, ok1 := req.Data.Str(0)
		local, ok2 := req.Data.Str(2)
		if !ok1 || !ok2 {
			return nil, nil, bad("malformed LOBBYSERVERLOGIN")
		}
		l.login(c, typed)
		if a, err := netip.ParseAddr(local); err == nil && a.Is4() {
			c.localIP = a.String()
		} else {
			c.localIP = ""
		}
		// the reply carries this lobby server's id
		return gsm.Reply(req, gsm.GSSUCCESS, dl.List{dl.S(strconv.Itoa(int(gsm.LOBBYSERVERLOGIN))), dl.Strs("1")}), nil, nil
	case gsm.LOBBY_MSG:
		return l.lobbyMsg(c, req)
	}
	return nil, nil, bad("no request handler for %s messages", req.Header.Type)
}

func (l *Lobby) login(c *client, typed string) {
	c.typed = typed
	account, err := l.Env.Accounts.Session(typed, c.IP)
	if err != nil {
		l.Log.Errorf("session of %s: %v", typed, err)
	}
	c.account, c.username = account, typed
	if account != nil {
		c.username = account.Name
		if err := l.Env.Accounts.RecordLobbyLogin(*account); err != nil {
			l.Log.Errorf("lobby login of %s: %v", account.Name, err)
		}
	}
}

func groupArgs(req *gsm.Message) dl.List {
	args, _ := req.Data.List(1)
	return args
}

func (l *Lobby) lobbyMsg(c *client, req *gsm.Message) (*gsm.Message, func(), error) {
	n, ok := req.Data.Int(0)
	sub := gsm.LobbyMsg(n)
	if !ok || !sub.Known() {
		// not the payload: it is the client's, up to a message's size, and this runs under the lock
		return nil, nil, bad("unknown lobby message %d (%d values, %d bytes)", n, len(req.Data), req.Header.Size)
	}
	args := groupArgs(req)
	intArg := func(i int) (int, error) {
		v, ok := args.Int(i)
		if !ok {
			return 0, bad("malformed %s", sub)
		}
		return v, nil
	}
	switch sub {
	case gsm.LobbyJoinServer:
		id, ok := args.At(0)
		if !ok {
			return nil, nil, bad("malformed JOIN_SERVER")
		}
		return router.JoinServer(req, id, l.Env.Advertise(c.Conn), l.Env.Ports.Lobby), nil, nil

	case gsm.LobbyGroupInfoGet:
		id, err := intArg(0)
		if err != nil {
			return nil, nil, err
		}
		flags, err := intArg(1)
		if err != nil {
			return nil, nil, err
		}
		// the GROUP_INFO notification is the answer
		l.sendGroupInfo(c, id, flags)
		return nil, nil, nil

	case gsm.LobbyCreateRoom:
		return l.createRoom(c, req, args)

	case gsm.LobbyLogin:
		if _, ok := args.At(0); !ok {
			return nil, nil, bad("malformed lobby LOGIN")
		}
		return gsm.LobbyReply(req, dl.List{dl.S(gsm.ResultSuccess), dl.Strs(strconv.Itoa(int(sub)))}), nil, nil

	case gsm.LobbyJoinLobby:
		id, err := intArg(0)
		if err != nil {
			return nil, nil, err
		}
		if c.lobbyID != 0 {
			l.leaveLobby(c)
		}
		c.lobbyID = id
		res := gsm.LobbyReply(req, dl.List{dl.S(gsm.ResultSuccess), dl.L(dl.S(strconv.Itoa(int(sub))), dl.L(args[0]))})
		l.sendMemberJoin(c, id, l.lobbyMembers(id))
		l.Log.Infof("%s joined lobby %d", c.name(), id)
		return res, nil, nil

	case gsm.LobbyJoinRoom:
		// [group id, password, flags, visitor, gs version]
		id, err := intArg(0)
		if err != nil {
			return nil, nil, err
		}
		flags, err := intArg(2)
		if err != nil {
			return nil, nil, err
		}
		visitor, ok := args.Str(3)
		if _, ok2 := args.At(4); !ok || !ok2 {
			return nil, nil, bad("malformed JOIN_ROOM")
		}
		r := l.findRoom(id)
		if r == nil {
			return nil, nil, bad("failed to find room %d on join", id)
		}
		if c.roomID != id && len(l.roomMembers(id)) >= MaxRoomMembers {
			return nil, nil, bad("JOIN_ROOM refused: room %d is full", id)
		}
		res := gsm.LobbyReply(req, dl.List{dl.S(gsm.ResultSuccess), dl.L(dl.S(strconv.Itoa(int(sub))), dl.L(args[0]))})
		if c.roomID != 0 {
			l.leaveRoom(c)
		}
		c.roomID = id
		c.visitor = visitor == "1"
		if c.visitor {
			r.nbVisitors++
		} else {
			r.nbPlayers++
		}
		l.Log.Infof("%s joined room %d", c.name(), id)
		// the game takes the room from this GROUP_INFO, but ignores its members until the join reply
		l.sendGroupInfo(c, id, flags)
		return res, func() { l.joinRoomMembers(c, r) }, nil

	case gsm.LobbyGroupLeave:
		id, err := intArg(0)
		if err != nil {
			return nil, nil, err
		}
		res := gsm.LobbyReply(req, dl.List{dl.S(gsm.ResultSuccess), dl.L(dl.S(strconv.Itoa(int(sub))), dl.L(args[0]))})
		if id == c.roomID {
			l.leaveRoom(c)
		} else if id == c.lobbyID {
			l.leaveLobby(c)
		}
		return res, nil, nil

	case gsm.LobbyGroupConfigUpdateRes:
		return l.configUpdate(c, req, args)

	case gsm.LobbySetPlayerInfo:
		// the game's own player data (rating and addresses), attached to its member info
		data, ok := args.Bin(0)
		if !ok {
			return nil, nil, bad("malformed SET_PLAYER_INFO")
		}
		c.playerInfo = data
		if c.lobbyID != 0 {
			for _, m := range l.lobbyMembers(c.lobbyID) {
				if m != c {
					l.send(m, gsm.LobbyPlayerInfoUpdate, dl.List{dl.S(c.username), dl.B(l.memberData(c, m, c.lobbyID))})
				}
			}
		}
		return gsm.LobbyResult(req), nil, nil

	case gsm.LobbyStartGame:
		// the host pressed Start: [group id]
		if _, ok := args.At(0); !ok {
			return nil, nil, bad("malformed START_GAME")
		}
		return gsm.LobbyGroup(req), nil, nil

	case gsm.LobbyGameReady:
		// the host is ready: [group id, data, port, ?]; everyone in the room, the host included, gets GAME_STARTED
		id, err := intArg(0)
		if err != nil {
			return nil, nil, err
		}
		data, ok1 := args.At(1)
		port, ok2 := args.At(2)
		if !ok1 || !ok2 {
			return nil, nil, bad("malformed GAME_READY")
		}
		res := gsm.LobbyGroup(req)
		r := l.findRoom(id)
		if r == nil {
			return res, nil, nil
		}
		l.noteGame(r)
		l.Log.Infof("%s started the game of room %d", c.name(), id)
		return res, func() {
			for _, m := range l.roomMembers(id) {
				ip, alt := l.memberAddrs(c, m, id)
				p := port
				if l.Relay != nil && m != c {
					p = l.relayPort(c, m, port)
				}
				l.send(m, gsm.LobbyGameStarted, dl.List{dl.S(strconv.Itoa(id)), l.gameData(r, data, m), p, dl.S(ip), dl.S(alt)})
			}
		}, nil

	case gsm.LobbyStartMatch:
		// rated game, the host starts it: [group id, ?, ?]; everyone in the room gets MATCH_STARTED with its id
		id, err := intArg(0)
		if err != nil {
			return nil, nil, err
		}
		res := gsm.LobbyGroup(req)
		r := l.findRoom(id)
		if r == nil {
			return res, nil, nil
		}
		m := &Match{ID: l.nextMatchID, Room: id, Values: map[string]dl.List{},
			Accounts: map[string]*accounts.Account{}, Disputed: map[string]bool{}, reports: map[string]map[*client]dl.List{}}
		m.Game, _ = r.gameTitle.Str()
		members := l.roomMembers(id)
		for _, member := range members {
			if !member.visitor {
				m.Players = append(m.Players, member.username)
			}
		}
		// account names first: a typed name may be someone else's account name
		for _, member := range members {
			if member.account != nil && !member.visitor {
				m.Accounts[member.account.Name] = member.account
			}
		}
		for _, member := range members {
			if member.account != nil && !member.visitor && m.Accounts[member.typed] == nil {
				m.Accounts[member.typed] = member.account
			}
		}
		l.nextMatchID++
		l.matches[m.ID] = m
		r.matchID = m.ID
		l.Log.Infof("rated match %d started in room %d", m.ID, id)
		return res, func() {
			for _, member := range l.roomMembers(id) {
				l.send(member, gsm.LobbyMatchStarted, dl.List{dl.S(strconv.Itoa(id)), dl.S(strconv.Itoa(m.ID))})
			}
		}, nil

	case gsm.LobbySubmitMatch:
		// a player's results: [match id, ?, [player, max index, count, mask, [values]], ...]
		id, err := intArg(0)
		if err != nil {
			return nil, nil, err
		}
		if m := l.matches[id]; m != nil {
			for _, entry := range args[min(2, len(args)):] {
				e, ok := entry.List()
				if !ok || len(e) < 5 {
					continue
				}
				name, ok1 := e.Str(0)
				values, ok2 := e.List(4)
				if !ok1 || !ok2 {
					continue
				}
				if _, seen := m.Values[name]; !seen {
					m.Order = append(m.Order, name)
				}
				m.Values[name] = values
				if m.reports[name] == nil {
					m.reports[name] = map[*client]dl.List{}
				}
				m.reports[name][c] = values
			}
		}
		return gsm.LobbyGroup(req), nil, nil

	case gsm.LobbyMatchFinish:
		// [group id]; the room gets everyone's submitted results
		id, err := intArg(0)
		if err != nil {
			return nil, nil, err
		}
		res := gsm.LobbyGroup(req)
		r := l.findRoom(id)
		if r == nil || r.matchID == 0 {
			return res, nil, nil
		}
		m := l.matches[r.matchID]
		delete(l.matches, r.matchID)
		r.matchID = 0
		if m == nil {
			return res, nil, nil
		}
		var final dl.List
		if len(m.Order) > 0 {
			results := make([]dl.Value, len(m.Order))
			for i, name := range m.Order {
				results[i] = dl.L(dl.S(name), dl.L(m.Values[name]...))
			}
			final = dl.List{dl.S(strconv.Itoa(m.ID)), dl.S(gsm.ResultSuccess), dl.L(results...)}
		} else {
			final = dl.List{dl.S(strconv.Itoa(m.ID)), dl.S(gsm.ResultFail), dl.Strs("0")}
		}
		m.settle(c)
		l.Log.Infof("rated match %d finished: %v", m.ID, final)
		if l.Results != nil {
			l.Results.MatchFinished(m)
		}
		return res, func() {
			for _, member := range l.roomMembers(id) {
				l.send(member, gsm.LobbyFinalMatchResults, final)
			}
		}, nil

	case gsm.LobbyGameFinish, gsm.LobbyPlayerMatchFinished:
		// end of the game for this player: no reply; the relay stops forwarding for it
		l.endGame(c)
		return nil, nil, nil

	case gsm.LobbyGameConnected, gsm.LobbyPlayerMatchStarted:
		// notifications, no reply
		return nil, nil, nil
	}
	return nil, nil, bad("no request handler for %s lobby message", sub)
}

// relayPort is the port in GAME_STARTED for a viewer: the host's relay port when the host sent one.
func (l *Lobby) relayPort(host, viewer *client, port dl.Value) dl.Value {
	s, ok := port.Str()
	n, ok2 := dl.ParseInt(s)
	if !ok || !ok2 || n == 0 {
		return port
	}
	if a, ok := l.Relay.PeerAddr(host.IP, l.ownHint(host), viewer.IP); ok {
		return dl.S(strconv.Itoa(int(a.Port())))
	}
	return port
}

func (l *Lobby) createRoom(c *client, req *gsm.Message, args dl.List) (*gsm.Message, func(), error) {
	if len(args) < 11 {
		return nil, nil, bad("malformed CREATE_ROOM")
	}
	parent, ok1 := args.Int(0)
	event, ok2 := args.Int(3)
	maxPlayers, ok3 := args.Int(4)
	maxVisitors, ok4 := args.Int(5)
	groupInfo, ok5 := args.Bin(6)
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 {
		return nil, nil, bad("malformed CREATE_ROOM")
	}
	// one room waiting for its creator to join at a time
	l.closeUnjoined(c)
	if len(l.rooms) >= MaxRooms {
		return nil, nil, bad("CREATE_ROOM refused: %d rooms are open", len(l.rooms))
	}
	id := l.nextRoomID
	l.nextRoomID++
	info, err := h5.DeserializeRoomInfo(groupInfo)
	if err != nil {
		return nil, nil, bad("CREATE_ROOM room info: %v", err)
	}
	r := &room{
		id: id, parentID: parent, name: args[1], gameTitle: args[2], eventID: event, maxPlayers: maxPlayers,
		maxVisitors: maxVisitors, groupInfo: groupInfo, password: args[7], gameVersion: args[8], gsVersion: args[9],
		altInfo: args[10], master: c.username, ip: c.IP, creator: c, config: LSMAllInfo, info: info,
	}
	if pw, ok := r.password.Str(); !ok || pw != "" {
		r.config |= LSMPrivate
	}
	// ids are -1 until the server assigns them
	info.GroupID = uint32(id)
	info.LobbySrvID = 1
	l.rooms = append(l.rooms, r)
	l.Log.Infof("%s created room %d", c.name(), id)
	for _, m := range l.lobbyMembers(parent) {
		if m != c && m.roomID == 0 {
			lst, _ := l.roomList(r, m).List()
			l.send(m, gsm.LobbyNewGroup, lst)
		}
	}
	res := gsm.LobbyReply(req, dl.List{dl.S(gsm.ResultSuccess),
		dl.L(dl.S(strconv.Itoa(int(gsm.LobbyCreateRoom))), dl.L(dl.S(strconv.Itoa(id)), r.name, dl.S("1")))})
	return res, nil, nil
}

// configUpdate handles GROUP_CONFIG_UPDATE_RES [group id, flags, values...], the values present by flags.
func (l *Lobby) configUpdate(c *client, req *gsm.Message, args dl.List) (*gsm.Message, func(), error) {
	id, ok1 := args.Int(0)
	flags, ok2 := args.Int(1)
	if !ok1 || !ok2 {
		return nil, nil, bad("malformed GROUP_CONFIG_UPDATE_RES")
	}
	r := l.findRoom(id)
	if r == nil {
		return nil, nil, bad("room %d not found on GROUP_CONFIG_UPDATE_RES", id)
	}
	if r.master != c.username {
		// only the host configures its room
		return nil, nil, bad("%s is not the host of room %d", c.name(), id)
	}
	idx := 2
	next := func() (dl.Value, error) {
		v, ok := args.At(idx)
		if !ok {
			return dl.Value{}, bad("malformed GROUP_CONFIG_UPDATE_RES")
		}
		idx++
		return v, nil
	}
	nextInt := func() (int, error) {
		v, err := next()
		if err != nil {
			return 0, err
		}
		s, _ := v.Str()
		n, ok := dl.ParseInt(s)
		if !ok {
			return 0, bad("malformed GROUP_CONFIG_UPDATE_RES")
		}
		return n, nil
	}
	// any of the dedicated server flags carries their value first
	if flags&updateDSFlags != 0 {
		if _, err := nextInt(); err != nil {
			return nil, nil, err
		}
	}
	if flags&updateMaxPlayers != 0 {
		n, err := nextInt()
		if err != nil {
			return nil, nil, err
		}
		r.maxPlayers = n
	}
	if flags&updateMaxVisitors != 0 {
		n, err := nextInt()
		if err != nil {
			return nil, nil, err
		}
		r.maxVisitors = n
	}
	if flags&updatePassword != 0 {
		v, err := next()
		if err != nil {
			return nil, nil, err
		}
		r.password = v
	}
	if flags&updateGroupInfo != 0 {
		v, err := next()
		if err != nil {
			return nil, nil, err
		}
		b, ok := v.Bin()
		if !ok {
			return nil, nil, bad("GROUP_CONFIG_UPDATE_RES group info is not binary")
		}
		r.groupInfo = b
	}
	if flags&updateAltGroupInfo != 0 {
		v, err := next()
		if err != nil {
			return nil, nil, err
		}
		r.altInfo = v
	}
	info, err := h5.DeserializeRoomInfo(r.groupInfo)
	if err != nil {
		return nil, nil, bad("room %d info: %v", id, err)
	}
	r.info = info
	l.sendRoomUpdate(r, nil)
	return gsm.LobbyReply(req, dl.List{dl.S(gsm.ResultSuccess),
		dl.L(dl.S(strconv.Itoa(int(gsm.LobbyGroupConfigUpdateRes))), dl.Strs(strconv.Itoa(id)))}), nil, nil
}
