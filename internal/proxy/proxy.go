// Package proxy implements the proxy and its wait module, which serve the game's proxy modules:
// ladderquery (ratings, code 1281) and persistantdata (the Profile screen, codes 1025 and 1026).
package proxy

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/accounts"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/dl"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/env"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/gsm"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/logx"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/netsrv"
)

// Module data codes.
const (
	CodeLadderQuery = "1281"
	CodeProfileGet  = "1025"
	CodeProfileSet  = "1026"
)

// MaxProfileSize is the largest profile blob stored.
const MaxProfileSize = 64 * 1024

// ErrModuleUnavailable is returned for module data this server has no service for; closing the
// module's connection fails the request and the game carries on.
var ErrModuleUnavailable = errors.New("no service for module request")

// Proxy serves the proxy and its wait module.
type Proxy struct {
	Env   *env.Env
	Log   *logx.Logger
	WMLog *logx.Logger
}

type client struct {
	*netsrv.GSClient
	username string
}

func str(l dl.List, i int, what string) (string, error) {
	s, ok := l.Str(i)
	if !ok {
		return "", fmt.Errorf("malformed request: no %s", what)
	}
	return s, nil
}

// ServeProxy serves a proxy connection: the module login handshake.
func (p *Proxy) ServeProxy(conn *netsrv.Conn) {
	c := &client{GSClient: &netsrv.GSClient{Conn: conn, Log: p.Log}}
	c.ServeGS(func(req *gsm.Message) error {
		var res *gsm.Message
		var err error
		switch req.Header.Type {
		case gsm.STILLALIVE:
			res = gsm.StillAlive(req)
		case gsm.JOINWAITMODULE:
			if c.username == "" {
				return errors.New("JOINWAITMODULE before LOGIN")
			}
			res = gsm.ProxyJoinWaitModule(req, c.username, p.Env.Advertise(conn), p.Env.Ports.ProxyWM)
		case gsm.LOGIN:
			// [user, game name]
			if c.username, err = str(req.Data, 0, "user name"); err != nil {
				return err
			}
			res = gsm.Success(req, dl.L())
		case gsm.KEY_EXCHANGE:
			res, err = c.Session.KeyExchange(req)
		default:
			return fmt.Errorf("no request handler for %s messages", req.Header.Type)
		}
		if err != nil {
			return err
		}
		c.SendMsg(res)
		return nil
	})
}

// ServeWaitModule serves a proxy wait module connection: the module data.
func (p *Proxy) ServeWaitModule(conn *netsrv.Conn) {
	c := &client{GSClient: &netsrv.GSClient{Conn: conn, Log: p.WMLog}}
	c.ServeGS(func(req *gsm.Message) error {
		var res *gsm.Message
		var err error
		switch req.Header.Type {
		case gsm.STILLALIVE:
			res = gsm.StillAlive(req)
		case gsm.LOGINWAITMODULE:
			// the name typed at login; the router knows its account
			typed, err := str(req.Data, 0, "user name")
			if err != nil {
				return err
			}
			c.username = p.Env.Accounts.AccountName(typed, c.IP)
			res = gsm.Success(req, dl.L())
		case gsm.PROXY_HANDLER:
			res, err = p.moduleData(c, req)
		case gsm.KEY_EXCHANGE:
			res, err = c.Session.KeyExchange(req)
		default:
			return fmt.Errorf("no request handler for %s messages", req.Header.Type)
		}
		if err != nil {
			if errors.Is(err, ErrModuleUnavailable) {
				p.WMLog.Infof("%v, closing", err)
			}
			return err
		}
		c.SendMsg(res)
		return nil
	})
}

// moduleData answers module data [code, seq, payload] on the same connection with [code, seq, result]
// (0x0043f790). The game matches the reply by seq.
func (p *Proxy) moduleData(c *client, req *gsm.Message) (*gsm.Message, error) {
	code, ok := req.Data.Str(0)
	seq, ok2 := req.Data.At(1)
	payload, ok3 := req.Data.At(2)
	if !ok || !ok2 || !ok3 {
		if !ok && len(req.Data) >= 3 {
			return nil, fmt.Errorf("%w %v", ErrModuleUnavailable, req.Data[0])
		}
		return nil, errors.New("malformed module data")
	}
	body, _ := payload.List()
	var result dl.Value
	var err error
	switch code {
	case CodeLadderQuery:
		result, err = p.ladderQuery(c, body)
	case CodeProfileGet:
		result, err = p.profileGet(c, body)
	case CodeProfileSet:
		result, err = p.profileSet(c, body)
	default:
		return nil, fmt.Errorf("%w %s", ErrModuleUnavailable, code)
	}
	if err != nil {
		return nil, err
	}
	res := gsm.Reply(req, req.Header.Type, dl.List{dl.S(code), seq, result})
	return res, nil
}

// player is the account a request is about: the asking game's own typed name, or another player's
// account name.
func (p *Proxy) player(name, ip string) (*accounts.Account, error) {
	a, err := p.Env.Accounts.Session(name, ip)
	if err != nil || a != nil {
		return a, err
	}
	return p.Env.Accounts.Find(name)
}

func failure(reason string) dl.Value { return dl.L(dl.S(gsm.ResultFail), dl.Strs(reason)) }

// LadderKey is the ladder a game's ladder id names.
func LadderKey(game, ladderID string) string { return game + "/" + ladderID }

// ladderQuery answers ['1', [reqId, game, ladderId, '0', [type, args], [filters, sort, fields]]]:
// success ['38', ['1', [reqId, '1', columns, rows]]] (parsed at 0x00432b50; the game reads row 0
// only), or failure ['39', [reason]], after which the game shows N/A. The game takes the first field
// of the result for the id of the request it answers (0x004325c0) and ignores a reply to a request
// it isn't waiting for, so the Profile screen, whose query is never a session's first, waited forever
// while that field was always 1.
func (p *Proxy) ladderQuery(c *client, body dl.List) (dl.Value, error) {
	request, ok := body.List(1)
	if !ok {
		return dl.Value{}, errors.New("malformed ladder query")
	}
	requestID, ok0 := request.Str(0)
	game, ok1 := request.Str(1)
	ladderID, ok2 := request.Str(2)
	query, ok3 := request.List(4)
	if !ok0 || !ok1 || !ok2 || !ok3 || len(query) != 2 {
		return dl.Value{}, errors.New("malformed ladder query")
	}
	queryType, _ := query[0].Str()
	args, _ := query[1].List()
	// pivot queries (1, 7): [user, count]
	if (queryType != "1" && queryType != "7") || len(args) == 0 {
		return failure("0"), nil
	}
	name, ok := args.Str(0)
	if !ok {
		return failure("0"), nil
	}
	account, err := p.player(name, c.IP)
	if err != nil {
		return dl.Value{}, err
	}
	if account == nil {
		return failure("0"), nil
	}
	stats, err := p.Env.Accounts.LadderStats(*account, LadderKey(game, ladderID))
	if err != nil {
		return dl.Value{}, err
	}
	values := Stats(stats)
	columns := make([]dl.Value, len(Fields))
	row := make([]string, len(Fields))
	for i, f := range Fields {
		columns[i] = dl.Strs(f, f)
		row[i] = strconv.FormatInt(values[f], 10)
	}
	return dl.L(dl.S(gsm.ResultSuccess), dl.L(dl.S("1"), dl.L(dl.S(requestID), dl.S("1"), dl.L(columns...), dl.L(dl.Strs(row...))))), nil
}

// profileGet answers [game, '0', user, '0', 'PUBLIC'] with ['38', [blob, length]] (0x0042b2d0), or
// ['39', ['1']] when nothing is stored.
func (p *Proxy) profileGet(c *client, body dl.List) (dl.Value, error) {
	game, ok1 := body.Str(0)
	user, ok2 := body.Str(2)
	if !ok1 || !ok2 {
		return dl.Value{}, errors.New("malformed profile request")
	}
	account, err := p.player(user, c.IP)
	if err != nil {
		return dl.Value{}, err
	}
	var data []byte
	if account != nil {
		if data, err = p.Env.Accounts.Profile(*account, game); err != nil {
			return dl.Value{}, err
		}
	}
	if data == nil {
		return failure("1"), nil
	}
	return dl.L(dl.S(gsm.ResultSuccess), dl.L(dl.B(data), dl.S(strconv.Itoa(len(data))))), nil
}

// profileSet stores [game, '0', own user, '0', 'PUBLIC', blob, length]: ['38', []] (0x0042b1b0), or
// ['39', ['0']]. Only the player's own data is written.
func (p *Proxy) profileSet(c *client, body dl.List) (dl.Value, error) {
	game, ok1 := body.Str(0)
	user, ok2 := body.Str(2)
	data, ok3 := body.Bin(5)
	if !ok1 || !ok2 || !ok3 {
		return dl.Value{}, errors.New("malformed profile save")
	}
	account, err := p.Env.Accounts.Session(user, c.IP)
	if err != nil {
		return dl.Value{}, err
	}
	if account == nil || len(data) > MaxProfileSize {
		return failure("0"), nil
	}
	if err := p.Env.Accounts.SetProfile(*account, game, data); err != nil {
		return dl.Value{}, err
	}
	p.WMLog.Infof("stored the profile of %s (%d bytes)", account.Name, len(data))
	return dl.L(dl.S(gsm.ResultSuccess), dl.L()), nil
}
