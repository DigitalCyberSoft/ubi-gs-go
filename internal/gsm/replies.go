package gsm

import (
	"encoding/binary"
	"strconv"
	"unicode/utf8"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/dl"
)

// Result codes as the game writes them in LOBBY_MSG and PROXY_HANDLER replies.
const (
	ResultSuccess = "38" // GSSUCCESS
	ResultFail    = "39" // GSFAIL
)

// TypeByte is the 1-byte binary holding a request type, field 0 of router-style replies.
func TypeByte(t Type) dl.Value { return dl.B([]byte{byte(t)}) }

// U32 is a 4-byte little-endian binary.
func U32(v uint32) dl.Value { return dl.B(binary.LittleEndian.AppendUint32(nil, v)) }

// Success is a router-style success reply: GSSUCCESS [request type, data...] (0x00428ea0).
func Success(req *Message, data ...dl.Value) *Message {
	return Reply(req, GSSUCCESS, append(dl.List{TypeByte(req.Header.Type)}, data...))
}

// Fail is a router-style refusal: GSFAIL [request type, [reason (u32 LE)]].
func Fail(req *Message, reason uint32) *Message {
	return Reply(req, GSFAIL, dl.List{TypeByte(req.Header.Type), dl.L(U32(reason))})
}

// StillAlive answers a keepalive with an empty one. The game sends one after 30 s of its own silence and
// drops the connection when nothing arrives from the server for 105 s.
func StillAlive(req *Message) *Message {
	return Reply(req, STILLALIVE, nil)
}

// PlayerInfoSizes are the game's buffers for the PLAYERINFO strings, terminator included (0x0042a990).
var PlayerInfoSizes = [7]int{12, 16, 36, 36, 68, 132, 132}

// UsernameSize is the game's username buffer in the proxy JOINWAITMODULE reply (0x0043f450).
const UsernameSize = 16

// PlayerInfo answers PLAYERINFO: [b'\x13', [nick, real name, five placeholders]], each cut to the
// game's fixed buffer.
func PlayerInfo(req *Message, user string) *Message {
	fields := []string{user, user, "findme3", "findme4", "findme5", "findme6", "findme7"}
	for i, f := range fields {
		fields[i] = Cap(f, PlayerInfoSizes[i])
	}
	return Success(req, dl.Strs(fields...))
}

// JoinWaitModule answers the router's JOINWAITMODULE: [b']', [ip, port (u32 LE)]].
func JoinWaitModule(req *Message, ip string, port int) *Message {
	return Success(req, dl.L(dl.S(ip), U32(uint32(port))))
}

// ProxyJoinWaitModule answers the proxy's JOINWAITMODULE: [b']', [user, ip, port]].
func ProxyJoinWaitModule(req *Message, user, ip string, port int) *Message {
	return Success(req, dl.L(dl.S(Cap(user, UsernameSize)), dl.S(ip), dl.S(strconv.Itoa(port))))
}

// UpdateFriend is the UPDATEFRIEND notification [name, status, mood, ?, ?, ?] (0x00428c60). Status 0 is
// online: the game keeps (status == 1) per friend (0x00b210f0) and draws such a friend disabled (0x009d7610).
func UpdateFriend(name string, online bool) *Message {
	status := uint32(1)
	if online {
		status = 0
	}
	return Notification(UPDATEFRIEND, PartyRouter, PartyPlayer,
		dl.List{dl.S(name), U32(status), dl.S(""), U32(0), U32(0), dl.S("")})
}

// LobbyReply is a LOBBY_MSG reply or notification payload: [result, [subtype, data...]].
func LobbyReply(req *Message, data dl.List) *Message {
	return Reply(req, LOBBY_MSG, data)
}

// LobbyResult is the plain success reply [38, [subtype]], echoing the request's subtype field.
func LobbyResult(req *Message) *Message {
	return LobbyReply(req, dl.List{dl.S(ResultSuccess), dl.L(req.Data[0])})
}

// LobbyGroup is the success reply about a group: [38, [subtype, [group id]]], echoing the request's fields.
func LobbyGroup(req *Message) *Message {
	group, _ := req.Data.List(1)
	return LobbyReply(req, dl.List{dl.S(ResultSuccess), dl.L(req.Data[0], dl.L(group[0]))})
}

// LobbyNotification is a LOBBY_MSG notification from the lobby server: [subtype, data].
func LobbyNotification(sub LobbyMsg, data dl.List) *Message {
	return Notification(LOBBY_MSG, PartyServer, PartyPlayer, dl.List{dl.S(strconv.Itoa(int(sub))), dl.L(data...)})
}

// Cap cuts text so it plus a terminator fits a size-byte buffer of the game, on a UTF-8 character
// boundary when the text is UTF-8.
func Cap(text string, size int) string {
	if len(text) < size {
		return text
	}
	return CutBytes(text, size-1)
}

// CutBytes cuts text to at most n bytes. UTF-8 text is cut on a character boundary; other text (the
// game's own code page) is cut at the byte.
func CutBytes(text string, n int) string {
	if len(text) <= n {
		return text
	}
	cut := text[:n]
	if utf8.ValidString(text) {
		for len(cut) > 0 && !utf8.ValidString(cut) {
			cut = cut[:len(cut)-1]
		}
	}
	return cut
}
