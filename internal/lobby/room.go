package lobby

import (
	"strconv"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/dl"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/h5"
)

// Lobby service masks (group config flags).
const (
	LSMPrivate        = 0x1
	LSMGroupInfo      = 0x40
	LSMGroupMembers   = 0x80
	LSMChildGroupInfo = 0x100
	LSMAllInfo        = LSMGroupInfo | LSMGroupMembers | LSMChildGroupInfo
)

// Room update flags of GROUP_CONFIG_UPDATE_RES.
const (
	updateDSFlags      = 0x2 | 0x4 | 0x200 // open, score submission, dedicated server: a dsFlags value first
	updateMaxPlayers   = 0x8
	updateMaxVisitors  = 0x10
	updatePassword     = 0x20
	updateGroupInfo    = 0x40
	updateAltGroupInfo = 0x400
)

// Player statuses in member data.
const (
	statusNone          = 0
	statusGameConnected = 2
)

// groupTypeUbiP2P is the group type of a Heroes V room.
const groupTypeUbiP2P = 7

// room is a game room (a group under a lobby).
type room struct {
	id          int
	parentID    int
	name        dl.Value
	gameTitle   dl.Value
	eventID     int
	maxPlayers  int
	maxVisitors int
	groupInfo   []byte
	password    dl.Value
	gameVersion dl.Value
	gsVersion   dl.Value
	altInfo     dl.Value
	master      string
	nbPlayers   int
	nbVisitors  int
	// ip is the host's address (its lobby connection)
	ip     string
	config int
	info   *h5.RoomInfo
	// matchID is the rated match being played, 0 for none
	matchID int
}

// list is the room's group data (`RoomInfo` struct) with the given group info and address.
func (r *room) list(groupInfo []byte, ip string) dl.Value {
	return dl.L(
		dl.S(strconv.Itoa(groupTypeUbiP2P)),
		r.name,
		dl.S(strconv.Itoa(r.id)),
		dl.S("1"),
		dl.S(strconv.Itoa(r.parentID)),
		dl.S(strconv.Itoa(r.config)),
		dl.S("1"),
		dl.S(r.master),
		dl.S(""),
		r.gameTitle, // the game hides rooms of other titles
		dl.B(groupInfo),
		dl.S(strconv.Itoa(r.eventID)),
		dl.S(strconv.Itoa(r.maxPlayers)),
		dl.S(strconv.Itoa(r.nbPlayers)),
		dl.S(strconv.Itoa(r.maxVisitors)),
		dl.S(strconv.Itoa(r.nbVisitors)),
		r.gameVersion,
		r.gsVersion,
		dl.S(ip),
		dl.S(""),
	)
}
