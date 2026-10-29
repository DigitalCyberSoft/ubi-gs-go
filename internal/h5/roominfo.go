package h5

import (
	"encoding/binary"
	"net/netip"
)

// SockAddr is a `sockaddr_in` (16 bytes): family (LE), port and IPv4 address (network order), padding.
type SockAddr struct {
	Family uint16
	Port   uint16
	IP     [4]byte
	Zero   [8]byte
}

func parseSockAddr(b []byte) SockAddr {
	var a SockAddr
	a.Family = binary.LittleEndian.Uint16(b[0:2])
	a.Port = binary.BigEndian.Uint16(b[2:4])
	copy(a.IP[:], b[4:8])
	copy(a.Zero[:], b[8:16])
	return a
}

func (a SockAddr) bytes() []byte {
	out := binary.LittleEndian.AppendUint16(nil, a.Family)
	out = binary.BigEndian.AppendUint16(out, a.Port)
	out = append(out, a.IP[:]...)
	return append(out, a.Zero[:]...)
}

// Addr returns the IPv4 address.
func (a SockAddr) Addr() netip.Addr { return netip.AddrFrom4(a.IP) }

// readSockAddr reads the address nested in field 2 of an 18-byte field (room and player info).
func readSockAddr(b []byte, name string) (SockAddr, error) {
	s, _, err := readStream(b)
	if err != nil {
		return SockAddr{}, err
	}
	if s.ID != 2 || len(s.Data) != 16 {
		return SockAddr{}, invalid("%s: missing/invalid field - HostIP (2)", name)
	}
	return parseSockAddr(s.Data), nil
}

func writeSockAddr(a SockAddr) []byte { return appendStream(nil, 2, a.bytes()) }

// PlayerInfo is the game's `PlayerInfo`: one entry of the room info's player list, and the lobby member
// data the game sets with SET_PLAYER_INFO.
type PlayerInfo struct {
	// Key is the id written before the entry in the room info's list; nil numbers the entries from 0.
	Key       *uint32
	Username  []byte
	ExtIP     SockAddr // public address
	LocalPort uint16
	LocalIP   [4]byte // private address
	LocalPad  [12]byte
	Int38     uint32 // unknown
	layout    []field
}

// playerFields are the fields of 1.60's player info, in its order.
var playerFields = []codec[PlayerInfo]{
	bytesField(2, "Username", func(p *PlayerInfo) *[]byte { return &p.Username }),
	{id: 3, name: "ExtIP", size: 18, required: true,
		read:  func(p *PlayerInfo, b []byte) (err error) { p.ExtIP, err = readSockAddr(b, "PlayerInfo"); return },
		write: func(p *PlayerInfo) []byte { return writeSockAddr(p.ExtIP) }},
	{id: 4, name: "LocalPortIP", size: -1, required: true, read: readLocalPortIP, write: writeLocalPortIP},
	u32Field(5, "Int38", func(p *PlayerInfo) *uint32 { return &p.Int38 }),
}

// ParsePlayerInfo reads the fields of a player info.
func ParsePlayerInfo(buf []byte) (*PlayerInfo, error) {
	p := &PlayerInfo{}
	var err error
	if p.layout, err = readFields(buf, p, playerFields, "PlayerInfo"); err != nil {
		return nil, err
	}
	return p, nil
}

func readLocalPortIP(p *PlayerInfo, b []byte) error {
	f := fields{buf: b}
	port := f.next(2, 2, "PlayerInfo: PortIP.Port")
	ip := f.next(3, 16, "PlayerInfo: PortIP.IP")
	if f.err != nil {
		return f.err
	}
	p.LocalPort = binary.LittleEndian.Uint16(port)
	copy(p.LocalIP[:], ip[0:4])
	copy(p.LocalPad[:], ip[4:16])
	return nil
}

func writeLocalPortIP(p *PlayerInfo) []byte {
	out := appendStream(nil, 2, binary.LittleEndian.AppendUint16(nil, p.LocalPort))
	return appendStream(out, 3, append(p.LocalIP[:], p.LocalPad[:]...))
}

// fields writes the player info's fields.
func (p *PlayerInfo) fields() []byte { return writeFields(p, p.layout, playerFields) }

// Serialize writes the player info as a complete structure (SET_PLAYER_INFO's member data).
func (p *PlayerInfo) Serialize() []byte { return wrap(p.fields()) }

// DeserializePlayerInfo reads a complete player info structure, as SET_PLAYER_INFO carries it.
func DeserializePlayerInfo(buf []byte) (*PlayerInfo, error) {
	data, err := unwrap(buf)
	if err != nil {
		return nil, err
	}
	return ParsePlayerInfo(data)
}

// WithoutAddresses returns a copy with the public and private addresses zeroed.
func (p *PlayerInfo) WithoutAddresses() *PlayerInfo {
	c := *p
	c.Username = clone(p.Username)
	c.ExtIP.IP = [4]byte{}
	c.LocalIP = [4]byte{}
	return &c
}

// Option is a room option: a key with an integer and a UTF-16 string value.
type Option struct {
	Key   []byte
	Int   uint32
	Value []byte // UTF-16LE
}

// RoomInfo is the game's `CRoomInfo`, the room data in a room's group info.
type RoomInfo struct {
	GroupID         uint32 // idx 2 (int32, -1 before the server assigns it)
	LobbySrvID      uint32 // idx 3
	HostIP          SockAddr
	HostLogicInit   bool   // idx 6
	GroupName       []byte // idx 7, UTF-16LE
	Password        []byte // idx 8, UTF-16LE
	IsPwdProtected  bool   // idx 9
	GhostMode       bool   // idx 10
	QuickCombat     bool   // idx 11
	FastCombatTurns bool   // idx 12
	TimeLimit       uint32 // idx 13 (int32)
	DifficultyID    uint32 // idx 14
	MapDesc         []byte // idx 15, map descriptor path (AdvMapDesc)
	Teams           []uint32
	MaxPlayers      uint32 // idx 20
	MapSize         uint32 // idx 21
	PlayerInfos     []*PlayerInfo
	GameVersion     uint32 // idx 23
	IsSaved         bool   // idx 24
	GUID            [16]byte
	SendResultsWait bool // idx 26
	Options         []Option
	IsArena         bool   // idx 28
	HostChecksum    uint32 // idx 29
	AdventureType   uint32 // idx 30
	MapDescTag      []byte // idx 31
	MapGoal         []byte // idx 32
	ArenaMapName    []byte // idx 33
	Int104          uint32 // idx 37
	Int108          uint32 // idx 38
	CombatTurnSpeed uint32 // idx 39
	Flag110         bool   // idx 40
	layout          []field
}

// roomFields are the fields of 1.60's room info, in its order. The lobby sets the ids and changes the
// addresses, the host's and the players'.
var roomFields = []codec[RoomInfo]{
	must(u32Field(2, "GroupID", func(r *RoomInfo) *uint32 { return &r.GroupID })),
	must(u32Field(3, "LobbySrvID", func(r *RoomInfo) *uint32 { return &r.LobbySrvID })),
	{id: 4, name: "host IP", size: 18, required: true,
		read:  func(r *RoomInfo, b []byte) (err error) { r.HostIP, err = readSockAddr(b, "RoomInfo"); return },
		write: func(r *RoomInfo) []byte { return writeSockAddr(r.HostIP) }},
	boolField(6, "bHostLogicInitialized", func(r *RoomInfo) *bool { return &r.HostLogicInit }),
	bytesField(7, "GroupName", func(r *RoomInfo) *[]byte { return &r.GroupName }),
	bytesField(8, "Password", func(r *RoomInfo) *[]byte { return &r.Password }),
	boolField(9, "IsPasswordProtected", func(r *RoomInfo) *bool { return &r.IsPwdProtected }),
	boolField(10, "GhostMode", func(r *RoomInfo) *bool { return &r.GhostMode }),
	boolField(11, "QuickCombat", func(r *RoomInfo) *bool { return &r.QuickCombat }),
	boolField(12, "FastCombatTurns", func(r *RoomInfo) *bool { return &r.FastCombatTurns }),
	u32Field(13, "TimeLimit", func(r *RoomInfo) *uint32 { return &r.TimeLimit }),
	u32Field(14, "DifficultyID", func(r *RoomInfo) *uint32 { return &r.DifficultyID }),
	nestedField(15, "MapDescriptor", func(r *RoomInfo) *[]byte { return &r.MapDesc }),
	{id: 19, name: "Teams", size: -1,
		read:  func(r *RoomInfo, b []byte) (err error) { r.Teams, err = readUints(b); return },
		write: func(r *RoomInfo) []byte { return writeUints(r.Teams) }},
	u32Field(20, "MaxPlayers", func(r *RoomInfo) *uint32 { return &r.MaxPlayers }),
	u32Field(21, "MapSize", func(r *RoomInfo) *uint32 { return &r.MapSize }),
	{id: 22, name: "PlayerInfos", size: -1, required: true,
		read:  func(r *RoomInfo, b []byte) (err error) { r.PlayerInfos, err = readPlayerInfos(b); return },
		write: func(r *RoomInfo) []byte { return writePlayerInfos(r.PlayerInfos) }},
	u32Field(23, "GameVersion", func(r *RoomInfo) *uint32 { return &r.GameVersion }),
	boolField(24, "IsSaved", func(r *RoomInfo) *bool { return &r.IsSaved }),
	{id: 25, name: "GUID", size: 16,
		read:  func(r *RoomInfo, b []byte) error { copy(r.GUID[:], b); return nil },
		write: func(r *RoomInfo) []byte { return r.GUID[:] }},
	boolField(26, "SendResults", func(r *RoomInfo) *bool { return &r.SendResultsWait }),
	{id: 27, name: "Options", size: -1,
		read:  func(r *RoomInfo, b []byte) (err error) { r.Options, err = readOptions(b); return },
		write: func(r *RoomInfo) []byte { return writeOptions(r.Options) }},
	boolField(28, "IsArena", func(r *RoomInfo) *bool { return &r.IsArena }),
	u32Field(29, "HostChecksum", func(r *RoomInfo) *uint32 { return &r.HostChecksum }),
	u32Field(30, "AdventureType", func(r *RoomInfo) *uint32 { return &r.AdventureType }),
	nestedField(31, "MapDescTag", func(r *RoomInfo) *[]byte { return &r.MapDescTag }),
	bytesField(32, "MapGoal", func(r *RoomInfo) *[]byte { return &r.MapGoal }),
	bytesField(33, "ArenaMapName", func(r *RoomInfo) *[]byte { return &r.ArenaMapName }),
	u32Field(37, "Int104", func(r *RoomInfo) *uint32 { return &r.Int104 }),
	u32Field(38, "Int108", func(r *RoomInfo) *uint32 { return &r.Int108 }),
	u32Field(39, "CombatTurnSpeed", func(r *RoomInfo) *uint32 { return &r.CombatTurnSpeed }),
	boolField(40, "Flag110", func(r *RoomInfo) *bool { return &r.Flag110 }),
}

// DeserializeRoomInfo reads a room's group info buffer.
func DeserializeRoomInfo(buf []byte) (*RoomInfo, error) {
	data, err := unwrap(buf)
	if err != nil {
		return nil, err
	}
	return parseRoomInfo(data)
}

func parseRoomInfo(buf []byte) (*RoomInfo, error) {
	r := &RoomInfo{}
	var err error
	if r.layout, err = readFields(buf, r, roomFields, "RoomInfo"); err != nil {
		return nil, err
	}
	return r, nil
}

// Differences describes how the room info's fields differ from 1.60's: the fields kept as they came, and
// 1.60's fields it doesn't have. It is empty for a room info laid out like 1.60's.
func (r *RoomInfo) Differences() string { return differences(r.layout, roomFields) }

// readNestedString reads a string nested in an id 2 field (an empty field of any id is an empty string).
func readNestedString(buf []byte) ([]byte, error) {
	s, _, err := readStream(buf)
	if err != nil {
		return nil, err
	}
	if len(s.Data) == 0 {
		return []byte{}, nil
	}
	if s.ID != 2 {
		return nil, invalid("RoomInfo: missing/invalid field - String.Value (2)")
	}
	return clone(s.Data), nil
}

// readUints reads a count (field 1, ignored) and a list of u32 (field 2).
func readUints(buf []byte) ([]uint32, error) {
	f := fields{buf: buf}
	f.next(1, 4, "RoomInfo: IDs.Count")
	entries := f.next(2, -1, "RoomInfo: IDs.Entries")
	if f.err != nil {
		return nil, f.err
	}
	if len(entries)%4 != 0 {
		return nil, invalid("RoomInfo: unpadded id list")
	}
	out := make([]uint32, 0, len(entries)/4)
	for i := 0; i < len(entries); i += 4 {
		out = append(out, u32(entries[i:]))
	}
	return out, nil
}

// readPlayerInfos reads count (3), an unknown value (4), the keys (1) and the entries (2).
func readPlayerInfos(buf []byte) ([]*PlayerInfo, error) {
	f := fields{buf: buf}
	countB := f.next(3, 4, "RoomInfo: PlayerInfos.ModeSetting1")
	f.next(4, 4, "RoomInfo: PlayerInfos.ModeSetting2")
	if f.err != nil {
		return nil, f.err
	}
	count := u32(countB)
	var keys []uint32
	for i := uint32(0); i < count; i++ {
		k := f.next(1, 4, "RoomInfo: PlayerInfos.Count")
		if f.err != nil {
			return nil, f.err
		}
		keys = append(keys, u32(k))
	}
	infos := make([]*PlayerInfo, 0, len(keys))
	for _, key := range keys {
		data := f.next(2, -1, "RoomInfo: PlayerInfos.PlayerInfo")
		if f.err != nil {
			return nil, f.err
		}
		info, err := ParsePlayerInfo(data)
		if err != nil {
			return nil, err
		}
		k := key
		info.Key = &k
		infos = append(infos, info)
	}
	return infos, nil
}

// readOptions reads count (3), an unknown value (4, 13), the keys (1) and the values (2).
func readOptions(buf []byte) ([]Option, error) {
	f := fields{buf: buf}
	countB := f.next(3, 4, "RoomInfo: PlayerInfos.ModeSetting1")
	f.next(4, 4, "RoomInfo: PlayerInfos.ModeSetting2")
	if f.err != nil {
		return nil, f.err
	}
	count := u32(countB)
	var keys [][]byte
	for i := uint32(0); i < count; i++ {
		k := f.next(1, -1, "RoomInfo: Options.Key")
		if f.err != nil {
			return nil, f.err
		}
		keys = append(keys, clone(k))
	}
	var options []Option
	// a repeated key keeps its first position and takes the last value, like a dict; the index keeps
	// this linear, as the room info comes from any lobby client and can hold thousands of keys
	index := map[string]int{}
	for _, key := range keys {
		data := f.next(2, -1, "RoomInfo: Options.IntValue")
		if f.err != nil {
			return nil, f.err
		}
		vf := fields{buf: data}
		iv := vf.next(2, -1, "RoomInfo: Options.IntValue")
		sv := vf.next(3, -1, "RoomInfo: Options.StringValue")
		if vf.err != nil {
			return nil, vf.err
		}
		if len(iv) < 4 {
			return nil, invalid("RoomInfo: Options.IntValue too short")
		}
		opt := Option{Key: key, Int: u32(iv), Value: clone(sv)}
		if i, ok := index[string(key)]; ok {
			options[i] = opt
			continue
		}
		index[string(key)] = len(options)
		options = append(options, opt)
	}
	return options, nil
}

// Serialize writes the room info as a group info buffer.
func (r *RoomInfo) Serialize() []byte { return wrap(r.fields()) }

func (r *RoomInfo) fields() []byte { return writeFields(r, r.layout, roomFields) }

func writeUints(list []uint32) []byte {
	out := appendStream(nil, 1, le32(uint32(len(list))))
	var data []byte
	for _, v := range list {
		data = binary.LittleEndian.AppendUint32(data, v)
	}
	return appendStream(out, 2, data)
}

func writePlayerInfos(infos []*PlayerInfo) []byte {
	out := appendStream(nil, 3, le32(uint32(len(infos))))
	out = appendStream(out, 4, le32(13))
	var data []byte
	for i, info := range infos {
		data = appendStream(data, 2, info.fields())
		key := uint32(i)
		if info.Key != nil {
			key = *info.Key
		}
		out = appendStream(out, 1, le32(key))
	}
	return append(out, data...)
}

func writeOptions(options []Option) []byte {
	out := appendStream(nil, 3, le32(uint32(len(options))))
	out = appendStream(out, 4, le32(13))
	var data []byte
	for _, o := range options {
		out = appendStream(out, 1, o.Key)
		value := appendStream(nil, 2, le32(o.Int))
		value = appendStream(value, 3, o.Value)
		data = appendStream(data, 2, value)
	}
	return append(out, data...)
}

// WithoutAddresses returns a copy with the host's and every player's addresses zeroed, for players who
// aren't in the room.
func (r *RoomInfo) WithoutAddresses() *RoomInfo {
	c := *r
	c.HostIP.IP = [4]byte{}
	c.PlayerInfos = make([]*PlayerInfo, len(r.PlayerInfos))
	for i, p := range r.PlayerInfos {
		c.PlayerInfos[i] = p.WithoutAddresses()
	}
	return &c
}
