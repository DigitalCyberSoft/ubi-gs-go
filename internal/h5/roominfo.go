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
}

// ParsePlayerInfo reads the fields of a player info.
func ParsePlayerInfo(buf []byte) (*PlayerInfo, error) {
	f := fields{buf: buf}
	p := &PlayerInfo{}
	p.Username = clone(f.next(2, -1, "PlayerInfo: Username"))
	ext := f.next(3, 18, "PlayerInfo: ExtIP")
	portIP := f.next(4, -1, "PlayerInfo: LocalPortIP")
	int38 := f.next(5, 4, "PlayerInfo: Int38")
	if f.err != nil {
		return nil, f.err
	}
	var err error
	if p.ExtIP, err = readSockAddr(ext, "PlayerInfo"); err != nil {
		return nil, err
	}
	pf := fields{buf: portIP}
	port := pf.next(2, 2, "PlayerInfo: PortIP.Port")
	ip := pf.next(3, 16, "PlayerInfo: PortIP.IP")
	if pf.err != nil {
		return nil, pf.err
	}
	p.LocalPort = binary.LittleEndian.Uint16(port)
	copy(p.LocalIP[:], ip[0:4])
	copy(p.LocalPad[:], ip[4:16])
	p.Int38 = u32(int38)
	return p, nil
}

// fields writes the player info's fields.
func (p *PlayerInfo) fields() []byte {
	out := appendStream(nil, 2, p.Username)
	out = appendStream(out, 3, writeSockAddr(p.ExtIP))
	portIP := appendStream(nil, 2, binary.LittleEndian.AppendUint16(nil, p.LocalPort))
	portIP = appendStream(portIP, 3, append(p.LocalIP[:], p.LocalPad[:]...))
	out = appendStream(out, 4, portIP)
	return appendStream(out, 5, le32(p.Int38))
}

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
	f := fields{buf: buf}
	r := &RoomInfo{}
	groupID := f.next(2, 4, "RoomInfo: GroupID")
	lobbyID := f.next(3, 4, "RoomInfo: LobbySrvID")
	host := f.next(4, 18, "RoomInfo: host IP")
	hostInit := f.next(6, 1, "RoomInfo: bHostLogicInitialized")
	r.GroupName = clone(f.nextOrEmpty(7, "RoomInfo: GroupName"))
	r.Password = clone(f.nextOrEmpty(8, "RoomInfo: Password"))
	pwd := f.next(9, 1, "RoomInfo: IsPasswordProtected")
	ghost := f.next(10, 1, "RoomInfo: GhostMode")
	quick := f.next(11, 1, "RoomInfo: QuickCombat")
	fast := f.next(12, 1, "RoomInfo: FastCombatTurns")
	timeLimit := f.next(13, 4, "RoomInfo: TimeLimit")
	difficulty := f.next(14, 4, "RoomInfo: DifficultyID")
	mapDesc := f.next(15, -1, "RoomInfo: MapDescriptor")
	teams := f.next(19, -1, "RoomInfo: Teams")
	maxPlayers := f.next(20, 4, "RoomInfo: MaxPlayers")
	mapSize := f.next(21, 4, "RoomInfo: MapSize")
	players := f.next(22, -1, "RoomInfo: PlayerInfos")
	version := f.next(23, 4, "RoomInfo: GameVersion")
	saved := f.next(24, 1, "RoomInfo: IsSaved")
	guid := f.next(25, 16, "RoomInfo: GUID")
	results := f.next(26, 1, "RoomInfo: SendResults")
	options := f.next(27, -1, "RoomInfo: Options")
	arena := f.next(28, 1, "RoomInfo: IsArena")
	checksum := f.next(29, 4, "RoomInfo: HostChecksum")
	adventure := f.next(30, 4, "RoomInfo: AdventureType")
	tag := f.next(31, -1, "RoomInfo: MapDescTag")
	r.MapGoal = clone(f.nextOrEmpty(32, "RoomInfo: MapGoal"))
	r.ArenaMapName = clone(f.nextOrEmpty(33, "RoomInfo: ArenaMapName"))
	i104 := f.next(37, 4, "RoomInfo: Int104")
	i108 := f.next(38, 4, "RoomInfo: Int108")
	speed := f.next(39, 4, "RoomInfo: CombatTurnSpeed")
	f110 := f.next(40, 1, "RoomInfo: Flag110")
	if f.err != nil {
		return nil, f.err
	}
	var err error
	r.GroupID, r.LobbySrvID = u32(groupID), u32(lobbyID)
	if r.HostIP, err = readSockAddr(host, "RoomInfo"); err != nil {
		return nil, err
	}
	r.HostLogicInit = flag(hostInit)
	r.IsPwdProtected, r.GhostMode, r.QuickCombat, r.FastCombatTurns = flag(pwd), flag(ghost), flag(quick), flag(fast)
	r.TimeLimit, r.DifficultyID = u32(timeLimit), u32(difficulty)
	if r.MapDesc, err = readNestedString(mapDesc); err != nil {
		return nil, err
	}
	if r.Teams, err = readUints(teams); err != nil {
		return nil, err
	}
	r.MaxPlayers, r.MapSize = u32(maxPlayers), u32(mapSize)
	if r.PlayerInfos, err = readPlayerInfos(players); err != nil {
		return nil, err
	}
	r.GameVersion = u32(version)
	r.IsSaved = flag(saved)
	copy(r.GUID[:], guid)
	r.SendResultsWait = flag(results)
	if r.Options, err = readOptions(options); err != nil {
		return nil, err
	}
	r.IsArena = flag(arena)
	r.HostChecksum, r.AdventureType = u32(checksum), u32(adventure)
	if r.MapDescTag, err = readNestedString(tag); err != nil {
		return nil, err
	}
	r.Int104, r.Int108, r.CombatTurnSpeed = u32(i104), u32(i108), u32(speed)
	r.Flag110 = flag(f110)
	return r, nil
}

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

func (r *RoomInfo) fields() []byte {
	out := appendStream(nil, 2, le32(r.GroupID))
	out = appendStream(out, 3, le32(r.LobbySrvID))
	out = appendStream(out, 4, writeSockAddr(r.HostIP))
	out = appendStream(out, 6, boolByte(r.HostLogicInit))
	out = appendStream(out, 7, r.GroupName)
	out = appendStream(out, 8, r.Password)
	out = appendStream(out, 9, boolByte(r.IsPwdProtected))
	out = appendStream(out, 10, boolByte(r.GhostMode))
	out = appendStream(out, 11, boolByte(r.QuickCombat))
	out = appendStream(out, 12, boolByte(r.FastCombatTurns))
	out = appendStream(out, 13, le32(r.TimeLimit))
	out = appendStream(out, 14, le32(r.DifficultyID))
	out = appendStream(out, 15, appendStream(nil, 2, r.MapDesc))
	out = appendStream(out, 19, writeUints(r.Teams))
	out = appendStream(out, 20, le32(r.MaxPlayers))
	out = appendStream(out, 21, le32(r.MapSize))
	out = appendStream(out, 22, writePlayerInfos(r.PlayerInfos))
	out = appendStream(out, 23, le32(r.GameVersion))
	out = appendStream(out, 24, boolByte(r.IsSaved))
	out = appendStream(out, 25, r.GUID[:])
	out = appendStream(out, 26, boolByte(r.SendResultsWait))
	out = appendStream(out, 27, writeOptions(r.Options))
	out = appendStream(out, 28, boolByte(r.IsArena))
	out = appendStream(out, 29, le32(r.HostChecksum))
	out = appendStream(out, 30, le32(r.AdventureType))
	out = appendStream(out, 31, appendStream(nil, 2, r.MapDescTag))
	out = appendStream(out, 32, r.MapGoal)
	out = appendStream(out, 33, r.ArenaMapName)
	out = appendStream(out, 37, le32(r.Int104))
	out = appendStream(out, 38, le32(r.Int108))
	out = appendStream(out, 39, le32(r.CombatTurnSpeed))
	return appendStream(out, 40, boolByte(r.Flag110))
}

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
