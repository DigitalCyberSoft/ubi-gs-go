package h5

import (
	"encoding/binary"
	"fmt"
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
	// Rest is the fields after these, as the game wrote them
	Rest []byte
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
	p.Rest = clone(f.buf)
	return p, nil
}

// fields writes the player info's fields.
func (p *PlayerInfo) fields() []byte {
	out := appendStream(nil, 2, p.Username)
	out = appendStream(out, 3, writeSockAddr(p.ExtIP))
	portIP := appendStream(nil, 2, binary.LittleEndian.AppendUint16(nil, p.LocalPort))
	portIP = appendStream(portIP, 3, append(p.LocalIP[:], p.LocalPad[:]...))
	out = appendStream(out, 4, portIP)
	out = appendStream(out, 5, le32(p.Int38))
	return append(out, p.Rest...)
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

// The room info fields the lobby reads and rewrites.
const (
	roomGroupID     = 2  // int32, -1 before the server assigns it
	roomLobbySrvID  = 3  // int32
	roomHostIP      = 4  // the host's address
	roomPlayerInfos = 22 // the players' entries, with their addresses
)

// RoomInfo is the game's `CRoomInfo`, the room data in a room's group info. Each game writes its own
// set of fields: Heroes V 2.1 writes 2-33 and 37-40, Hammers of Fate 2-33 and 34-36, Tribes of the East
// 2-11, 13-33 and 34-41. The lobby decodes only the fields it rewrites (the ids, the host's address and
// the players' entries) and keeps every other field as the game wrote it, in the game's order, so a room
// info of any game goes back to the players as it came.
type RoomInfo struct {
	GroupID     uint32
	LobbySrvID  uint32
	HostIP      SockAddr
	PlayerInfos []*PlayerInfo
	// raw is every field in the game's order; the ones above are written from their values
	raw []Stream
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
	seen := map[byte]bool{}
	for len(buf) > 0 {
		s, n, err := readStream(buf)
		if err != nil {
			return nil, fmt.Errorf("RoomInfo: field after %d: %w", len(r.raw), err)
		}
		buf = buf[n:]
		switch s.ID {
		case roomGroupID, roomLobbySrvID, roomHostIP, roomPlayerInfos:
			// rewritten from one value: a second copy would go out unchecked
			if seen[s.ID] {
				return nil, invalid("RoomInfo: repeated field %d", s.ID)
			}
			seen[s.ID] = true
		}
		switch s.ID {
		case roomGroupID, roomLobbySrvID:
			if len(s.Data) != 4 {
				return nil, invalid("RoomInfo: field %d is %d bytes, not 4", s.ID, len(s.Data))
			}
			if s.ID == roomGroupID {
				r.GroupID = u32(s.Data)
			} else {
				r.LobbySrvID = u32(s.Data)
			}
		case roomHostIP:
			if r.HostIP, err = readSockAddr(s.Data, "RoomInfo"); err != nil {
				return nil, err
			}
		case roomPlayerInfos:
			if r.PlayerInfos, err = readPlayerInfos(s.Data); err != nil {
				return nil, err
			}
		}
		r.raw = append(r.raw, Stream{ID: s.ID, Data: clone(s.Data)})
	}
	return r, nil
}

// Field returns the data of the first field with the id, as the game wrote it.
func (r *RoomInfo) Field(id byte) ([]byte, bool) {
	for _, s := range r.raw {
		if s.ID == id {
			return s.Data, true
		}
	}
	return nil, false
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

// Serialize writes the room info as a group info buffer.
func (r *RoomInfo) Serialize() []byte { return wrap(r.fields()) }

func (r *RoomInfo) fields() []byte {
	var out []byte
	for _, s := range r.raw {
		data := s.Data
		switch s.ID {
		case roomGroupID:
			data = le32(r.GroupID)
		case roomLobbySrvID:
			data = le32(r.LobbySrvID)
		case roomHostIP:
			data = writeSockAddr(r.HostIP)
		case roomPlayerInfos:
			data = writePlayerInfos(r.PlayerInfos)
		}
		out = appendStream(out, s.ID, data)
	}
	return out
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
