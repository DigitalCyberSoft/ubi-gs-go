package proxy

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// The profile data is what the game's structure saver (CStructureSaver) writes for the profile
// (NUI::CMPProfileSaver, 0x009d81b0; read back at 0x009f6770): sections, each [id][length][data],
// where the length is a byte holding length*2, or, when length*2 doesn't fit a byte, 4 bytes
// (little-endian) holding length*2|1. Chunks inside a section have the same format.
//
//	section 4: the saver's version, an int32, 4
//	section 1: the data
//	    chunk 1: the profile (0x009d8440)
//	        chunk 2: the avatar, an int32 (0x1003c by default, 0x008d0780)
//	        chunk 4: the "Additional Information" text, UTF-16LE, no terminator, at most 255
//	                 characters (its edit box's MaxLength)
//	sections 0, 2 and 5: the saver's object table, object data and type map, empty for a profile
//
// The rest of the screen (ratings, games, races) comes from the ladder. The game saves when the player
// changes the text and leaves the screen (OK or Back, 0x009f3650): only its own profile, and only
// from the lobby.

// MaxProfileSize is the largest profile data accepted; the game's own is at most 543 bytes.
const MaxProfileSize = 1024

// MaxProfileText is the most characters in the profile's text (the edit box's MaxLength).
const MaxProfileText = 255

const (
	profileVersion = 4       // the structure saver's version (0x010cfa58)
	DefaultAvatar  = 0x1003c // the avatar of a new profile
)

// Profile is a player's profile data.
type Profile struct {
	Avatar int32
	Text   []byte // UTF-16LE
}

// DefaultProfile is a new player's profile: the default avatar, no text.
var DefaultProfile = Profile{Avatar: DefaultAvatar}.Encode()

func chunk(id byte, data []byte) []byte {
	out := []byte{id}
	if n := len(data) * 2; n < 0x100 {
		out = append(out, byte(n))
	} else {
		out = binary.LittleEndian.AppendUint32(out, uint32(n)|1)
	}
	return append(out, data...)
}

// Encode returns the profile data as the game writes it.
func (p Profile) Encode() []byte {
	fields := append(chunk(2, binary.LittleEndian.AppendUint32(nil, uint32(p.Avatar))), chunk(4, p.Text)...)
	var out []byte
	out = append(out, chunk(4, binary.LittleEndian.AppendUint32(nil, profileVersion))...)
	out = append(out, chunk(1, chunk(1, fields))...)
	out = append(out, chunk(0, nil)...)
	out = append(out, chunk(2, nil)...)
	return append(out, chunk(5, nil)...)
}

// chunks splits data into its chunks, each id at most once and one of allowed.
func chunks(data []byte, allowed ...byte) (map[byte][]byte, error) {
	found := map[byte][]byte{}
	for pos := 0; pos < len(data); {
		if pos+2 > len(data) {
			return nil, errors.New("truncated chunk header")
		}
		id, n := data[pos], uint32(data[pos+1])
		pos += 2
		if n&1 != 0 {
			if pos+3 > len(data) {
				return nil, errors.New("truncated chunk length")
			}
			n = binary.LittleEndian.Uint32(data[pos-1:])
			pos += 3
		}
		n >>= 1
		if uint64(pos)+uint64(n) > uint64(len(data)) {
			return nil, errors.New("truncated chunk")
		}
		ok := false
		for _, a := range allowed {
			ok = ok || a == id
		}
		if _, seen := found[id]; !ok || seen {
			return nil, fmt.Errorf("unexpected chunk %d", id)
		}
		found[id] = data[pos : pos+int(n)]
		pos += int(n)
	}
	return found, nil
}

// DecodeProfile reads profile data, and fails unless it is a profile and nothing else. A missing
// avatar or text reads as the default, as in the game.
func DecodeProfile(data []byte) (Profile, error) {
	p := Profile{Avatar: DefaultAvatar}
	sections, err := chunks(data, 0, 1, 2, 4, 5)
	if err != nil {
		return p, err
	}
	if v := sections[4]; len(v) != 4 || binary.LittleEndian.Uint32(v) != profileVersion {
		return p, errors.New("not version 4")
	}
	if len(sections[0]) != 0 || len(sections[2]) != 0 || len(sections[5]) != 0 {
		return p, errors.New("objects in a profile")
	}
	outer, err := chunks(sections[1], 1)
	if err != nil {
		return p, err
	}
	fields, err := chunks(outer[1], 2, 4)
	if err != nil {
		return p, err
	}
	if a, ok := fields[2]; ok {
		if len(a) != 4 {
			return p, errors.New("avatar size")
		}
		p.Avatar = int32(binary.LittleEndian.Uint32(a))
	}
	if t := fields[4]; len(t)%2 != 0 || len(t) > MaxProfileText*2 {
		return p, errors.New("text size")
	}
	p.Text = append([]byte(nil), fields[4]...)
	return p, nil
}
