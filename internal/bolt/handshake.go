package bolt

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Magic opens every Bolt connection.
var Magic = [4]byte{0x60, 0x60, 0xB0, 0x17}

// Version is a Bolt protocol version.
type Version struct{ Major, Minor uint8 }

func (v Version) String() string { return fmt.Sprintf("%d.%d", v.Major, v.Minor) }

// Bytes is the four-byte form the server answers with.
func (v Version) Bytes() [4]byte { return [4]byte{0, 0, v.Minor, v.Major} }

// AtLeast reports whether v is major.minor or later.
func (v Version) AtLeast(major, minor uint8) bool {
	return v.Major > major || v.Major == major && v.Minor >= minor
}

// Supported are the versions Gatehouse speaks, in the worker's sidecar and in
// the broker alike: the ones Memgraph 3 accepts that current drivers offer,
// 5.2 (every 5.x driver) and 4.3.
var Supported = []Version{{Major: 5, Minor: 2}, {Major: 4, Minor: 3}}

// Proposal is one of the client's four handshake slots: a version and how
// many minor versions below it the client also speaks (Bolt 4.3 and later).
// A manifest proposal (Bolt 5.7's version negotiation) is skipped: a server
// may always answer with a plain version from another slot.
type Proposal struct {
	Version
	Range uint8
}

// Handshake is the client's opening: the magic and four proposals.
type Handshake [20]byte

var errMagic = errors.New("bolt: not a Bolt connection")

// ReadHandshake reads the client's opening. When the magic has already been
// read (a listener that sniffed the protocol), pass sniffed true.
func ReadHandshake(r io.Reader, sniffed bool) (Handshake, error) {
	var h Handshake
	copy(h[:4], Magic[:])
	start := 0
	if sniffed {
		start = 4
	}
	if _, err := io.ReadFull(r, h[start:]); err != nil {
		return h, err
	}
	if [4]byte(h[:4]) != Magic {
		return h, errMagic
	}
	return h, nil
}

// Proposals returns the four proposals in the client's order of preference.
func (h Handshake) Proposals() []Proposal {
	out := make([]Proposal, 0, 4)
	for i := range 4 {
		slot := h[4+4*i : 8+4*i]
		major, minor, rng := slot[3], slot[2], slot[1]
		if major == 0 || major == 0xFF {
			continue // empty slot, or a manifest proposal
		}
		out = append(out, Proposal{Version: Version{major, minor}, Range: rng})
	}
	return out
}

// Choose picks the client's most preferred version that supported holds,
// honoring each proposal's range. ok is false when there is none.
func (h Handshake) Choose(supported []Version) (Version, bool) {
	for _, p := range h.Proposals() {
		for _, s := range supported {
			if s.Major == p.Major && s.Minor <= p.Minor && int(p.Minor)-int(s.Minor) <= int(p.Range) {
				best := s
				// The highest supported minor inside this proposal wins.
				for _, other := range supported {
					if other.Major == p.Major && other.Minor <= p.Minor && int(p.Minor)-int(other.Minor) <= int(p.Range) && other.Minor > best.Minor {
						best = other
					}
				}
				return best, true
			}
		}
	}
	return Version{}, false
}

// ClientHandshake is the opening a client sends to propose exactly v.
func ClientHandshake(v Version) []byte {
	out := append([]byte(nil), Magic[:]...)
	out = append(out, 0, 0, v.Minor, v.Major)
	return append(out, make([]byte, 12)...)
}

// ReadVersion reads a server's answer to a handshake. The zero version means
// the server speaks none of the proposals.
func ReadVersion(r io.Reader) (Version, error) {
	var b [4]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return Version{}, err
	}
	if binary.BigEndian.Uint32(b[:]) == 0 {
		return Version{}, nil
	}
	return Version{Major: b[3], Minor: b[2]}, nil
}
