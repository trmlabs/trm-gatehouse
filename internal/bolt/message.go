package bolt

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Message tags. Requests come from the client, summaries and records from
// the server.
const (
	TagHello     byte = 0x01
	TagGoodbye   byte = 0x02
	TagLogon     byte = 0x6A
	TagLogoff    byte = 0x6B
	TagReset     byte = 0x0F
	TagRun       byte = 0x10
	TagBegin     byte = 0x11
	TagCommit    byte = 0x12
	TagRollback  byte = 0x13
	TagDiscard   byte = 0x2F
	TagPull      byte = 0x3F
	TagTelemetry byte = 0x54
	TagRoute     byte = 0x66

	TagSuccess byte = 0x70
	TagRecord  byte = 0x71
	TagIgnored byte = 0x7E
	TagFailure byte = 0x7F
)

// ErrTooLarge is a message past the reader's bound.
var ErrTooLarge = errors.New("bolt: message too large")

var errNotMessage = errors.New("bolt: message is not a structure")

// ReadRaw reads one chunked message and returns its bytes. A chunk header of
// zero ends a message; a zero header with no chunks before it is a keepalive
// (NOOP) and is skipped. max bounds the message, not each chunk.
func ReadRaw(r io.Reader, max int) ([]byte, error) {
	var out []byte
	var header [2]byte
	for {
		if _, err := io.ReadFull(r, header[:]); err != nil {
			if len(out) > 0 && errors.Is(err, io.EOF) {
				return nil, io.ErrUnexpectedEOF
			}
			return nil, err
		}
		n := int(binary.BigEndian.Uint16(header[:]))
		if n == 0 {
			if len(out) == 0 {
				continue
			}
			return out, nil
		}
		if len(out)+n > max {
			return nil, ErrTooLarge
		}
		start := len(out)
		out = append(out, make([]byte, n)...)
		if _, err := io.ReadFull(r, out[start:]); err != nil {
			return nil, err
		}
	}
}

// WriteRaw writes msg as chunks of at most 65535 bytes and the end marker.
func WriteRaw(w io.Writer, msg []byte) error {
	_, err := w.Write(Frame(msg))
	return err
}

// Frame returns msg in chunks with its end marker, ready to write.
func Frame(msg []byte) []byte {
	out := make([]byte, 0, len(msg)+2*(len(msg)/0xFFFF+2))
	for len(msg) > 0 {
		n := min(len(msg), 0xFFFF)
		out = binary.BigEndian.AppendUint16(out, uint16(n))
		out = append(out, msg[:n]...)
		msg = msg[n:]
	}
	return append(out, 0, 0)
}

// Tag returns a raw message's tag without decoding its fields, so a relay can
// pass records through untouched.
func Tag(raw []byte) (byte, error) {
	if len(raw) < 2 || raw[0] < 0xB0 || raw[0] > 0xBF {
		return 0, errNotMessage
	}
	return raw[1], nil
}

// Decode reads a raw message as a structure.
func Decode(raw []byte) (*Structure, error) {
	v, err := Unpack(raw)
	if err != nil {
		return nil, err
	}
	s, ok := v.(*Structure)
	if !ok {
		return nil, errNotMessage
	}
	return s, nil
}

// Encode packs a message.
func Encode(tag byte, fields ...any) ([]byte, error) {
	return Pack(&Structure{Tag: tag, Fields: fields})
}

// Map returns field i as a map, or nil when it is absent. A field of another
// type is an error.
func (s *Structure) Map(i int) (map[string]any, error) {
	if i >= len(s.Fields) || s.Fields[i] == nil {
		return nil, nil
	}
	m, ok := s.Fields[i].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("bolt: field %d of message 0x%02X is not a map", i, s.Tag)
	}
	return m, nil
}

// Success is a SUCCESS message carrying metadata.
func Success(metadata map[string]any) []byte {
	if metadata == nil {
		metadata = map[string]any{}
	}
	b, _ := Encode(TagSuccess, metadata)
	return b
}

// Failure is a FAILURE message. Drivers read the second dotted part of code
// as the classification (ClientError, TransientError, DatabaseError), so a
// code shaped "Gatehouse.TransientError.X.Y" is retried and
// "Gatehouse.ClientError.X.Y" is not. Bolt 5.7 and later read the GQL fields;
// earlier versions ignore them.
func Failure(code, message string) []byte {
	b, _ := Encode(TagFailure, map[string]any{"code": code, "message": message})
	return b
}

// Ignored is an IGNORED message, the answer to every request after a failure
// until RESET.
func Ignored() []byte {
	b, _ := Encode(TagIgnored)
	return b
}
