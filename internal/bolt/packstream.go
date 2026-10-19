// Package bolt reads and writes the Bolt protocol that Neo4j-compatible graph
// databases such as Memgraph speak: the version handshake, chunked messages
// and the PackStream values inside them. It holds no policy; the database
// broker and the worker sidecar decide what to do with each message.
package bolt

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// Structure is a PackStream structure: a message (HELLO, RUN, SUCCESS, ...)
// or a value such as a node, a date or a point.
type Structure struct {
	Tag    byte
	Fields []any
}

// Values decode to nil, bool, int64, float64, string, []byte, []any,
// map[string]any or *Structure, and only those encode.

// maxDepth bounds nesting so a hostile value cannot exhaust the stack. A
// message's size is bounded by its reader; this bounds only recursion.
const maxDepth = 256

var (
	errTruncated = errors.New("bolt: truncated value")
	errDepth     = errors.New("bolt: value nested too deeply")
	errMarker    = errors.New("bolt: unknown PackStream marker")
	errMapKey    = errors.New("bolt: map key is not a string")
	errTrailing  = errors.New("bolt: trailing bytes after the message")
)

// Unpack decodes exactly one value from b and refuses trailing bytes.
func Unpack(b []byte) (any, error) {
	d := decoder{b: b}
	v, err := d.value(0)
	if err != nil {
		return nil, err
	}
	if d.i != len(b) {
		return nil, errTrailing
	}
	return v, nil
}

type decoder struct {
	b []byte
	i int
}

func (d *decoder) take(n int) ([]byte, error) {
	if n < 0 || len(d.b)-d.i < n {
		return nil, errTruncated
	}
	out := d.b[d.i : d.i+n]
	d.i += n
	return out, nil
}

func (d *decoder) size(n int) (int, error) {
	b, err := d.take(n)
	if err != nil {
		return 0, err
	}
	switch n {
	case 1:
		return int(b[0]), nil
	case 2:
		return int(binary.BigEndian.Uint16(b)), nil
	default:
		v := binary.BigEndian.Uint32(b)
		// Every item takes at least one byte, so a count past what is left is
		// a lie, refused before any allocation.
		if uint64(v) > uint64(len(d.b)-d.i) {
			return 0, errTruncated
		}
		return int(v), nil
	}
}

func (d *decoder) value(depth int) (any, error) {
	if depth > maxDepth {
		return nil, errDepth
	}
	mb, err := d.take(1)
	if err != nil {
		return nil, err
	}
	m := mb[0]
	switch {
	case m < 0x80:
		return int64(m), nil
	case m >= 0xF0:
		return int64(int8(m)), nil
	case m >= 0x80 && m <= 0x8F:
		return d.str(int(m & 0x0F))
	case m >= 0x90 && m <= 0x9F:
		return d.list(int(m&0x0F), depth)
	case m >= 0xA0 && m <= 0xAF:
		return d.dict(int(m&0x0F), depth)
	case m >= 0xB0 && m <= 0xBF:
		return d.structure(int(m&0x0F), depth)
	}
	switch m {
	case 0xC0:
		return nil, nil
	case 0xC1:
		b, err := d.take(8)
		if err != nil {
			return nil, err
		}
		return math.Float64frombits(binary.BigEndian.Uint64(b)), nil
	case 0xC2:
		return false, nil
	case 0xC3:
		return true, nil
	case 0xC8, 0xC9, 0xCA, 0xCB:
		n := 1 << (m - 0xC8)
		b, err := d.take(n)
		if err != nil {
			return nil, err
		}
		switch n {
		case 1:
			return int64(int8(b[0])), nil
		case 2:
			return int64(int16(binary.BigEndian.Uint16(b))), nil
		case 4:
			return int64(int32(binary.BigEndian.Uint32(b))), nil
		default:
			return int64(binary.BigEndian.Uint64(b)), nil
		}
	case 0xCC, 0xCD, 0xCE:
		n, err := d.size(1 << (m - 0xCC))
		if err != nil {
			return nil, err
		}
		b, err := d.take(n)
		if err != nil {
			return nil, err
		}
		out := make([]byte, n)
		copy(out, b)
		return out, nil
	case 0xD0, 0xD1, 0xD2:
		n, err := d.size(1 << (m - 0xD0))
		if err != nil {
			return nil, err
		}
		return d.str(n)
	case 0xD4, 0xD5, 0xD6:
		n, err := d.size(1 << (m - 0xD4))
		if err != nil {
			return nil, err
		}
		return d.list(n, depth)
	case 0xD8, 0xD9, 0xDA:
		n, err := d.size(1 << (m - 0xD8))
		if err != nil {
			return nil, err
		}
		return d.dict(n, depth)
	}
	return nil, fmt.Errorf("%w 0x%02X", errMarker, m)
}

func (d *decoder) str(n int) (string, error) {
	b, err := d.take(n)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (d *decoder) list(n, depth int) ([]any, error) {
	if n > len(d.b)-d.i {
		return nil, errTruncated
	}
	out := make([]any, 0, n)
	for range n {
		v, err := d.value(depth + 1)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (d *decoder) dict(n, depth int) (map[string]any, error) {
	if n > (len(d.b)-d.i)/2 {
		return nil, errTruncated
	}
	out := make(map[string]any, n)
	for range n {
		k, err := d.value(depth + 1)
		if err != nil {
			return nil, err
		}
		key, ok := k.(string)
		if !ok {
			return nil, errMapKey
		}
		v, err := d.value(depth + 1)
		if err != nil {
			return nil, err
		}
		out[key] = v
	}
	return out, nil
}

func (d *decoder) structure(n, depth int) (*Structure, error) {
	tag, err := d.take(1)
	if err != nil {
		return nil, err
	}
	fields, err := d.list(n, depth)
	if err != nil {
		return nil, err
	}
	return &Structure{Tag: tag[0], Fields: fields}, nil
}

// Pack encodes v. It fails on a type outside the decoded set.
func Pack(v any) ([]byte, error) {
	var out []byte
	return appendValue(out, v, 0)
}

func appendSize(out []byte, n int, tiny, b8, b16, b32 byte) ([]byte, error) {
	switch {
	case n < 16 && tiny != 0:
		return append(out, tiny|byte(n)), nil
	case n <= math.MaxUint8 && b8 != 0:
		return append(out, b8, byte(n)), nil
	case n <= math.MaxUint16:
		return binary.BigEndian.AppendUint16(append(out, b16), uint16(n)), nil
	case uint64(n) <= math.MaxUint32:
		return binary.BigEndian.AppendUint32(append(out, b32), uint32(n)), nil
	}
	return nil, errors.New("bolt: value too large")
}

func appendValue(out []byte, v any, depth int) ([]byte, error) {
	if depth > maxDepth {
		return nil, errDepth
	}
	var err error
	switch x := v.(type) {
	case nil:
		return append(out, 0xC0), nil
	case bool:
		if x {
			return append(out, 0xC3), nil
		}
		return append(out, 0xC2), nil
	case int:
		return appendInt(out, int64(x)), nil
	case int64:
		return appendInt(out, x), nil
	case float64:
		return binary.BigEndian.AppendUint64(append(out, 0xC1), math.Float64bits(x)), nil
	case string:
		if out, err = appendSize(out, len(x), 0x80, 0xD0, 0xD1, 0xD2); err != nil {
			return nil, err
		}
		return append(out, x...), nil
	case []byte:
		if out, err = appendSize(out, len(x), 0, 0xCC, 0xCD, 0xCE); err != nil {
			return nil, err
		}
		return append(out, x...), nil
	case []any:
		if out, err = appendSize(out, len(x), 0x90, 0xD4, 0xD5, 0xD6); err != nil {
			return nil, err
		}
		for _, item := range x {
			if out, err = appendValue(out, item, depth+1); err != nil {
				return nil, err
			}
		}
		return out, nil
	case map[string]any:
		if out, err = appendSize(out, len(x), 0xA0, 0xD8, 0xD9, 0xDA); err != nil {
			return nil, err
		}
		for k, item := range x {
			if out, err = appendValue(out, k, depth+1); err != nil {
				return nil, err
			}
			if out, err = appendValue(out, item, depth+1); err != nil {
				return nil, err
			}
		}
		return out, nil
	case *Structure:
		if len(x.Fields) > 15 {
			return nil, errors.New("bolt: structure has too many fields")
		}
		out = append(out, 0xB0|byte(len(x.Fields)), x.Tag)
		for _, item := range x.Fields {
			if out, err = appendValue(out, item, depth+1); err != nil {
				return nil, err
			}
		}
		return out, nil
	}
	return nil, fmt.Errorf("bolt: cannot pack %T", v)
}

func appendInt(out []byte, v int64) []byte {
	switch {
	case v >= -16 && v <= 127:
		return append(out, byte(int8(v)))
	case v >= math.MinInt8 && v <= math.MaxInt8:
		return append(out, 0xC8, byte(int8(v)))
	case v >= math.MinInt16 && v <= math.MaxInt16:
		return binary.BigEndian.AppendUint16(append(out, 0xC9), uint16(int16(v)))
	case v >= math.MinInt32 && v <= math.MaxInt32:
		return binary.BigEndian.AppendUint32(append(out, 0xCA), uint32(int32(v)))
	}
	return binary.BigEndian.AppendUint64(append(out, 0xCB), uint64(v))
}
