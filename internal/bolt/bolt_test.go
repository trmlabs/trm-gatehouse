package bolt

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"reflect"
	"strings"
	"testing"
)

func TestPackRoundTrip(t *testing.T) {
	values := []any{
		nil, true, false, int64(0), int64(-16), int64(-17), int64(127), int64(128), int64(-129),
		int64(math.MaxInt16 + 1), int64(math.MinInt32), int64(math.MaxInt64), int64(math.MinInt64),
		1.5, math.Inf(-1), "", "short", strings.Repeat("x", 300), strings.Repeat("y", 70000),
		[]byte{}, []byte{1, 2, 3}, []any{}, []any{int64(1), "two", []any{3.0}},
		map[string]any{}, map[string]any{"a": int64(1), "b": map[string]any{"c": nil}},
		&Structure{Tag: 0x4E, Fields: []any{int64(1), []any{"Label"}, map[string]any{"x": int64(2)}, "4:abc:1"}},
	}
	for _, v := range values {
		b, err := Pack(v)
		if err != nil {
			t.Fatalf("pack %#v: %v", v, err)
		}
		got, err := Unpack(b)
		if err != nil {
			t.Fatalf("unpack %#v: %v", v, err)
		}
		if !reflect.DeepEqual(got, v) {
			t.Fatalf("round trip: got %#v, want %#v", got, v)
		}
	}
}

func TestUnpackRefusesHostileInput(t *testing.T) {
	deep := bytes.Repeat([]byte{0x91}, maxDepth+2)
	deep = append(deep, 0xC0)
	cases := map[string][]byte{
		"truncated string":   {0xD0, 0x05, 'a'},
		"huge list count":    {0xD6, 0xFF, 0xFF, 0xFF, 0xFF},
		"huge map count":     {0xDA, 0x7F, 0xFF, 0xFF, 0xFF},
		"non-string map key": {0xA1, 0x01, 0x02},
		"unknown marker":     {0xC4},
		"trailing bytes":     {0xC0, 0xC0},
		"too deep":           deep,
		"empty":              {},
	}
	for name, b := range cases {
		if _, err := Unpack(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestChunkedMessages(t *testing.T) {
	big := bytes.Repeat([]byte{0xAB}, 0xFFFF*2+10)
	var stream bytes.Buffer
	// A keepalive (NOOP) between messages is skipped.
	stream.Write([]byte{0, 0})
	stream.Write(Frame([]byte{0xB0, TagReset}))
	stream.Write([]byte{0, 0})
	stream.Write(Frame(big))
	got, err := ReadRaw(&stream, 1<<20)
	if err != nil || !bytes.Equal(got, []byte{0xB0, TagReset}) {
		t.Fatalf("first message: %x, %v", got, err)
	}
	got, err = ReadRaw(&stream, 1<<20)
	if err != nil || !bytes.Equal(got, big) {
		t.Fatalf("chunked message: %d bytes, %v", len(got), err)
	}
	if _, err := ReadRaw(&stream, 1<<20); !errors.Is(err, io.EOF) {
		t.Fatalf("end of stream: %v", err)
	}
	if _, err := ReadRaw(bytes.NewReader(Frame(big)), 1000); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("bound not enforced: %v", err)
	}
	if _, err := ReadRaw(bytes.NewReader([]byte{0, 4, 1, 2}), 100); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("cut chunk: %v", err)
	}
}

func TestHandshakeChoose(t *testing.T) {
	supported := []Version{{5, 2}, {4, 3}}
	slot := func(major, minor, rng byte) []byte { return []byte{0, rng, minor, major} }
	build := func(slots ...[]byte) Handshake {
		var h Handshake
		copy(h[:4], Magic[:])
		for i, s := range slots {
			copy(h[4+4*i:], s)
		}
		return h
	}
	cases := []struct {
		name string
		h    Handshake
		want Version
		ok   bool
	}{
		// The Python driver 6.x: a manifest, then 5.8 down to 5.0, then 4.4 down to 4.2.
		{"python 6", build([]byte{0, 0, 1, 0xFF}, slot(5, 8, 8), slot(4, 4, 2)), Version{5, 2}, true},
		{"exact 5.2", build(slot(5, 2, 0)), Version{5, 2}, true},
		{"5.4 only", build(slot(5, 4, 0)), Version{}, false},
		{"4.4 down to 4.2", build(slot(4, 4, 2)), Version{4, 3}, true},
		{"5.1 down to 5.0 then 4.3", build(slot(5, 1, 1), slot(4, 3, 0)), Version{4, 3}, true},
		{"nothing", build(), Version{}, false},
	}
	for _, c := range cases {
		got, ok := c.h.Choose(supported)
		if got != c.want || ok != c.ok {
			t.Errorf("%s: got %v %v, want %v %v", c.name, got, ok, c.want, c.ok)
		}
	}
	h, err := ReadHandshake(bytes.NewReader(ClientHandshake(Version{5, 2})), false)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := h.Choose(supported); !ok || v != (Version{5, 2}) {
		t.Fatalf("client handshake proposes %v", v)
	}
	if _, err := ReadHandshake(bytes.NewReader(make([]byte, 20)), false); err == nil {
		t.Fatal("accepted a stream without the magic")
	}
	answer := Version{5, 2}.Bytes()
	if v, err := ReadVersion(bytes.NewReader(answer[:])); err != nil || v != (Version{5, 2}) {
		t.Fatalf("read version: %v %v", v, err)
	}
	if v, err := ReadVersion(bytes.NewReader(binary.BigEndian.AppendUint32(nil, 0))); err != nil || v != (Version{}) {
		t.Fatalf("refusal: %v %v", v, err)
	}
}

func TestMessages(t *testing.T) {
	raw := Failure("Gatehouse.ClientError.Statement.AccessMode", "Gatehouse: read-only")
	if tag, err := Tag(raw); err != nil || tag != TagFailure {
		t.Fatalf("tag %x %v", tag, err)
	}
	msg, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := msg.Map(0)
	if err != nil || meta["code"] != "Gatehouse.ClientError.Statement.AccessMode" {
		t.Fatalf("metadata %v %v", meta, err)
	}
	if _, err := msg.Map(5); err != nil {
		t.Fatal("absent field must read as no map")
	}
	if _, err := Decode([]byte{0xC0}); err == nil {
		t.Fatal("decoded a non-structure as a message")
	}
	if tag, _ := Tag(Ignored()); tag != TagIgnored {
		t.Fatal("ignored")
	}
}
