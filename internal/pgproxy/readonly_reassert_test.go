package pgproxy

import (
	"bytes"
	"testing"
)

func backendMsg(kind byte, body ...byte) []byte {
	n := uint32(len(body) + 4)
	return append([]byte{kind, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}, body...)
}

// Only the re-assert's answer is dropped, however the stream is split.
func TestReassertFilterDropsOnlyItsAnswer(t *testing.T) {
	var out bytes.Buffer
	answer := append(backendMsg('C', 'S', 'E', 'T', 0), backendMsg('Z', 'I')...)
	next := append(backendMsg('T', 1, 2, 3), backendMsg('Z', 'I')...)
	stream := bytes.Join([][]byte{answer, next}, nil)
	for step := 1; step <= len(stream); step++ {
		out.Reset()
		g := newReassertFilter(&out)
		g.sent()
		for i := 0; i < len(stream); i += step {
			if _, err := g.Write(stream[i:min(i+step, len(stream))]); err != nil {
				t.Fatal(err)
			}
		}
		if !bytes.Equal(out.Bytes(), next) {
			t.Fatalf("step %d: client got %x, want %x", step, out.Bytes(), next)
		}
		if g.owed != 0 || g.swallow {
			t.Fatalf("step %d: owed %d swallow %v after the answer", step, g.owed, g.swallow)
		}
	}
}
