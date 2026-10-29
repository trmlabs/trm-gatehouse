package mitm

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"sync"

	"github.com/Infisical/agent-vault/internal/auditchain"
)

// maxErrorBody bounds the part of a 4xx body read for its message field.
const maxErrorBody = 4096

// errorMessage holds the message field of a 4xx JSON body as the worker reads it.
type errorMessage struct {
	mu      sync.Mutex
	text    string
	needles [][]byte
}

func (m *errorMessage) get() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.text
}

// hook taps a 4xx response; the bytes the worker receives are untouched.
func (m *errorMessage) hook(resp *http.Response) {
	if resp.StatusCode < 400 || resp.StatusCode > 499 || resp.Body == nil {
		return
	}
	resp.Body = &messageTap{ReadCloser: resp.Body, into: m}
}

type messageTap struct {
	io.ReadCloser
	into *errorMessage
	buf  bytes.Buffer
	once sync.Once
}

func (t *messageTap) Read(p []byte) (int, error) {
	n, err := t.ReadCloser.Read(p)
	if room := min(n, maxErrorBody-t.buf.Len()); room > 0 {
		t.buf.Write(p[:room])
	}
	if err == io.EOF {
		t.settle()
	}
	return n, err
}

func (t *messageTap) Close() error {
	t.settle()
	return t.ReadCloser.Close()
}

func (t *messageTap) settle() {
	t.once.Do(func() {
		var body struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(t.buf.Bytes(), &body) != nil {
			return
		}
		for _, n := range t.into.needles {
			if bytes.Contains([]byte(body.Message), n) {
				return
			}
		}
		t.into.mu.Lock()
		t.into.text = auditchain.MessageField(body.Message)
		t.into.mu.Unlock()
	})
}
