package mitm

import (
	"encoding/json"
	"io"
	"strconv"
	"sync"

	"github.com/Infisical/agent-vault/internal/auditchain"
)

// graphqlScanLimit bounds how much of one GraphQL answer is parsed for an
// errors array; a larger answer is relayed in full and the rest goes
// unscanned. GitHub's answers are far smaller.
const graphqlScanLimit = 32 << 20

// graphqlErrorScan reads a GitHub GraphQL answer as it streams to the worker
// and notes whether it carries a top-level "errors" array, which GitHub sends
// with status 200 when it refuses part of a query (a missing permission, a
// field the token cannot see) and gh then fails on. It never holds the body:
// a decoder walks tokens, skipping every top-level value but "errors", so a
// large "data" costs time, not memory, and the relay is not delayed.
//
// Only each error's type and path are kept; never a message or any data.
type graphqlErrorScan struct {
	once  sync.Once
	pw    *io.PipeWriter
	done  chan struct{}
	types []string
	paths [][]string
	found bool
}

func newGraphQLErrorScan() *graphqlErrorScan { return &graphqlErrorScan{} }

// tee returns body unchanged to its reader while feeding the scan.
func (s *graphqlErrorScan) tee(body io.ReadCloser) io.ReadCloser {
	var pr *io.PipeReader
	pr, s.pw = io.Pipe()
	s.done = make(chan struct{})
	go func() {
		defer close(s.done)
		s.scan(&limitedScan{r: pr})
		_, _ = io.Copy(io.Discard, pr) // never block the relay
	}()
	return &scanBody{ReadCloser: body, pw: s.pw}
}

// result ends the scan and reports the answer's error summary; ok is false
// when it carried no errors array, or was never scanned. Safe to call more
// than once.
func (s *graphqlErrorScan) result() (summary string, ok bool) {
	s.once.Do(func() {
		if s.pw != nil {
			_ = s.pw.Close()
			<-s.done
		}
	})
	if !s.found {
		return "", false
	}
	summary = auditchain.GraphQLErrorsField(s.types, s.paths)
	if summary == "" {
		summary = "UNKNOWN@-"
	}
	return summary, true
}

type scanBody struct {
	io.ReadCloser
	pw *io.PipeWriter
}

func (b *scanBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		_, _ = b.pw.Write(p[:n]) // the scan drains, so this only waits for it
	}
	return n, err
}

// limitedScan ends the scan's input at graphqlScanLimit bytes.
type limitedScan struct {
	r io.Reader
	n int64
}

func (l *limitedScan) Read(p []byte) (int, error) {
	if l.n >= graphqlScanLimit {
		return 0, io.EOF
	}
	if room := graphqlScanLimit - l.n; int64(len(p)) > room {
		p = p[:room]
	}
	n, err := l.r.Read(p)
	l.n += int64(n)
	return n, err
}

func (s *graphqlErrorScan) scan(r io.Reader) {
	dec := json.NewDecoder(r)
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return
	}
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return
		}
		if name, _ := key.(string); name == "errors" {
			if !s.readErrors(dec) {
				return
			}
			continue
		}
		if !skipValue(dec) {
			return
		}
	}
}

// readErrors reads the errors value. An array (even an empty one) is not an
// error; each element is, and one that is not an object still counts.
func (s *graphqlErrorScan) readErrors(dec *json.Decoder) bool {
	t, err := dec.Token()
	if err != nil {
		return false
	}
	if t != json.Delim('[') {
		return skipRest(dec, t)
	}
	for dec.More() {
		var e struct {
			Type string `json:"type"`
			Path []any  `json:"path"`
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return false
		}
		_ = json.Unmarshal(raw, &e) // an element of another shape still counts, unnamed
		var path []string
		for _, p := range e.Path {
			switch v := p.(type) {
			case string:
				path = append(path, v)
			case float64:
				path = append(path, strconv.FormatInt(int64(v), 10))
			default:
				path = append(path, "")
			}
		}
		s.found = true
		if len(s.types) < 1000 { // the summary names eight and counts the rest
			s.types = append(s.types, e.Type)
			s.paths = append(s.paths, path)
		}
	}
	_, err = dec.Token() // the closing bracket
	return err == nil
}

// skipValue consumes one JSON value, however large, without keeping it.
func skipValue(dec *json.Decoder) bool {
	t, err := dec.Token()
	if err != nil {
		return false
	}
	return skipRest(dec, t)
}

// skipRest consumes what remains of the value that began with token t.
func skipRest(dec *json.Decoder, t json.Token) bool {
	d, ok := t.(json.Delim)
	if !ok || (d != '{' && d != '[') {
		return true
	}
	for depth := 1; depth > 0; {
		t, err := dec.Token()
		if err != nil {
			return false
		}
		if d, ok := t.(json.Delim); ok {
			if d == '{' || d == '[' {
				depth++
			} else {
				depth--
			}
		}
	}
	return true
}
