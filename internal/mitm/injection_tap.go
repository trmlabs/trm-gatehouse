package mitm

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/Infisical/agent-vault/internal/auditchain"
	"github.com/Infisical/agent-vault/internal/injection"
)

// injectionRoutes are the GitHub REST routes whose responses carry text outside authors wrote.
var injectionRoutes = map[string]bool{"read-pull": true, "list-pulls": true, "list-comments": true, "read-comment": true}

// injectionOperation reports whether an HTTP row's operation reads Slack messages.
func injectionOperation(op string) bool {
	return op == "slack.conversations_history" || op == "slack.conversations_replies" || strings.HasPrefix(op, "slack.search_")
}

// screenTap copies a bounded prefix of a response as the worker reads it and queues it on Close; the worker's bytes are untouched.
type screenTap struct {
	io.ReadCloser
	flagger *injection.Flagger
	event   auditchain.Event
	buf     bytes.Buffer
	over    bool
	cut     bool
	once    sync.Once
}

func (t *screenTap) Read(p []byte) (int, error) {
	n, err := t.ReadCloser.Read(p)
	if !t.over && n > injection.MaxBodyBytes-t.buf.Len() {
		t.cut = true
	}
	if room := min(n, injection.MaxBodyBytes-t.buf.Len()); room > 0 && !t.over {
		if t.flagger.Reserve(room) {
			t.buf.Write(p[:room])
		} else {
			t.flagger.Release(t.buf.Len())
			t.buf.Reset()
			t.over = true
		}
	}
	return n, err
}

func (t *screenTap) Close() error {
	t.once.Do(func() {
		if t.cut && !t.over {
			t.flagger.NoteTruncated()
		}
		if !t.over && t.buf.Len() > 0 {
			t.flagger.Submit(injection.Item{Event: t.event, Body: t.buf.Bytes()})
		}
	})
	return t.ReadCloser.Close()
}

// responseHook changes an upstream response before it is relayed.
type responseHook func(*http.Response)

// screenResponse returns the adjust step that taps a response for the screener, or nil when none is configured.
func (p *Proxy) screenResponse(route string, event auditchain.Event) responseHook {
	flagger := p.adapter.injection()
	if flagger == nil {
		return nil
	}
	event.Route = route
	return func(resp *http.Response) {
		if resp.StatusCode != http.StatusOK || resp.Body == nil {
			return
		}
		resp.Body = &screenTap{ReadCloser: resp.Body, flagger: flagger, event: event}
	}
}

// chainAdjust runs each non-nil step in order.
func chainAdjust(steps ...func(*http.Response)) responseHook {
	return func(resp *http.Response) {
		for _, s := range steps {
			if s != nil {
				s(resp)
			}
		}
	}
}
