package mitm

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"testing"

	"github.com/Infisical/agent-vault/internal/httpcatalog"
)

// mintedTokens stands in for httpcatalog.ClientTokens: it hands out a token,
// or an error, and counts invalidations.
type mintedTokens struct {
	mu          sync.Mutex
	value       string
	err         error
	invalidated int
}

func (m *mintedTokens) Token(context.Context, *httpcatalog.Entry) (httpcatalog.Secret, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return httpcatalog.Secret{}, m.err
	}
	return testSecret(m.value), nil
}

func (m *mintedTokens) Invalidate(*httpcatalog.Entry) { m.mu.Lock(); m.invalidated++; m.mu.Unlock() }

// newClientCredentialsFixture is the adapter fixture with its entry's key
// minted instead of stored. The minted token is adapterKeyV1, so the
// fixture's vendor accepts it and its echo paths echo it.
func newClientCredentialsFixture(t *testing.T, tokens *mintedTokens) *adapterFixture {
	t.Helper()
	return newAdapterFixture(t, func(o *Options) {
		catalog, err := httpcatalog.Parse([]byte(fmt.Sprintf(`{"entries":[{
			"name":"llm","host":"example.com","port":%d,"pathPrefixes":["/v1/chat","/v1/echo-split","/v1/echo-header"],
			"methods":["POST","GET"],"header":"Authorization","scheme":"Bearer","placeholder":"__vault_LLM_KEY__",
			"clientCredentials":{"tokenHost":"auth.example.com","audience":"https://example.com","client":{"mount":"gatehouse","path":"vendors/llm"}},
			"pools":["pool-agent"]}]}`, o.HeaderAdapter.Catalog.Current().Entries()[0].Port)))
		if err != nil {
			t.Fatal(err)
		}
		o.HeaderAdapter.Catalog = catalog
		if tokens != nil {
			o.HeaderAdapter.ClientTokens = tokens
		}
	})
}

func TestAdapterSendsAMintedToken(t *testing.T) {
	tokens := &mintedTokens{value: adapterKeyV1}
	f := newClientCredentialsFixture(t, tokens)
	// The entry has no stored key; reading one fails the call.
	f.keys.err = httpcatalog.ErrKeyDeleted
	for _, mutate := range []func(*http.Request){nil, func(r *http.Request) { r.Header.Del("Authorization") }} {
		code, body, err := f.do(t, "POST", "/v1/chat/completions", `{}`, mutate)
		if err != nil || code != 200 || body != `{"method":"POST","bytes":2}` {
			t.Fatalf("chat: %d %q %v", code, body, err)
		}
	}
	// The token is screened like a stored key.
	if code, _, _ := f.do(t, "GET", "/v1/echo-header", "", nil); code != 502 || f.audit.last().Outcome != "response_refused" {
		t.Fatalf("header echo: %d %+v", code, f.audit.last())
	}
	// A worker's own token is refused.
	code, _, _ := f.do(t, "POST", "/v1/chat/completions", `{}`, func(r *http.Request) { r.Header.Set("Authorization", "Bearer worker-own") })
	if code != 400 || f.audit.last().Outcome != "credential_header" {
		t.Fatalf("worker token: %d %+v", code, f.audit.last())
	}
	// A vendor refusal asks for a new token.
	f.acceptsV = adapterKeyV2
	if code, _, _ := f.do(t, "POST", "/v1/chat/completions", `{}`, nil); code != 401 || tokens.invalidated != 1 || f.keys.invalidated != 0 {
		t.Fatalf("refusal: %d invalidated=%d, stored key invalidated=%d", code, tokens.invalidated, f.keys.invalidated)
	}
}

func TestAdapterRefusesWithoutAMintedToken(t *testing.T) {
	for _, tc := range []struct {
		err     error
		outcome string
		retry   bool
	}{
		{httpcatalog.ErrClientToken, "token_unavailable", true},
		{httpcatalog.ErrKeyUnavailable, "key_unavailable", true},
		{httpcatalog.ErrKeyDeleted, "key_deleted", false},
	} {
		f := newClientCredentialsFixture(t, &mintedTokens{err: tc.err})
		r, _ := http.NewRequest("POST", f.url("/v1/chat/completions"), nil)
		r.Header.Set("Authorization", "Bearer __vault_LLM_KEY__")
		resp, err := f.client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != 503 || resp.Header.Get(RefusalHeader) != tc.outcome || (resp.Header.Get("Retry-After") != "") != tc.retry || f.calls.Load() != 0 {
			t.Fatalf("%v: %d %q Retry-After %q, vendor calls %d", tc.err, resp.StatusCode, resp.Header.Get(RefusalHeader), resp.Header.Get("Retry-After"), f.calls.Load())
		}
	}
	// A broker without a minter refuses the entry as misconfigured.
	f := newClientCredentialsFixture(t, nil)
	r, _ := http.NewRequest("POST", f.url("/v1/chat/completions"), nil)
	resp, err := f.client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 503 || resp.Header.Get(RefusalHeader) != "broker_misconfigured" || f.calls.Load() != 0 {
		t.Fatalf("no minter: %d %q", resp.StatusCode, resp.Header.Get(RefusalHeader))
	}
}
