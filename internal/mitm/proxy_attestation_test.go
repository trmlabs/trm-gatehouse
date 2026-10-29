package mitm

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

// recordingAttestor admits everything and records the attestation each
// admission and recheck saw.
type recordingAttestor struct {
	fakeAttestor
	mu   sync.Mutex
	seen []string
}

func (a *recordingAttestor) Attest(ctx context.Context, token string, peer netip.Addr) (*brokercore.ProxyScope, error) {
	a.mu.Lock()
	a.seen = append(a.seen, brokercore.AttestationFrom(ctx))
	a.mu.Unlock()
	return a.fakeAttestor.Attest(ctx, token, peer)
}

// A shared proxy's CONNECT attestation reaches the admission and every
// per-request recheck; a request inside the tunnel cannot replace it.
func TestConnectAttestationReachesEveryCheck(t *testing.T) {
	attestor := &recordingAttestor{}
	f := newAdapterFixture(t, func(o *Options) {
		o.Attestor = attestor
		o.Sessions = &fakeSessionResolver{resolve: func(string, string) (*brokercore.ProxyScope, error) {
			t.Error("token review consulted while an Attestor is configured")
			return nil, brokercore.ErrInvalidSession
		}}
	})
	f.client.Transport.(*http.Transport).ProxyConnectHeader = http.Header{brokercore.AttestationHeader: {"attested-by-proxy"}}
	if code, _, err := f.do(t, "GET", "/v1/chat/x", "", func(r *http.Request) {
		r.Header.Set(brokercore.AttestationHeader, "forged-inside-tunnel")
	}); err != nil || code != 200 {
		t.Fatalf("call: %d %v", code, err)
	}
	attestor.mu.Lock()
	defer attestor.mu.Unlock()
	if len(attestor.seen) < 2 {
		t.Fatalf("checks %v", attestor.seen)
	}
	for _, got := range attestor.seen {
		if got != "attested-by-proxy" {
			t.Fatalf("check saw %q", got)
		}
	}
}

// outageAttestor admits every worker until its verifier is switched off.
type outageAttestor struct {
	fakeAttestor
	down atomic.Bool
}

func (a *outageAttestor) Attest(ctx context.Context, token string, peer netip.Addr) (*brokercore.ProxyScope, error) {
	if a.down.Load() {
		return nil, errors.New("verifier unavailable")
	}
	return a.fakeAttestor.Attest(ctx, token, peer)
}

// While the verifier is down every CONNECT is denied with no token-review fallback, and admission resumes when it returns.
func TestVerifierOutageDeniesEveryRequestThenRecovers(t *testing.T) {
	attestor := &outageAttestor{}
	var fallbacks atomic.Int32
	f := newAdapterFixture(t, func(o *Options) {
		o.Attestor = attestor
		o.Sessions = &fakeSessionResolver{resolve: func(string, string) (*brokercore.ProxyScope, error) {
			fallbacks.Add(1)
			return &brokercore.ProxyScope{VaultID: "vault-1", AgentID: "agent-uuid-1", Pool: "pool-agent"}, nil
		}}
	})
	fresh := func() { f.client.Transport.(*http.Transport).CloseIdleConnections() }
	if code, _, err := f.do(t, "GET", "/v1/chat/x", "", nil); err != nil || code != 200 {
		t.Fatalf("before the outage: %d %v", code, err)
	}
	served := f.calls.Load()

	attestor.down.Store(true)
	for range 3 {
		fresh()
		if code, _, err := f.do(t, "GET", "/v1/chat/x", "", nil); err == nil && code == 200 {
			t.Fatal("a request was admitted while the verifier was down")
		}
	}
	if f.calls.Load() != served || fallbacks.Load() != 0 {
		t.Fatalf("upstream calls %d (was %d), token-review fallbacks %d", f.calls.Load(), served, fallbacks.Load())
	}

	attestor.down.Store(false)
	fresh()
	if code, _, err := f.do(t, "GET", "/v1/chat/x", "", nil); err != nil || code != 200 {
		t.Fatalf("after the verifier returned: %d %v", code, err)
	}
}
