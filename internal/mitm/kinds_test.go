package mitm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/ratelimit"
	"github.com/Infisical/agent-vault/internal/runnerid"
)

type kindAttestor struct{ kind string }

func (a kindAttestor) Attest(context.Context, string, netip.Addr) (*brokercore.ProxyScope, error) {
	return &brokercore.ProxyScope{AgentID: "agent", VaultID: "vault", IdentityKind: a.kind}, nil
}

func TestListenerAdmitsOnlyItsIdentityKinds(t *testing.T) {
	cross := []string{brokercore.KindProxyAttested}
	peer := netip.MustParseAddr("192.0.2.7")
	for name, c := range map[string]struct {
		kind  string
		kinds []string
		ok    bool
	}{
		"pool Pod on a pool listener":            {brokercore.KindPodToken, nil, true},
		"proxy on a pool listener":               {brokercore.KindProxyAttested, nil, false},
		"proxy on the cross-cluster listener":    {brokercore.KindProxyAttested, cross, true},
		"pool Pod on the cross-cluster listener": {brokercore.KindPodToken, cross, false},
		// A Claude session's Pod proves itself with its own token; the runner session only names the person.
		"session-jwt caller on the cross-cluster listener": {brokercore.KindPodToken, cross, false},
		"token review on the cross-cluster listener":       {brokercore.KindTokenReview, cross, false},
		"legacy session on the cross-cluster":              {"", cross, false},
	} {
		a, b := net.Pipe()
		conn := net.Conn(a)
		if c.kinds != nil {
			conn = &brokercore.KindedConn{Conn: a, Kinds: c.kinds}
		}
		ctx := withSessionToken(withPeerConn(context.Background(), &peerConn{Conn: conn}), "runner.session.token")
		p := &Proxy{attestor: kindAttestor{c.kind}}
		_, err := p.resolveScope(ctx, "token", "", peer, nil, false)
		if (err == nil) != c.ok {
			t.Errorf("%s: err %v", name, err)
		}
		_ = a.Close()
		_ = b.Close()
	}
}

// testListenerWrap, when set, wraps the test proxy's listener.
var testListenerWrap func(net.Listener) net.Listener

type crossClusterListener struct{ net.Listener }

func (l crossClusterListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &brokercore.KindedConn{Conn: c, Kinds: []string{brokercore.KindProxyAttested}}, nil
}

// A proxy-attested CONNECT on the cross-cluster listener carries its kinds into the tunnel; the same proxy on a pool listener is refused at CONNECT.
func TestCrossClusterTunnelServesItsRequests(t *testing.T) {
	for name, cross := range map[string]bool{"cross-cluster listener": true, "pool listener": false} {
		if cross {
			testListenerWrap = func(l net.Listener) net.Listener { return crossClusterListener{l} }
		}
		f := newAdapterFixture(t, func(o *Options) {
			o.Attestor = kindAttestorScope{&brokercore.ProxyScope{VaultID: "vault-1", AgentID: "agent-uuid-1", Pool: "pool-agent",
				WorkloadID: "agent-pod-uid", VaultRole: "proxy", IdentityKind: brokercore.KindProxyAttested}}
		})
		testListenerWrap = nil
		code, _, err := f.do(t, "POST", "/v1/chat/completions", "{}", nil)
		if cross && (err != nil || code != 200) {
			t.Errorf("%s: %d %v", name, code, err)
		}
		if !cross && err == nil && code == 200 {
			t.Errorf("%s: a proxy-attested tunnel was served", name)
		}
	}
}

type kindAttestorScope struct{ scope *brokercore.ProxyScope }

func (a kindAttestorScope) Attest(context.Context, string, netip.Addr) (*brokercore.ProxyScope, error) {
	s := *a.scope
	return &s, nil
}

// Refusals are logged by reason code, at most once per reason per interval.
func TestRefusalLogIsRateLimitedByReason(t *testing.T) {
	var buf bytes.Buffer
	p := &Proxy{logger: slog.New(slog.NewTextHandler(&buf, nil))}
	for i := 0; i < 5; i++ {
		p.logRefusal("proxy_source", nil)
	}
	p.logRefusal("catalog_profile", nil)
	out := buf.String()
	if strings.Count(out, "reason=proxy_source") != 1 || strings.Count(out, "reason=catalog_profile") != 1 {
		t.Fatalf("log: %s", out)
	}
	p.refusals.last["proxy_source"] = time.Now().Add(-refusalLogEvery)
	p.logRefusal("proxy_source", nil)
	if !strings.Contains(buf.String(), "reason=proxy_source count=5") {
		t.Fatalf("folded count missing: %s", buf.String())
	}
}

// A signing-key refusal names the token's kid and the connection's peer; a kid that is not a plain identifier is recorded as "invalid" plus a hash prefix, and its row is still written.
func TestKeyRefusalNamesKidAndPeer(t *testing.T) {
	peer := netip.MustParseAddr("10.20.30.40")
	for _, c := range []struct {
		name, reason, kid, wantKid string
		hashed                     bool
	}{
		{"pinned", "token_keys_pinned_mismatch", "c3ludGhldGljLXBpbm5lZC1rZXktaWQtMDAwMDAwMQ", "c3ludGhldGljLXBpbm5lZC1rZXktaWQtMDAwMDAwMQ", false},
		{"in-cluster", "token_keys_in_cluster_unknown", "k.1_a", "k.1_a", false},
		{"signature", "token_signature", "k1", "k1", false},
		{"quote", "token_signature", `k"1`, "invalid", true},
		{"space", "token_keys_pinned_mismatch", "k 1", "invalid", true},
		{"long", "token_keys_unavailable", strings.Repeat("k", 600), "invalid", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			refusal := brokercore.WithPeer(brokercore.DeniedKey(c.reason, c.kid), peer)
			sum := sha256.Sum256([]byte(c.kid))
			wantHash := ""
			if c.hashed {
				wantHash = hex.EncodeToString(sum[:])[:12]
			}
			var buf bytes.Buffer
			p := &Proxy{logger: slog.New(slog.NewTextHandler(&buf, nil))}
			p.logRefusal(brokercore.DenialReason(refusal), brokercore.DenialKey(refusal))
			line := buf.String()
			want := "reason=" + c.reason + " count=1 kid=" + c.wantKid
			if c.hashed {
				want += " kid_sha256=" + wantHash
			}
			if !strings.Contains(line, want+" peer=10.20.30.40") || (c.hashed && strings.Contains(line, c.kid)) {
				t.Fatalf("log line %q", line)
			}
			var proxyLog bytes.Buffer
			attestor := &tokenRecordingAttestor{err: refusal}
			f := newAdapterFixture(t, func(o *Options) {
				o.Attestor, o.Logger = attestor, slog.New(slog.NewTextHandler(&proxyLog, nil))
			})
			f.client = newTrustingClient(f.proxyURL, url.User(fakeJWT), f.roots)
			// The tunnel is refused at CONNECT: 403, never 503.
			_, _, err := f.do(t, "GET", "/v1/chat/x", "", nil)
			if err == nil || !strings.HasSuffix(err.Error(), ": Forbidden") || strings.Contains(err.Error(), c.reason) {
				t.Fatalf("caller saw %v", err)
			}
			e := f.audit.last()
			if e.Event != "denied" || e.Decision != "identity_"+c.reason || e.Kid != c.wantKid || e.KidSHA256 != wantHash || e.Peer != "10.20.30.40" || e.Status != 403 {
				t.Fatalf("audit row %+v", e)
			}
			// The token reached the attestor, and no part of it reached the log or the row.
			token := attestor.token()
			if token != fakeJWT {
				t.Fatalf("the attestor saw %q", token)
			}
			for _, part := range strings.Split(token, ".") {
				if strings.Contains(proxyLog.String(), part) || strings.Contains(fmt.Sprintf("%+v", f.audit.all()), part) {
					t.Fatalf("token part %q in log %q or rows", part, proxyLog.String())
				}
			}
			if !strings.Contains(proxyLog.String(), want+" peer=10.20.30.40") || (c.hashed && strings.Contains(proxyLog.String(), c.kid)) {
				t.Fatalf("proxy log %q", proxyLog.String())
			}
		})
	}
	var buf bytes.Buffer
	p := &Proxy{logger: slog.New(slog.NewTextHandler(&buf, nil))}
	p.logRefusal("proxy_source", brokercore.DenialKey(brokercore.WithPeer(brokercore.Denied("proxy_source"), peer)))
	if strings.Contains(buf.String(), "kid=") || strings.Contains(buf.String(), "peer=") {
		t.Fatalf("plain refusal line %q", buf.String())
	}
}

// A signing-key fetch outage is a 503 with the audit decision of its own, not the 403 of a key the issuer does not publish.
func TestKeysUnavailableRefusalIsRetryable(t *testing.T) {
	refusal := brokercore.WithPeer(brokercore.DeniedKey(runnerid.ReasonKeysUnavailable, "k1"), netip.MustParseAddr("10.20.30.40"))
	f := newAdapterFixture(t, func(o *Options) { o.Attestor = &tokenRecordingAttestor{err: refusal} })
	f.client = newTrustingClient(f.proxyURL, url.User(fakeJWT), f.roots)
	_, _, err := f.do(t, "GET", "/v1/chat/x", "", nil)
	if err == nil || !strings.HasSuffix(err.Error(), ": Service Unavailable") {
		t.Fatalf("caller saw %v", err)
	}
	if e := f.audit.last(); e.Event != "denied" || e.Decision != "identity_oidc_keys_unavailable" || e.Kid != "k1" || e.Status != 503 {
		t.Fatalf("audit row %+v", e)
	}
}

// An identity check the broker could not complete is a passing 503 with Retry-After and its own outcome; a refusing check stays a lasting 403.
func TestUnfinishedIdentityCheckIsRetryable(t *testing.T) {
	auth := "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("workload-token:")) + "\r\n"
	for name, c := range map[string]struct {
		refusal                   error
		retrySeconds, status      int
		code, outcome, retryAfter string
	}{
		"store outage":         {brokercore.Unavailable("store_unavailable"), 0, 503, "broker_unavailable", "broker_unavailable", "20"},
		"configured wait":      {brokercore.Unavailable("pod_lookup_unavailable"), 45, 503, "broker_unavailable", "broker_unavailable", "45"},
		"wait over the cap":    {brokercore.Unavailable("store_unavailable"), 100000, 503, "broker_unavailable", "broker_unavailable", "600"},
		"check timeout":        {brokercore.Unavailable("check_timeout"), 0, 503, "broker_unavailable", "broker_unavailable", "20"},
		"Pod gone":             {brokercore.Denied("pod_unreadable"), 0, 403, "identity", "refused", ""},
		"lasting with setting": {brokercore.Denied("deadline"), 45, 403, "identity", "refused", ""},
	} {
		t.Run(name, func(t *testing.T) {
			f := newAdapterFixture(t, func(o *Options) { o.Attestor, o.IdentityRetrySeconds = refusingAttestor{c.refusal}, c.retrySeconds })
			resp := rawConnect(t, f.proxyURL, f.roots, auth)
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != c.status || resp.Header.Get(RefusalHeader) != c.code || resp.Header.Get("Retry-After") != c.retryAfter {
				t.Fatalf("caller saw %d %q Retry-After %q", resp.StatusCode, resp.Header.Get(RefusalHeader), resp.Header.Get("Retry-After"))
			}
			if e := f.audit.last(); e.Event != "denied" || e.Outcome != c.outcome || e.Decision != "identity_"+brokercore.DenialReason(c.refusal) || e.Status != c.status {
				t.Fatalf("audit row %+v", e)
			}
		})
	}
}

// A refusal the broker could not complete never spends the address's failed sign-in budget, so an outage cannot end in a 429; a real refusal still does.
func TestUnfinishedIdentityCheckSpendsNoSignInBudget(t *testing.T) {
	auth := "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("workload-token:")) + "\r\n"
	for name, c := range map[string]struct {
		refusal error
		limited bool
	}{
		"unfinished": {brokercore.Unavailable("store_unavailable"), false},
		"refused":    {brokercore.Denied("pod_unreadable"), true},
	} {
		t.Run(name, func(t *testing.T) {
			f := newAdapterFixture(t, func(o *Options) { o.Sessions = errResolver(c.refusal) })
			cfg := ratelimit.DefaultsFor(ratelimit.ProfileDefault)
			cfg.Tiers[ratelimit.TierAuth].Max = 3
			f.proxy.rateLimit = ratelimit.New(cfg)
			overrideRemoteAddr(f.proxy, "10.0.0.5:12345")
			limited := false
			for i := 0; i < 6; i++ {
				resp := rawConnect(t, f.proxyURL, f.roots, auth)
				_ = resp.Body.Close()
				limited = limited || resp.StatusCode == http.StatusTooManyRequests
			}
			if limited != c.limited {
				t.Fatalf("six refusals of a budget of three: limited %v, want %v", limited, c.limited)
			}
		})
	}
}

// Without a catalog the refusal carries the same Retry-After.
func TestUnfinishedIdentityCheckWithoutCatalogIsRetryable(t *testing.T) {
	f := newStrictFixture(t, func(o *Options) { o.Sessions = errResolver(brokercore.Unavailable("store_unavailable")) })
	resp := rawConnect(t, f.proxyURL, nil, "Proxy-Authorization: Basic "+base64.StdEncoding.EncodeToString([]byte("workload-token:"))+"\r\n")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") != "20" {
		t.Fatalf("caller saw %d Retry-After %q", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
}

// admitOnceResolver admits the CONNECT, then answers every recheck inside the tunnel with err.
type admitOnceResolver struct {
	calls atomic.Int32
	scope *brokercore.ProxyScope
	err   error
}

func (s *admitOnceResolver) ResolveForProxy(context.Context, string, string) (*brokercore.ProxyScope, error) {
	if s.calls.Add(1) == 1 {
		return s.scope, nil
	}
	return nil, s.err
}

// A recheck inside an open tunnel that the broker could not complete is retryable too, and nothing reaches the destination.
func TestUnfinishedRecheckInTunnelIsRetryable(t *testing.T) {
	sessions := &admitOnceResolver{scope: &brokercore.ProxyScope{VaultID: "vault-1", AgentID: "agent-uuid-1", Pool: "pool-agent", WorkloadID: "pod-uid-1", VaultRole: "proxy"},
		err: brokercore.Unavailable("store_unavailable")}
	f := newAdapterFixture(t, func(o *Options) { o.Sessions = sessions })
	req, err := http.NewRequest(http.MethodGet, f.url("/v1/chat/x"), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer __vault_LLM_KEY__")
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 503 || resp.Header.Get(RefusalHeader) != "broker_unavailable" || resp.Header.Get("Retry-After") != "20" || f.calls.Load() != 0 {
		t.Fatalf("caller saw %d %q Retry-After %q, vendor calls %d", resp.StatusCode, resp.Header.Get(RefusalHeader), resp.Header.Get("Retry-After"), f.calls.Load())
	}
	if e := f.audit.last(); e.Event != "denied" || e.Outcome != "broker_unavailable" || e.Decision != "identity_store_unavailable" || e.Status != 503 {
		t.Fatalf("audit row %+v", e)
	}
}

type refusingAttestor struct{ err error }

// fakeJWT has a real token's three segments; none may reach a log or row.
const fakeJWT = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImsxIn0.eyJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6eDp5In0.c2lnbmF0dXJlLWJ5dGVz"

type tokenRecordingAttestor struct {
	err  error
	mu   sync.Mutex
	seen string
}

func (a *tokenRecordingAttestor) Attest(_ context.Context, token string, _ netip.Addr) (*brokercore.ProxyScope, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.seen = token
	return nil, a.err
}

func (a *tokenRecordingAttestor) token() string { a.mu.Lock(); defer a.mu.Unlock(); return a.seen }

func (a refusingAttestor) Attest(context.Context, string, netip.Addr) (*brokercore.ProxyScope, error) {
	return nil, a.err
}

func TestIdentityRefusalIsAuditedWithItsReason(t *testing.T) {
	f := newAdapterFixture(t, func(o *Options) { o.Attestor = refusingAttestor{brokercore.Denied("proxy_source")} })
	code, body, _ := f.do(t, "GET", "/v1/chat/x", "", nil)
	if code == 200 || strings.Contains(body, "proxy_source") {
		t.Fatalf("caller saw %d %q", code, body)
	}
	if e := f.audit.last(); e.Event != "denied" || e.Decision != "identity_proxy_source" || e.Status != 403 {
		t.Fatalf("audit row %+v", e)
	}
	g := newAdapterFixture(t, func(o *Options) { o.Attestor = refusingAttestor{brokercore.ErrInvalidSession} })
	g.do(t, "GET", "/v1/chat/x", "", nil)
	if e := g.audit.last(); e.Event != "denied" || e.Decision != "" {
		t.Fatalf("plain refusal row %+v", e)
	}
}
