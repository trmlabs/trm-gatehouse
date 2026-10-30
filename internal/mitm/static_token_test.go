package mitm

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/agenttoken"
	"github.com/Infisical/agent-vault/internal/auditchain"
	"github.com/Infisical/agent-vault/internal/authorize"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/ratelimit"
	"github.com/Infisical/agent-vault/internal/runnerid"
)

type staticTokenListener struct{ net.Listener }

func (l staticTokenListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &brokercore.KindedConn{Conn: c, Kinds: []string{brokercore.KindStaticToken}}, nil
}

// countingKeys counts the key reads behind an adapter, so a test can show a
// refusal came before any credential was read.
type countingKeys struct {
	*adapterKeys
	reads atomic.Int64
}

func (k *countingKeys) Get(ctx context.Context, ref httpcatalog.KeyRef) (httpcatalog.Secret, error) {
	k.reads.Add(1)
	return k.adapterKeys.Get(ctx, ref)
}

// staticCatalog is the catalog of an automations pool served by one harness
// that proves identity with a static token. The agent blocks are the caller's.
func staticCatalog(t *testing.T, port int, blocks string) httpcatalog.Catalog {
	t.Helper()
	c, err := httpcatalog.Parse([]byte(fmt.Sprintf(`{
	 "harnesses":[{"name":"token-agents","identity":{"kind":"static-token"},"path":{"kind":"direct"},
	   "authorization":{"mode":"automation","poolName":"automations"},"client":{"proxyEnv":"EXAMPLE_PROXY","caFileEnv":"EXAMPLE_CA_FILE"}}],
	 "pools":[{"name":"automations","namespace":"n","serviceAccount":"worker","identity":"cursor-automation"}],
	 "entries":[
	  {"name":"llm","host":"example.com","port":%d,"pathPrefixes":["/v1/chat"],"methods":["POST","GET"],"header":"Authorization","scheme":"Bearer","placeholder":"__vault_LLM_KEY__",
	   "key":{"mount":"gatehouse","path":"vendors/llm","field":"key"},"pools":["automations"]},
	  {"name":"private","host":"example.com","port":%d,"pathPrefixes":["/v1/private"],"methods":["GET"],"header":"Authorization","scheme":"Bearer","placeholder":"__vault_PRIV_KEY__",
	   "key":{"mount":"gatehouse","path":"vendors/private","field":"key"},"pools":["automations"]}],
	 "automations":[%s]}`, port, port, blocks)))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// agentBlock is one token block. A token block must carry an expiry inside the
// longest a token may live, so it gets one unless extra sets its own.
func agentBlock(id, entry string, hashes []string, extra string) string {
	if !strings.Contains(extra, `"expires"`) {
		extra += fmt.Sprintf(`,"expires":%q`, time.Now().Add(30*24*time.Hour).UTC().Format(time.RFC3339))
	}
	return fmt.Sprintf(`{"id":%q,"name":"%s-name","owner":"platform-team","entries":[%q],"tokenSHA256":["%s"]%s}`, id, id, entry, strings.Join(hashes, `","`), extra)
}

type staticFixture struct {
	*adapterFixture
	keys *countingKeys
	// token is agent-1's token, which may use the llm entry only.
	token string
	hash  string
}

func newStaticFixture(t *testing.T, extra string) *staticFixture {
	t.Helper()
	testListenerWrap = func(l net.Listener) net.Listener { return staticTokenListener{l} }
	f := newAdapterFixture(t)
	testListenerWrap = nil
	token, hash, err := agenttoken.Mint("agent-1")
	if err != nil {
		t.Fatal(err)
	}
	sf := &staticFixture{adapterFixture: f, keys: &countingKeys{adapterKeys: f.keys}, token: token, hash: hash}
	catalog := staticCatalog(t, f.port, agentBlock("agent-1", "llm", []string{hash}, extra))
	f.proxy.adapter.Catalog = catalog
	f.proxy.adapter.Keys = sf.keys
	f.proxy.agentTokens = agenttoken.Static{Catalog: f.proxy.adapter.Catalog}
	sf.useToken(token)
	return sf
}

func (f *staticFixture) useToken(token string) {
	f.client.CloseIdleConnections()
	f.client = newTrustingClient(f.proxyURL, url.User(token), f.roots)
}

// A token agent is an Automation of the automations pool: its block's entry is
// served with the key added at the broker, and every row names the pool, the
// agent, how it was admitted and the team that owns it. An entry its block
// does not list is refused.
func TestStaticTokenAgentIsServedItsOwnEntries(t *testing.T) {
	f := newStaticFixture(t, "")
	code, body, err := f.do(t, "POST", "/v1/chat/completions", `{}`, nil)
	if err != nil || code != 200 {
		t.Fatalf("%d %q %v", code, body, err)
	}
	var allowed auditchain.Event
	for _, e := range f.audit.all() {
		if e.Event == auditchain.EventHTTPRequest {
			allowed = e
		}
	}
	if allowed.Pool != "automations" || allowed.Agent != "agent-1" || allowed.Automation != "agent-1" || allowed.Source != "STATIC_TOKEN" ||
		allowed.RequesterKind != "automation" || allowed.AutomationName != "agent-1-name" || allowed.AutomationOwner != "platform-team" || allowed.Binding != "llm" ||
		allowed.Decision != "automation_granted" && allowed.Decision != "t0" {
		t.Fatalf("row %+v", allowed)
	}
	// The token never reaches the upstream or a row.
	if strings.Contains(fmt.Sprint(f.seen.Load()), f.token) || strings.Contains(fmt.Sprintf("%+v", f.audit.all()), f.token) {
		t.Fatal("the token reached the upstream or an audit row")
	}
	reads := f.keys.reads.Load()
	code, _, _ = f.do(t, "GET", "/v1/private/x", "", nil)
	if code != http.StatusForbidden {
		t.Fatalf("an entry outside the block: %d", code)
	}
	if e := f.audit.last(); e.Outcome != "automation_not_granted" || e.Automation != "agent-1" || e.Binding != "private" {
		t.Fatalf("row %+v", e)
	}
	if f.keys.reads.Load() != reads {
		t.Error("a key was read for a refused entry")
	}
}

// Wrong token, unknown agent, expired token and a token for a removed block
// are each refused at the CONNECT, before any credential is read, and each
// leaves a row that names the reason and the agent id the token claimed.
func TestStaticTokenRefusalsAreAuditedBeforeAnyCredential(t *testing.T) {
	f := newStaticFixture(t, "")
	_, hash2, _ := agenttoken.Mint("agent-2")
	expiredToken, expiredHash, _ := agenttoken.Mint("agent-3")
	f.proxy.adapter.Catalog = staticCatalog(t, f.port, strings.Join([]string{
		agentBlock("agent-1", "llm", []string{f.hash}, ""),
		agentBlock("agent-3", "llm", []string{expiredHash}, `,"expires":"2020-01-01T00:00:00Z"`),
	}, ","))
	f.proxy.agentTokens = agenttoken.Static{Catalog: f.proxy.adapter.Catalog}
	unknownToken, _, _ := agenttoken.Mint("agent-9")
	_ = hash2
	for name, tc := range map[string]struct{ token, decision, agent string }{
		"a wrong secret":    {"agent-1." + strings.Repeat("A", 43), "identity_token_mismatch", "agent-1"},
		"an unknown agent":  {unknownToken, "identity_agent_unknown", "agent-9"},
		"an expired token":  {expiredToken, "identity_token_expired", "agent-3"},
		"a Pod-style token": {fakeJWT, "identity_token_malformed", ""},
	} {
		reads, calls := f.keys.reads.Load(), f.calls.Load()
		f.useToken(tc.token)
		code, body, err := f.do(t, "POST", "/v1/chat/completions", `{}`, nil)
		if err == nil && code == 200 {
			t.Errorf("%s: served", name)
		}
		if strings.Contains(body, tc.decision) || strings.Contains(fmt.Sprint(err), "token_") {
			t.Errorf("%s: the caller was told why: %q %v", name, body, err)
		}
		e := f.audit.last()
		if e.Event != auditchain.EventDenied || e.Decision != tc.decision || e.Status != 403 || e.Pool != "" {
			t.Errorf("%s: row %+v", name, e)
		}
		if tc.agent != "" && e.Kid != tc.agent {
			t.Errorf("%s: the row names agent %q", name, e.Kid)
		}
		if strings.Contains(fmt.Sprintf("%+v", e), tc.token) {
			t.Errorf("%s: the row holds the token", name)
		}
		if f.keys.reads.Load() != reads || f.calls.Load() != calls {
			t.Errorf("%s: a credential was read or the upstream called", name)
		}
	}
}

// Removing a block ends access on the tunnel's next request: the block was
// there when the tunnel opened, so the refusal is agent_removed, not unknown.
func TestStaticTokenRemovedBlockEndsAnOpenTunnel(t *testing.T) {
	f := newStaticFixture(t, "")
	if code, _, err := f.do(t, "POST", "/v1/chat/completions", `{}`, nil); err != nil || code != 200 {
		t.Fatalf("%d %v", code, err)
	}
	other, otherHash, _ := agenttoken.Mint("agent-2")
	_ = other
	f.proxy.adapter.Catalog = staticCatalog(t, f.port, agentBlock("agent-2", "llm", []string{otherHash}, ""))
	f.proxy.agentTokens = agenttoken.Static{Catalog: f.proxy.adapter.Catalog}
	reads := f.keys.reads.Load()
	code, _, err := f.do(t, "POST", "/v1/chat/completions", `{}`, nil)
	if err == nil && code == 200 {
		t.Fatal("served after the block was removed")
	}
	if e := f.audit.last(); e.Event != auditchain.EventDenied || e.Decision != "identity_agent_removed" || e.Kid != "agent-1" {
		t.Fatalf("row %+v", e)
	}
	if f.keys.reads.Load() != reads {
		t.Error("a key was read after the block was removed")
	}
}

// resolveAgentToken on its own: the scope it makes, and its refusals, with
// the peer the TLS front named.
func TestResolveAgentToken(t *testing.T) {
	token, hash, _ := agenttoken.Mint("agent-1")
	catalog := staticCatalog(t, 443, agentBlock("agent-1", "llm", []string{hash}, ""))
	p := &Proxy{agentTokens: agenttoken.Static{Catalog: catalog}}
	peer := netip.MustParseAddr("192.0.2.7")
	ctx := withKinds(context.Background(), []string{brokercore.KindStaticToken})
	scope, err := p.resolveScope(ctx, token, "", peer, nil, false)
	if err != nil || scope.AgentID != "agent-1" || scope.Automation != "agent-1" || scope.Pool != "automations" || scope.IdentityKind != brokercore.KindStaticToken ||
		scope.WorkloadID != "" || scope.UserID != "" || scope.NotAfter.IsZero() {
		t.Fatalf("%+v %v", scope, err)
	}
	// A vault hint is not part of the token's form.
	if _, err := p.resolveScope(ctx, token, "vault", peer, nil, false); brokercore.DenialReason(err) != agenttoken.ReasonMalformed {
		t.Errorf("hint: %v", err)
	}
	// The refusal names the peer, with the claimed id.
	_, err = p.resolveScope(ctx, "agent-1."+strings.Repeat("A", 43), "", peer, nil, false)
	if k := brokercore.DenialKey(err); k == nil || k.Peer != "192.0.2.7" || k.Kid != "agent-1" {
		t.Errorf("refusal %+v %v", k, err)
	}
	// With no verifier the listener refuses everyone.
	bare := &Proxy{}
	if _, err := bare.resolveScope(ctx, token, "", peer, nil, false); brokercore.DenialReason(err) != reasonNoVerifier {
		t.Errorf("no verifier: %v", err)
	}
	// A verifier's own, uncoded error still refuses with a code.
	broken := &Proxy{agentTokens: failingVerifier{}}
	if _, err := broken.resolveScope(ctx, token, "", peer, nil, false); brokercore.DenialReason(err) != reasonNoVerifier {
		t.Errorf("uncoded error: %v", err)
	}
	// A verifier's session that has already ended is refused, whatever it says.
	if _, err := (&Proxy{agentTokens: expiredVerifier{}}).resolveScope(ctx, token, "", peer, nil, false); brokercore.DenialReason(err) != agenttoken.ReasonExpired {
		t.Errorf("expired session: %v", err)
	}
}

type failingVerifier struct{}

func (failingVerifier) Verify(context.Context, string) (agenttoken.Session, error) {
	return agenttoken.Session{}, fmt.Errorf("catalog unavailable")
}

type expiredVerifier struct{}

func (expiredVerifier) Verify(context.Context, string) (agenttoken.Session, error) {
	return agenttoken.Session{Automation: "agent-1", Pool: "automations", Expires: parseTime("2000-01-01T00:00:00Z")}, nil
}

// Each listener admits only the kinds it was opened for. A scope of the
// static-token kind is admitted by the static-token listener alone, and the
// static-token listener reads tokens with the agent verifier only: a Pod's or a
// shared proxy's token is never handed to the Attestor there.
func TestStaticTokenKindIsAdmittedOnItsOwnListenerOnly(t *testing.T) {
	peer := netip.MustParseAddr("192.0.2.7")
	resolve := func(p *Proxy, kinds []string) error {
		a, b := net.Pipe()
		defer func() { _ = a.Close(); _ = b.Close() }()
		conn := net.Conn(a)
		if kinds != nil {
			conn = &brokercore.KindedConn{Conn: a, Kinds: kinds}
		}
		_, err := p.resolveScope(withPeerConn(context.Background(), &peerConn{Conn: conn}), "token", "", peer, nil, false)
		return err
	}
	// A scope of the static kind, however it got there, is refused on any
	// other listener.
	for name, kinds := range map[string][]string{
		"a pool listener":               nil,
		"the cross-cluster listener":    {brokercore.KindProxyAttested},
		"a listener with several kinds": {brokercore.KindStaticToken, brokercore.KindPodToken},
	} {
		if err := resolve(&Proxy{attestor: kindAttestor{brokercore.KindStaticToken}}, kinds); brokercore.DenialReason(err) != "listener_kind" {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The static-token listener admits its own kind from the agent verifier,
	// and never asks the Attestor, whatever kind that would have returned.
	p := &Proxy{attestor: kindAttestor{brokercore.KindPodToken}, agentTokens: scopeVerifier{}}
	if err := resolve(p, []string{brokercore.KindStaticToken}); err != nil {
		t.Errorf("the static-token listener refused an agent token: %v", err)
	}
	if err := resolve(&Proxy{attestor: kindAttestor{brokercore.KindPodToken}}, []string{brokercore.KindStaticToken}); brokercore.DenialReason(err) != reasonNoVerifier {
		t.Errorf("the static-token listener fell back to the Attestor: %v", err)
	}
}

type scopeVerifier struct{}

func (scopeVerifier) Verify(context.Context, string) (agenttoken.Session, error) {
	return agenttoken.Session{Automation: "agent-1", Pool: "automations"}, nil
}

// addrConn is a connection whose remote address is the peer the TLS front named.
type addrConn struct {
	net.Conn
	addr net.Addr
}

func (c addrConn) RemoteAddr() net.Addr { return c.addr }

// The failure budget on the static-token listener is keyed on the peer the TLS
// front named, never on the agent id the caller wrote, and a token that
// verifies is never held back by it.
func TestStaticTokenFailureBudgetIsPerPeer(t *testing.T) {
	secret := strings.Repeat("A", 43)
	a, b := net.Pipe()
	defer func() { _ = a.Close(); _ = b.Close() }()
	request := func(peer, userinfo string) *http.Request {
		r := httptest.NewRequest("CONNECT", "http://api.example.com:443", nil)
		r.RemoteAddr = "127.0.0.1:40000"
		r.SetBasicAuth(userinfo, "")
		r.Header.Set("Proxy-Authorization", r.Header.Get("Authorization"))
		conn := &peerConn{Conn: addrConn{a, &net.TCPAddr{IP: net.ParseIP(peer), Port: 4000}}}
		ctx := withPeerConn(withKinds(r.Context(), []string{brokercore.KindStaticToken}), conn)
		return r.WithContext(ctx)
	}
	one, two := mitmIPKey(request("192.0.2.7", "agent-1."+secret)), mitmIPKey(request("192.0.2.8", "agent-1."+secret))
	if one != "mitm:static-token/peer:192.0.2.7" || two != "mitm:static-token/peer:192.0.2.8" {
		t.Fatalf("keys %q %q", one, two)
	}
	// Ids the caller rotates share the peer's one budget.
	if mitmIPKey(request("192.0.2.7", "agent-2."+secret)) != one || mitmIPKey(request("192.0.2.7", "junk")) != one {
		t.Fatal("the key follows the claimed id")
	}
	if got := mitmIPKey(httptest.NewRequest("CONNECT", "http://api.example.com:443", nil).WithContext(withKinds(context.Background(), []string{brokercore.KindStaticToken}))); got != "mitm:static-token" {
		t.Fatalf("no peer: %q", got)
	}
}

// Failed tokens are slowed per peer, whatever ids they name, and a correct
// token always passes: three bad tokens naming one agent, or three different
// agents, do not lock the real agent out. The limited attempt's row names the
// agent id it claimed.
func TestStaticTokenFailuresNeverBlockACorrectToken(t *testing.T) {
	f := newStaticFixture(t, "")
	cfg := ratelimit.DefaultsFor(ratelimit.ProfileDefault)
	cfg.Tiers[ratelimit.TierAuth].Max = 3
	f.proxy.rateLimit = ratelimit.New(cfg)
	secret := strings.Repeat("A", 43)
	for i := 0; i < 3; i++ {
		f.useToken(fmt.Sprintf("agent-%d.%s", i+1, secret))
		f.do(t, "POST", "/v1/chat/completions", `{}`, nil)
	}
	// The peer is over its failure budget: a further bad token is limited, by
	// the id it names or any other.
	f.useToken("agent-1." + secret)
	code, _, err := f.do(t, "POST", "/v1/chat/completions", `{}`, nil)
	if err == nil && code == 200 {
		t.Fatal("a bad token was served")
	}
	if e := f.audit.last(); e.Decision != "identity_rate_limited" || e.Status != 429 || e.Kid != "agent-1" || e.Peer == "" {
		t.Fatalf("row %+v", e)
	}
	f.useToken("agent-77." + secret)
	f.do(t, "POST", "/v1/chat/completions", `{}`, nil)
	if e := f.audit.last(); e.Decision != "identity_rate_limited" || e.Kid != "agent-77" {
		t.Fatalf("row %+v", e)
	}
	// The correct token is served, and keeps being served.
	for i := 0; i < 3; i++ {
		f.useToken(f.token)
		if code, body, err := f.do(t, "POST", "/v1/chat/completions", `{}`, nil); err != nil || code != 200 {
			t.Fatalf("the correct token was refused after others' failures: %d %q %v", code, body, err)
		}
	}
}

// A connection on the static-token listener takes CONNECT only: a refused
// CONNECT does not leave it open for another kind of request, which is refused
// and ends the connection.
func TestStaticTokenListenerRefusesLaterNonConnect(t *testing.T) {
	f := newStaticFixture(t, "")
	conn, err := net.Dial("tcp", f.proxyURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	br := bufio.NewReader(conn)
	_, _ = fmt.Fprintf(conn, "CONNECT example.com:%d HTTP/1.1\r\nHost: example.com:%d\r\nProxy-Authorization: Basic %s\r\n\r\n", f.port, f.port,
		base64.StdEncoding.EncodeToString([]byte("agent-1."+strings.Repeat("A", 43))))
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("refused CONNECT: %v %v", resp, err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	reads, calls := f.keys.reads.Load(), f.calls.Load()
	_, _ = fmt.Fprintf(conn, "GET http://example.com:%d/v1/chat/completions HTTP/1.1\r\nHost: example.com:%d\r\nProxy-Authorization: Basic %s\r\n\r\n", f.port, f.port,
		base64.StdEncoding.EncodeToString([]byte(f.token)))
	// Either the connection is already closed, or the request is refused with
	// a close; what it must never be is served.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if resp, err = http.ReadResponse(br, nil); err == nil {
		if resp.StatusCode != http.StatusBadRequest || !resp.Close {
			t.Fatalf("a later GET: %d, close %v", resp.StatusCode, resp.Close)
		}
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
	}
	if f.keys.reads.Load() != reads || f.calls.Load() != calls {
		t.Error("a key was read or the upstream called")
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := br.ReadByte(); err == nil {
		t.Error("the connection stayed open")
	}
}

func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

// A Gumloop ID token admits the Automation its org names, on the static-token listener alone, and every refusal carries a code.
func TestResolveAgentTokenGumloopOIDC(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	point, _ := key.PublicKey.Bytes()
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		x, y := base64.RawURLEncoding.EncodeToString(point[1:33]), base64.RawURLEncoding.EncodeToString(point[33:65])
		_, _ = fmt.Fprintf(w, `{"keys":[{"kty":"EC","crv":"P-256","kid":"k1","alg":"ES256","use":"sig","x":%q,"y":%q}]}`, x, y)
	}))
	defer jwks.Close()
	sign := func(org string, exp time.Time) string {
		header, payload := `{"alg":"ES256","kid":"k1"}`, fmt.Sprintf(`{"iss":%q,"aud":"gatehouse-broker","exp":%d,"gumloop_org_id":%q,"gumloop_owner_id":"owner-7","gumloop_owner_type":"user"}`, runnerid.GumloopIssuer, exp.Unix(), org)
		input := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload))
		digest := sha256.Sum256([]byte(input))
		r, s, _ := ecdsa.Sign(rand.Reader, key, digest[:])
		return input + "." + base64.RawURLEncoding.EncodeToString(append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...))
	}
	catalog := staticCatalog(t, 443, `{"id":"gl-1","name":"gumloop-one","owner":"platform-team","entries":["llm"],"gumloop":{"orgID":"org-1"}}`)
	verifier := &runnerid.GumloopVerifier{JWKSURL: jwks.URL, Issuer: runnerid.GumloopIssuer, Audience: "gatehouse-broker", Client: jwks.Client()}
	p := &Proxy{agentTokens: agenttoken.Either{Static: agenttoken.Static{Catalog: catalog}, OIDC: agenttoken.GumloopOIDC{Catalog: catalog, Verifier: verifier}}}
	peer := netip.MustParseAddr("192.0.2.7")
	ctx := withKinds(context.Background(), []string{brokercore.KindStaticToken})
	exp := time.Now().Add(time.Hour)
	scope, err := p.resolveScope(ctx, sign("org-1", exp), "", peer, nil, false)
	if err != nil || scope.AgentID != "gl-1" || scope.Automation != "gl-1" || scope.Pool != "automations" || scope.IdentityKind != brokercore.KindStaticToken ||
		scope.TokenSource != authorize.SourceGumloopOIDC || scope.TokenOwner != "owner-7" || claimsOf(scope).TokenOwner != "owner-7" || scope.NotAfter.IsZero() || scope.NotAfter.After(exp.Add(time.Second)) {
		t.Fatalf("%+v %v", scope, err)
	}
	for name, tc := range map[string]struct{ token, reason string }{
		"an unlisted org":     {sign("org-9", exp), agenttoken.ReasonOrgUnlisted},
		"an expired token":    {sign("org-1", time.Now().Add(-time.Minute)), "oidc_expired"},
		"a bad signature":     {sign("org-1", exp)[:len(sign("org-1", exp))-4] + "AAAA", "oidc_signature"},
		"a token of no shape": {"a.b.c", "oidc_malformed"},
	} {
		_, err := p.resolveScope(ctx, tc.token, "", peer, nil, false)
		if brokercore.DenialReason(err) != tc.reason {
			t.Errorf("%s: %q", name, brokercore.DenialReason(err))
		}
	}
	// A vault hint is refused for an ID token as for a static one.
	if _, err := p.resolveScope(ctx, sign("org-1", exp), "vault", peer, nil, false); brokercore.DenialReason(err) != agenttoken.ReasonMalformed {
		t.Errorf("hint: %v", err)
	}
}
