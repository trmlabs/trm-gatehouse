package workloadidentity

import (
	"testing"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

type fakeNamespaces map[string]string // namespace to pool, in remoteIssuer

func (f fakeNamespaces) PoolFor(namespace, issuer string) (string, bool) {
	pool, ok := f[namespace]
	return pool, ok && issuer == remoteIssuer
}

func (f fakeNamespaces) Namespaces(issuer string) []string {
	var out []string
	for ns := range f {
		if issuer == remoteIssuer {
			out = append(out, ns)
		}
	}
	return out
}

// catalogProxy is the proxy fixture with no static profiles: the catalog says which namespaces the binding serves.
func catalogProxy(t *testing.T, mutate func(*Config)) *proxyFixture {
	t.Helper()
	p := setupProxy(t)
	c := p.r.config
	c.Bindings = append([]Binding(nil), c.Bindings...)
	proxy := *c.Bindings[1].Proxy
	proxy.Profiles, proxy.CatalogPools = nil, true
	c.Bindings[1].Proxy = &proxy
	if mutate != nil {
		mutate(&c)
	}
	r, err := New(c, &fakeStore{status: "active", role: "proxy"})
	if err != nil {
		t.Fatal(err)
	}
	r.profiles.Store(p.r.profiles.Load())
	r.SetNamespaces(fakeNamespaces{"agent-sandboxes": "sandboxes", "team-a-sandboxes": "team-a"})
	p.r = r
	return p
}

func TestCatalogPoolsServeCatalogNamespaces(t *testing.T) {
	p := catalogProxy(t, nil)
	token := p.rc.token(p.rc.claims())
	if scope, err := p.r.Attest(p.ctx(t, p.a), token, linkIP); err != nil || scope.Pool != "sandboxes" {
		t.Fatalf("developers: %v %+v", err, scope)
	}
	teamA := p.a
	teamA.Namespace, teamA.Profile = "team-a-sandboxes", "agent-sandbox-team-a"
	if scope, err := p.r.Attest(p.ctx(t, teamA), token, linkIP); err != nil || scope.Pool != "team-a" {
		t.Fatalf("team-a: %v %+v", err, scope)
	}
	id, err := p.r.IdentifyProxy(p.ctx(t, p.a), token, linkIP)
	if err != nil || len(id.Namespaces) != 2 {
		t.Fatalf("served namespaces: %v %+v", err, id)
	}
}

func TestCatalogPoolsRefusals(t *testing.T) {
	token := func(p *proxyFixture) string { return p.rc.token(p.rc.claims()) }
	reason := func(p *proxyFixture, a Attestation) string {
		_, err := p.r.Attest(p.ctx(t, a), token(p), linkIP)
		if err == nil {
			t.Fatal("admitted")
		}
		return brokercore.DenialReason(err)
	}
	p := catalogProxy(t, nil)
	unclaimed := p.a
	unclaimed.Namespace = "other-sandboxes"
	if got := reason(p, unclaimed); got != "catalog_namespace" {
		t.Errorf("namespace no pool claims: %q", got)
	}
	wrong := p.a
	wrong.Profile = "agent-sandbox-team-a"
	if got := reason(p, wrong); got != "attestation_profile" {
		t.Errorf("another pool's profile: %q", got)
	}
	// No catalog source loaded: nothing is claimed.
	p.r.namespaces.Store(nil)
	if got := reason(p, p.a); got != "catalog_namespace" {
		t.Errorf("no catalog source: %q", got)
	}
	// Without catalogPools the old refusal stands.
	static := setupProxy(t)
	static.r.SetNamespaces(fakeNamespaces{"other-sandboxes": "sandboxes"})
	if got := reason(static, unclaimed); got != "attestation_namespace" {
		t.Errorf("static binding: %q", got)
	}
	// A namespace another binding lists by hand is not the catalog binding's.
	other := catalogProxy(t, func(c *Config) {
		c.Bindings = append(c.Bindings, Binding{
			Namespace: "second-edge", ServiceAccount: "second-edge", ServiceAccountUID: "second-account-uid",
			AgentID: "agent", VaultID: "vault", TrustDomain: "agent-sandbox",
			Proxy: &ProxyBinding{Profiles: []ProxyProfile{{Namespace: "agent-sandboxes", Profile: "example-sandbox-profile", Pool: "sandboxes"}},
				OwnerKind: "Sandbox", ImageDigests: []string{workerDigest}, SourceCIDRs: []string{"192.0.2.0/24"}},
		})
	})
	if got := reason(other, other.a); got != "catalog_namespace" {
		t.Errorf("namespace listed by another binding: %q", got)
	}
	if id, err := other.r.IdentifyProxy(other.ctx(t, other.a), token(other), linkIP); err != nil || len(id.Namespaces) != 1 || id.Namespaces[0] != "team-a-sandboxes" {
		t.Errorf("served namespaces: %v %+v", err, id)
	}
}

func TestOneCatalogPoolsBindingPerTrustDomain(t *testing.T) {
	p := setupProxy(t)
	c := p.r.config
	c.Bindings = append([]Binding(nil), c.Bindings...)
	for i := 0; i < 2; i++ {
		b := Binding{Namespace: "edge", ServiceAccount: "edge", ServiceAccountUID: "uid", AgentID: "agent", VaultID: "vault", TrustDomain: "agent-sandbox",
			Proxy: &ProxyBinding{CatalogPools: true, OwnerKind: "Sandbox", ImageDigests: []string{workerDigest}, SourceCIDRs: []string{"192.0.2.0/24"}}}
		b.ServiceAccount += string(rune('a' + i))
		c.Bindings = append(c.Bindings, b)
	}
	if _, err := New(c, &fakeStore{status: "active", role: "proxy"}); err == nil {
		t.Fatal("two catalogPools bindings of one trust domain accepted")
	}
}
