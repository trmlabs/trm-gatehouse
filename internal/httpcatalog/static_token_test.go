package httpcatalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// soonText is an expiry a token block may carry: inside the longest a token
// may live.
func soonText() string {
	return time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339)
}

func hashOf(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// staticTokenCatalog is automationCatalog with a second harness on the same
// pool, which proves a client with a token instead of a Pod, and one
// Automation block that carries a token hash.
func staticTokenCatalog() map[string]any {
	c := automationCatalog()
	c["harnesses"] = append(c["harnesses"].([]any), map[string]any{
		"name":          "token-agents",
		"identity":      map[string]any{"kind": "static-token"},
		"path":          map[string]any{"kind": "direct"},
		"authorization": map[string]any{"mode": "automation", "poolName": "example-workers"},
		"client":        map[string]any{"proxyEnv": "EXAMPLE_PROXY", "caFileEnv": "EXAMPLE_CA_FILE"},
	})
	c["automations"] = append(c["automations"].([]any), map[string]any{
		"id": "agent-1", "name": "agent-one", "owner": "platform-team", "entries": []any{"tracker"},
		"tokenSHA256": []any{hashOf("agent-1.secret-a")}, "expires": soonText(),
	})
	return c
}

func tokenHarness(c map[string]any) map[string]any {
	return harnessAt(c, len(c["harnesses"].([]any))-1)
}

// The automations pool is the same pool for a Cursor run and for a token
// agent: the harness carries how the agent proves itself, so a second platform
// is catalog data, not a second pool.
func TestStaticTokenHarnessSharesTheAutomationPool(t *testing.T) {
	catalog, err := parseCatalog(t, staticTokenCatalog())
	if err != nil {
		t.Fatal(err)
	}
	if n := len(catalog.Pools()); n != 3 {
		t.Fatalf("pools %d", n)
	}
	pool, _ := catalog.Pool("example-workers")
	// The Kubernetes profile is still the pool's, so a Pod is admitted by it.
	if p := pool.Profile(); p.Identity.Kind != IdentitySessionJWT || p.RequesterKind() != RequesterCursorOIDC || p.Authorization.Mode != AuthorizeAutomation {
		t.Fatalf("pool profile %+v", p)
	}
	static, ok := pool.StaticToken()
	if !ok || static.Identity.Kind != IdentityStaticToken || static.Path.Kind != PathDirect || static.Client.ProxyEnv != "EXAMPLE_PROXY" {
		t.Fatalf("static profile %+v", static)
	}
	if _, ok := mustPool(t, catalog, "claude-sessions").StaticToken(); ok {
		t.Error("a pool with no static harness reports one")
	}
	a, poolName, ok := catalog.StaticAgent("agent-1")
	if !ok || poolName != "example-workers" || !a.Uses("tracker") || a.Uses("vendor") {
		t.Fatalf("static agent %+v %q %v", a, poolName, ok)
	}
	// A block with no token hash is a Cursor Automation: no token reaches it.
	if _, _, ok := catalog.StaticAgent("auto-1"); ok {
		t.Error("an Automation with no tokenSHA256 is reachable by token")
	}
	if _, _, ok := catalog.StaticAgent("nobody"); ok {
		t.Error("an unlisted id is reachable by token")
	}
	// The pool still decides per Automation for both kinds of agent.
	if got, ok := pool.Automation("agent-1"); !ok || got.ID != "agent-1" {
		t.Error("the pool does not list the token agent's block")
	}
}

func mustPool(t *testing.T, c Catalog, name string) Pool {
	t.Helper()
	p, ok := c.Pool(name)
	if !ok {
		t.Fatalf("no pool %q", name)
	}
	return p
}

// A pool with only a static-token harness has no Kubernetes profile to admit
// a Pod by: Profile is the static one, whose empty trust domain matches no
// issuer, so a Pod is never admitted into it.
func TestStaticTokenOnlyPoolAdmitsNoPod(t *testing.T) {
	catalog, err := parseCatalog(t, withoutHarness(staticTokenCatalog(), "cursor"))
	if err != nil {
		t.Fatal(err)
	}
	pool := mustPool(t, catalog, "example-workers")
	if p := pool.Profile(); p.Identity.Kind != IdentityStaticToken || p.TrustDomain.Issuer != "" {
		t.Fatalf("profile %+v", p)
	}
}

func withoutHarness(c map[string]any, name string) map[string]any {
	var kept []any
	for _, h := range c["harnesses"].([]any) {
		if h.(map[string]any)["name"] != name {
			kept = append(kept, h)
		}
	}
	c["harnesses"] = kept
	return c
}

func TestStaticTokenHarnessRefusedAtLoad(t *testing.T) {
	for name, mutate := range map[string]func(c map[string]any){
		"a trust domain": func(c map[string]any) {
			tokenHarness(c)["trustDomain"] = map[string]any{"issuer": "https://issuer.example", "keys": "remote", "audience": "gatehouse"}
		},
		"an owner kind": func(c map[string]any) {
			tokenHarness(c)["identity"].(map[string]any)["ownerKind"] = "Job"
		},
		"namespaces": func(c map[string]any) {
			tokenHarness(c)["identity"].(map[string]any)["namespaces"] = []any{"cursor"}
		},
		"image digests": func(c map[string]any) {
			tokenHarness(c)["identity"].(map[string]any)["imageDigests"] = []any{digestA}
		},
		"an image prefix": func(c map[string]any) {
			tokenHarness(c)["identity"].(map[string]any)["imagePrefix"] = "example/"
		},
		"a requester": func(c map[string]any) {
			tokenHarness(c)["identity"].(map[string]any)["requester"] = map[string]any{"kind": "cursor-oidc"}
		},
		"a sidecar path": func(c map[string]any) { tokenHarness(c)["path"] = map[string]any{"kind": "sidecar"} },
		"a cross-cluster path": func(c map[string]any) {
			tokenHarness(c)["path"] = map[string]any{"kind": "direct", "crossCluster": true}
		},
		"pool authorization": func(c map[string]any) {
			tokenHarness(c)["authorization"].(map[string]any)["mode"] = "pool"
		},
		"person authorization": func(c map[string]any) {
			tokenHarness(c)["authorization"].(map[string]any)["mode"] = "person"
		},
		"no client names": func(c map[string]any) { delete(tokenHarness(c), "client") },
		"a second static harness": func(c map[string]any) {
			second := map[string]any{}
			b, _ := json.Marshal(tokenHarness(c))
			_ = json.Unmarshal(b, &second)
			second["name"] = "more-token-agents"
			c["harnesses"] = append(c["harnesses"].([]any), second)
		},
		"another harness of the same kind on the pool": func(c map[string]any) {
			second := map[string]any{}
			b, _ := json.Marshal(harnessAt(c, 0))
			_ = json.Unmarshal(b, &second)
			second["name"] = "cursor-two"
			c["harnesses"] = append(c["harnesses"].([]any), second)
		},
		"the pool of a person harness": func(c map[string]any) {
			tokenHarness(c)["authorization"].(map[string]any)["poolName"] = "claude-sessions"
		},
		"a direct path on a Pod harness": func(c map[string]any) { harnessAt(c, 0)["path"] = map[string]any{"kind": "direct"} },
	} {
		c := staticTokenCatalog()
		mutate(c)
		if _, err := parseCatalog(t, c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestAutomationTokenFields(t *testing.T) {
	good := hashOf("agent-1.secret-b")
	other := hashOf("agent-1.secret-c")
	now := time.Now().UTC()
	// expires "" is the default, a time inside the cap; "none" leaves the key out.
	for name, tc := range map[string]struct {
		token   []any
		expires string
		ok      bool
	}{
		"one hash":                 {[]any{good}, "", true},
		"two hashes":               {[]any{good, other}, "", true},
		"an expiry inside the cap": {[]any{good}, now.Add(MaxTokenLifetime - time.Hour).Format(time.RFC3339), true},
		"an expiry already passed": {[]any{good}, "2020-01-01T00:00:00Z", true},
		"no expiry":                {[]any{good}, "none", false},
		"the zero time":            {[]any{good}, "0001-01-01T00:00:00Z", false},
		"an expiry past the cap":   {[]any{good}, now.Add(MaxTokenLifetime + 48*time.Hour).Format(time.RFC3339), false},
		"a far-off expiry":         {[]any{good}, "2999-01-01T00:00:00Z", false},
		"three hashes":             {[]any{good, other, hashOf("x")}, "", false},
		"a repeated hash":          {[]any{good, good}, "", false},
		"upper-case hex":           {[]any{strings.ToUpper(good)}, "", false},
		"a short hash":             {[]any{good[:63]}, "", false},
		"not hex":                  {[]any{strings.Repeat("g", 64)}, "", false},
		"expiry no token":          {nil, "", false},
		"a date, not a time":       {[]any{good}, "2031-01-02", false},
		"an empty hash":            {[]any{""}, "", false},
	} {
		c := staticTokenCatalog()
		block := c["automations"].([]any)[2].(map[string]any)
		block["tokenSHA256"] = tc.token
		if tc.token == nil {
			delete(block, "tokenSHA256")
		}
		switch tc.expires {
		case "":
		case "none":
			delete(block, "expires")
		default:
			block["expires"] = tc.expires
		}
		_, err := parseCatalog(t, c)
		if (err == nil) != tc.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestAutomationMatchTokenAndExpiry(t *testing.T) {
	c := staticTokenCatalog()
	block := c["automations"].([]any)[2].(map[string]any)
	block["tokenSHA256"] = []any{hashOf("agent-1.old"), hashOf("agent-1.new")}
	expires := time.Now().Add(45 * 24 * time.Hour).UTC().Truncate(time.Second)
	block["expires"] = expires.Format(time.RFC3339)
	catalog, err := parseCatalog(t, c)
	if err != nil {
		t.Fatal(err)
	}
	a, _, _ := catalog.StaticAgent("agent-1")
	for token, want := range map[string]bool{"agent-1.old": true, "agent-1.new": true, "agent-1.other": false, "": false, "agent-1.old" + " ": false} {
		if got := a.MatchToken(token); got != want {
			t.Errorf("%q: %v", token, got)
		}
	}
	if want := expires; !a.TokenExpires().Equal(want) {
		t.Errorf("expires %v", a.TokenExpires())
	}
	if (Automation{}).MatchToken("anything") {
		t.Error("a block with no hash matches a token")
	}
}

// A tolerant load drops a bad token harness or block by itself, and never
// leaves a token agent reachable without its harness.
func TestTolerantStaticTokenParts(t *testing.T) {
	c := staticTokenCatalog()
	tokenHarness(c)["identity"].(map[string]any)["namespaces"] = []any{"cursor"}
	data, _ := json.Marshal(c)
	catalog, dropped, err := ParseTolerant(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(dropped) != 1 || dropped[0].Kind != "harness" || dropped[0].Name != "token-agents" {
		t.Fatalf("dropped %+v", dropped)
	}
	if _, _, ok := catalog.StaticAgent("agent-1"); ok {
		t.Error("a token agent is reachable with its harness dropped")
	}

	c = staticTokenCatalog()
	c["automations"].([]any)[2].(map[string]any)["tokenSHA256"] = []any{"not-a-hash"}
	data, _ = json.Marshal(c)
	catalog, dropped, err = ParseTolerant(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(dropped) != 1 || dropped[0].Kind != "automation" || dropped[0].Name != "agent-1" {
		t.Fatalf("dropped %+v", dropped)
	}
	if _, _, ok := catalog.StaticAgent("agent-1"); ok {
		t.Error("a dropped block is reachable")
	}

	// Two harnesses of one kind on a pool are both dropped, as any conflict is.
	c = staticTokenCatalog()
	second := map[string]any{}
	b, _ := json.Marshal(tokenHarness(c))
	_ = json.Unmarshal(b, &second)
	second["name"] = "more-token-agents"
	c["harnesses"] = append(c["harnesses"].([]any), second)
	data, _ = json.Marshal(c)
	if _, dropped, err = ParseTolerant(data); err != nil || len(dropped) < 2 {
		t.Fatalf("dropped %+v err %v", dropped, err)
	}
}

// Only a static-token harness may share a pool with a Kubernetes harness, so
// two Kubernetes harnesses never share one, whatever modes a later kind has.
func TestSharePoolNeedsExactlyOneStaticToken(t *testing.T) {
	h := func(kind string) Harness {
		return Harness{Identity: HarnessIdentity{Kind: kind}, Authorization: HarnessAuthorization{Mode: AuthorizeAutomation}}
	}
	for name, tc := range map[string]struct {
		a, b Harness
		want bool
	}{
		"Kubernetes and static":     {h(IdentitySessionJWT), h(IdentityStaticToken), true},
		"static and Kubernetes":     {h(IdentityStaticToken), h(IdentitySessionJWT), true},
		"two static":                {h(IdentityStaticToken), h(IdentityStaticToken), false},
		"two Kubernetes, same kind": {h(IdentitySessionJWT), h(IdentitySessionJWT), false},
		"two Kubernetes kinds":      {h(IdentitySessionJWT), h(IdentityPodToken), false},
	} {
		if got := sharePool(tc.a, tc.b); got != tc.want {
			t.Errorf("%s: %v", name, got)
		}
	}
	pool := h(IdentityStaticToken)
	pool.Authorization.Mode = AuthorizePool
	if sharePool(h(IdentitySessionJWT), pool) {
		t.Error("a pool-mode harness shares a pool")
	}
}

// The cap is measured from the time the catalog loads: an expiry exactly the
// cap away loads, a second further refuses, and the refusal says why.
func TestTokenExpiryCapBoundary(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	tokenClock = func() time.Time { return now }
	t.Cleanup(func() { tokenClock = time.Now })
	for name, tc := range map[string]struct {
		expires string
		want    string // a fragment of the refusal, "" when the catalog loads
	}{
		"at the cap":          {now.Add(MaxTokenLifetime).Format(time.RFC3339), ""},
		"one second past":     {now.Add(MaxTokenLifetime + time.Second).Format(time.RFC3339), "longest a token may live"},
		"the zero time":       {"0001-01-01T00:00:00Z", "zero time"},
		"missing":             {"none", "expires is required"},
		"zero time, any zone": {"0001-01-01T00:00:00+00:00", "zero time"},
	} {
		c := staticTokenCatalog()
		block := c["automations"].([]any)[2].(map[string]any)
		if tc.expires == "none" {
			delete(block, "expires")
		} else {
			block["expires"] = tc.expires
		}
		_, err := parseCatalog(t, c)
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: got %v, want a refusal naming %q", name, err, tc.want)
		}
	}
}
