package httpcatalog

import (
	"encoding/json"
	"strings"
	"testing"
)

func signedHarness(name, issuer string) map[string]any {
	return map[string]any{
		"name": name,
		"identity": map[string]any{"kind": "signed-token", "token": map[string]any{
			"issuer": issuer, "jwksURL": issuer + "/keys", "audiences": []any{"gatehouse"}, "algorithms": []any{"RS256", "ES256"},
			"maxLifetimeSeconds": 3600, "subjectClaim": "sub", "groupsClaim": "groups"}},
		"path":          map[string]any{"kind": "direct"},
		"authorization": map[string]any{"mode": "automation", "poolName": "example-workers"},
		"client":        map[string]any{"proxyEnv": "EXAMPLE_PROXY", "caFileEnv": "EXAMPLE_CA_FILE"},
	}
}

func signedCatalog() map[string]any {
	c := automationCatalog()
	c["harnesses"] = append(c["harnesses"].([]any), signedHarness("platform-a", "https://issuer-a.example"))
	c["automations"] = append(c["automations"].([]any), map[string]any{
		"id": "agent-a", "name": "agent-a", "owner": "platform-team", "entries": []any{"tracker"},
		"signedToken": map[string]any{"harness": "platform-a", "subject": "sa-1@example", "groups": []any{"team-a"}},
	})
	return c
}

func tokenRules(c map[string]any) map[string]any {
	return tokenHarness(c)["identity"].(map[string]any)["token"].(map[string]any)
}

func TestSignedTokenHarnessLoads(t *testing.T) {
	catalog, err := parseCatalog(t, signedCatalog())
	if err != nil {
		t.Fatal(err)
	}
	pool := mustPool(t, catalog, "example-workers")
	if _, ok := pool.StaticToken(); ok {
		t.Error("a signed-token harness reads as a static-token one")
	}
	if p := pool.Profile(); p.Identity.Kind != IdentitySessionJWT {
		t.Errorf("the Kubernetes harness is no longer the pool's profile: %+v", p)
	}
	h, ok := catalog.SignedTokenHarness("https://issuer-a.example")
	if !ok || h.Name != "platform-a" || h.Identity.Token.SubjectClaim != "sub" {
		t.Fatalf("%+v %v", h, ok)
	}
	if _, ok := catalog.SignedTokenHarness("https://other.example"); ok {
		t.Error("an issuer no harness names found one")
	}
	a, poolName, ok := catalog.SignedTokenAgent("platform-a", "sa-1@example")
	if !ok || a.ID != "agent-a" || poolName != "example-workers" || !a.HasOwnIdentity() || a.HasToken() {
		t.Fatalf("%+v %q %v", a, poolName, ok)
	}
	for _, miss := range [][2]string{{"platform-a", "sa-2@example"}, {"platform-b", "sa-1@example"}, {"", ""}} {
		if _, _, ok := catalog.SignedTokenAgent(miss[0], miss[1]); ok {
			t.Errorf("%v found an agent", miss)
		}
	}
	if !pool.AdmitsToken(a) {
		t.Error("the pool refuses its own harness's agent")
	}
	// A static or Gumloop block is not admitted by a signed-token harness alone, and a signed block not by a static one.
	if pool.AdmitsToken(Automation{ID: "x", TokenSHA256: []string{hashOf("x")}}) {
		t.Error("a pool with no static-token harness admitted a static-token block")
	}
	if pool.AdmitsToken(Automation{ID: "y", SignedToken: &SignedTokenIdentity{Harness: "platform-b", Subject: "s"}}) {
		t.Error("a block naming another harness was admitted")
	}
}

func TestSignedTokenPoolsHostSeveralPlatformsAndAStaticHarness(t *testing.T) {
	c := staticTokenCatalog()
	c["harnesses"] = append(c["harnesses"].([]any), signedHarness("platform-a", "https://issuer-a.example"), signedHarness("platform-b", "https://issuer-b.example"))
	c["automations"] = append(c["automations"].([]any),
		map[string]any{"id": "agent-a", "name": "agent-a", "owner": "platform-team", "entries": []any{"tracker"}, "signedToken": map[string]any{"harness": "platform-a", "subject": "s"}},
		map[string]any{"id": "agent-b", "name": "agent-b", "owner": "platform-team", "entries": []any{"tracker"}, "signedToken": map[string]any{"harness": "platform-b", "subject": "s"}})
	catalog, err := parseCatalog(t, c)
	if err != nil {
		t.Fatal(err)
	}
	// The same subject on two platforms is two agents.
	a, _, okA := catalog.SignedTokenAgent("platform-a", "s")
	b, _, okB := catalog.SignedTokenAgent("platform-b", "s")
	if !okA || !okB || a.ID != "agent-a" || b.ID != "agent-b" {
		t.Fatalf("%+v %+v", a, b)
	}
	pool := mustPool(t, catalog, "example-workers")
	if _, ok := pool.StaticToken(); !ok {
		t.Error("the static-token harness was lost")
	}
}

func TestSignedTokenHarnessRefusedAtLoad(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(c map[string]any)
		want   string
	}{
		"no token rules":                          {func(c map[string]any) { delete(tokenHarness(c)["identity"].(map[string]any), "token") }, "needs identity.token"},
		"a plain http issuer":                     {func(c map[string]any) { tokenRules(c)["issuer"] = "http://issuer-a.example" }, "issuer must be an HTTPS URL"},
		"an issuer with a query":                  {func(c map[string]any) { tokenRules(c)["issuer"] = "https://issuer-a.example?x=1" }, "no query"},
		"a plain http key URL":                    {func(c map[string]any) { tokenRules(c)["jwksURL"] = "http://issuer-a.example/keys" }, "jwksURL must be an HTTPS URL"},
		"no key source":                           {func(c map[string]any) { delete(tokenRules(c), "jwksURL") }, "exactly one of jwksURL and discovery"},
		"both key sources":                        {func(c map[string]any) { tokenRules(c)["discovery"] = true }, "exactly one of jwksURL and discovery"},
		"no audience":                             {func(c map[string]any) { tokenRules(c)["audiences"] = []any{} }, "audiences needs"},
		"a repeated audience":                     {func(c map[string]any) { tokenRules(c)["audiences"] = []any{"a", "a"} }, "invalid or repeated"},
		"an audience with a space":                {func(c map[string]any) { tokenRules(c)["audiences"] = []any{"a b"} }, "invalid or repeated"},
		"no algorithm":                            {func(c map[string]any) { tokenRules(c)["algorithms"] = []any{} }, "algorithms needs"},
		"algorithm none":                          {func(c map[string]any) { tokenRules(c)["algorithms"] = []any{"none"} }, "RS256 or ES256"},
		"an HMAC algorithm":                       {func(c map[string]any) { tokenRules(c)["algorithms"] = []any{"HS256"} }, "RS256 or ES256"},
		"no maximum lifetime":                     {func(c map[string]any) { delete(tokenRules(c), "maxLifetimeSeconds") }, "maxLifetimeSeconds"},
		"a lifetime of a week":                    {func(c map[string]any) { tokenRules(c)["maxLifetimeSeconds"] = 7 * 24 * 3600 }, "maxLifetimeSeconds"},
		"a negative clock skew":                   {func(c map[string]any) { tokenRules(c)["clockSkewSeconds"] = -1 }, "clockSkewSeconds"},
		"a huge clock skew":                       {func(c map[string]any) { tokenRules(c)["clockSkewSeconds"] = 3600 }, "clockSkewSeconds"},
		"no subject claim":                        {func(c map[string]any) { delete(tokenRules(c), "subjectClaim") }, "subjectClaim"},
		"the expiry as subject claim":             {func(c map[string]any) { tokenRules(c)["subjectClaim"] = "exp" }, "subjectClaim"},
		"groups from the subject":                 {func(c map[string]any) { tokenRules(c)["groupsClaim"] = "sub" }, "groupsClaim"},
		"a backoff over half the default key age": {func(c map[string]any) { tokenRules(c)["refreshBackoffSeconds"] = 1801 }, "at most half of keyMaxAgeSeconds"},
		"a backoff over half a set key age": {func(c map[string]any) {
			tokenRules(c)["keyMaxAgeSeconds"], tokenRules(c)["refreshBackoffSeconds"] = 60, 31
		}, "at most half of keyMaxAgeSeconds"},
		"a short key age with the default backoff": {func(c map[string]any) { tokenRules(c)["keyMaxAgeSeconds"] = 59 }, "keyMaxAgeSeconds"},
		"an issuer that is a trust domain's": {func(c map[string]any) {
			tokenRules(c)["issuer"] = "https://container.googleapis.com/v1/projects/p/locations/l/clusters/example-cluster"
			tokenRules(c)["jwksURL"] = "https://container.googleapis.com/keys"
		}, "trustDomain.issuer"},
		"required claims with a reserved name": {func(c map[string]any) { tokenRules(c)["requiredClaims"] = map[string]any{"aud": "x"} }, "requiredClaims"},
		"required claims naming the subject":   {func(c map[string]any) { tokenRules(c)["requiredClaims"] = map[string]any{"sub": "x"} }, "requiredClaims"},
		"a required claim with an empty value": {func(c map[string]any) { tokenRules(c)["requiredClaims"] = map[string]any{"tenant": ""} }, "requiredClaims"},
		"a required claim with a spaced value": {func(c map[string]any) { tokenRules(c)["requiredClaims"] = map[string]any{"tenant": "a b"} }, "requiredClaims"},
		"a short key age":                      {func(c map[string]any) { tokenRules(c)["keyMaxAgeSeconds"] = 5 }, "keyMaxAgeSeconds"},
		"a backoff of a day":                   {func(c map[string]any) { tokenRules(c)["refreshBackoffSeconds"] = 99999 }, "refreshBackoffSeconds"},
		"an unknown token field":               {func(c map[string]any) { tokenRules(c)["insecureSkipVerify"] = true }, "unknown field"},
		"a Kubernetes namespace": {func(c map[string]any) {
			tokenHarness(c)["identity"].(map[string]any)["namespaces"] = []any{"cursor"}
		}, "takes no ownerKind"},
		"a trust domain": {func(c map[string]any) {
			tokenHarness(c)["trustDomain"] = map[string]any{"issuer": "https://i.example", "keys": "remote", "audience": "a"}
		}, "no trustDomain"},
		"a sidecar path":  {func(c map[string]any) { tokenHarness(c)["path"] = map[string]any{"kind": "sidecar"} }, "reaches the broker directly"},
		"person mode":     {func(c map[string]any) { tokenHarness(c)["authorization"].(map[string]any)["mode"] = "person" }, "authorizes the automation"},
		"no client names": {func(c map[string]any) { delete(tokenHarness(c), "client") }, "environment variable names"},
		"a token on another kind": {func(c map[string]any) {
			harnessAt(c, 0)["identity"].(map[string]any)["token"] = tokenRules(c)
		}, "identity.token is for signed-token"},
		"a second harness for one issuer": {func(c map[string]any) {
			c["harnesses"] = append(c["harnesses"].([]any), signedHarness("platform-a2", "https://issuer-a.example"))
		}, "both name issuer"},
		"an automation naming no harness": {func(c map[string]any) {
			c["automations"].([]any)[2].(map[string]any)["signedToken"].(map[string]any)["harness"] = "platform-z"
		}, "not declared"},
		"two automations for one subject": {func(c map[string]any) {
			c["automations"] = append(c["automations"].([]any), map[string]any{"id": "agent-dup", "name": "dup", "owner": "platform-team", "entries": []any{"tracker"},
				"signedToken": map[string]any{"harness": "platform-a", "subject": "sa-1@example"}})
		}, "same signedToken harness and subject"},
		"a block with a token hash too": {func(c map[string]any) {
			c["automations"].([]any)[2].(map[string]any)["tokenSHA256"] = []any{hashOf("x")}
			c["automations"].([]any)[2].(map[string]any)["expires"] = soonText()
		}, "a block has one"},
		"a subject with a space": {func(c map[string]any) {
			c["automations"].([]any)[2].(map[string]any)["signedToken"].(map[string]any)["subject"] = "a b"
		}, "plain value"},
		"a repeated group": {func(c map[string]any) {
			c["automations"].([]any)[2].(map[string]any)["signedToken"].(map[string]any)["groups"] = []any{"g", "g"}
		}, "invalid or repeated"},
		"the Gumloop issuer": {func(c map[string]any) {
			tokenRules(c)["issuer"] = "https://api.gumloop.com"
			tokenRules(c)["jwksURL"] = "https://api.gumloop.com/keys"
		}, "cannot be claimed"},
		"the Google issuer": {func(c map[string]any) {
			tokenRules(c)["issuer"] = "https://accounts.google.com"
			tokenRules(c)["jwksURL"] = "https://accounts.google.com/keys"
		}, "cannot be claimed"},
		"groups with no groupsClaim":  {func(c map[string]any) { delete(tokenRules(c), "groupsClaim") }, "has no groupsClaim"},
		"subagents on a signed block": {func(c map[string]any) { c["automations"].([]any)[2].(map[string]any)["subagents"] = 2 }, "not one with"},
	} {
		t.Run(name, func(t *testing.T) {
			c := signedCatalog()
			tc.mutate(c)
			if _, err := parseCatalog(t, c); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

func TestSignedTokenHarnessOnAPoolThatIsNotAutomationIsRefused(t *testing.T) {
	c := harnessCatalog()
	h := signedHarness("platform-a", "https://issuer-a.example")
	h["authorization"].(map[string]any)["poolName"] = "claude-sessions"
	c["harnesses"] = append(c["harnesses"].([]any), h)
	if _, err := parseCatalog(t, c); err == nil {
		t.Fatal("a signed-token harness on a person pool loaded")
	}
}

func TestTolerantLoadDropsASignedTokenPartAndKeepsTheRest(t *testing.T) {
	c := signedCatalog()
	tokenRules(c)["algorithms"] = []any{"none"}
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	catalog, dropped, err := ParseTolerant(data)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := catalog.SignedTokenHarness("https://issuer-a.example"); ok {
		t.Error("a harness that fails validation was kept")
	}
	var harness, automation bool
	for _, d := range dropped {
		harness = harness || (d.Kind == "harness" && d.Name == "platform-a")
		automation = automation || (d.Kind == "automation" && d.Name == "agent-a")
	}
	if !harness || !automation {
		t.Errorf("dropped %+v: the harness and the block that names it should both go", dropped)
	}
	if _, ok := catalog.Automation("auto-1"); !ok {
		t.Error("an unrelated Automation was dropped with it")
	}
}

func TestTolerantLoadDropsGroupsUnderAHarnessWithNoGroupsClaim(t *testing.T) {
	c := signedCatalog()
	delete(tokenRules(c), "groupsClaim")
	data, _ := json.Marshal(c)
	catalog, dropped, err := ParseTolerant(data)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := catalog.SignedTokenAgent("platform-a", "sa-1@example"); ok {
		t.Error("a block listing groups under a harness with no groupsClaim was kept")
	}
	var found bool
	for _, d := range dropped {
		found = found || (d.Kind == "automation" && d.Name == "agent-a")
	}
	if !found {
		t.Errorf("dropped %+v", dropped)
	}
}

func TestClockSkewSecondsKeepsZeroApartFromUnset(t *testing.T) {
	for name, tc := range map[string]struct {
		set  bool
		val  int
		want int
	}{"unset": {false, 0, -1}, "zero": {true, 0, 0}, "positive": {true, 90, 90}} {
		c := signedCatalog()
		if tc.set {
			tokenRules(c)["clockSkewSeconds"] = tc.val
		}
		catalog, err := parseCatalog(t, c)
		if err != nil {
			t.Fatal(err)
		}
		h, _ := catalog.SignedTokenHarness("https://issuer-a.example")
		got := h.Identity.Token.ClockSkewSeconds
		if (tc.want == -1 && got != nil) || (tc.want >= 0 && (got == nil || *got != tc.want)) {
			t.Errorf("%s: %v", name, got)
		}
	}
}

func TestSignedTokenHarnessLoadsRequiredClaimsAndAnEvenBackoff(t *testing.T) {
	c := signedCatalog()
	tokenRules(c)["requiredClaims"] = map[string]any{"tenant": "acme"}
	tokenRules(c)["keyMaxAgeSeconds"], tokenRules(c)["refreshBackoffSeconds"] = 60, 30
	catalog, err := parseCatalog(t, c)
	if err != nil {
		t.Fatal(err)
	}
	h, _ := catalog.SignedTokenHarness("https://issuer-a.example")
	if h.Identity.Token.RequiredClaims["tenant"] != "acme" {
		t.Errorf("%+v", h.Identity.Token)
	}
}

func TestTolerantLoadDropsOnlyASignedHarnessThatNamesATrustDomainIssuer(t *testing.T) {
	c := signedCatalog()
	tokenRules(c)["issuer"] = "https://container.googleapis.com/v1/projects/p/locations/l/clusters/example-cluster"
	tokenRules(c)["jwksURL"] = "https://container.googleapis.com/keys"
	data, _ := json.Marshal(c)
	catalog, dropped, err := ParseTolerant(data)
	if err != nil {
		t.Fatalf("one colliding harness refused the whole version: %v", err)
	}
	if _, ok := catalog.SignedTokenHarness("https://container.googleapis.com/v1/projects/p/locations/l/clusters/example-cluster"); ok {
		t.Error("the colliding signed-token harness was kept")
	}
	var harness bool
	for _, d := range dropped {
		harness = harness || (d.Kind == "harness" && d.Name == "platform-a")
		if d.Kind == "harness" && d.Name != "platform-a" {
			t.Errorf("a Kubernetes harness was dropped with it: %+v", d)
		}
	}
	if !harness {
		t.Errorf("dropped %+v", dropped)
	}
	if _, ok := catalog.Automation("auto-1"); !ok {
		t.Error("an unrelated Automation was dropped")
	}
}
