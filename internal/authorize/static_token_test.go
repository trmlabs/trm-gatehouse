package authorize

import (
	"context"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/authorize/authorizetest"
	"github.com/Infisical/agent-vault/internal/entitlement"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
)

const tokenAgentHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// tokenCatalog serves one automations pool by two harnesses: a Cursor run's
// session token and a static token. agent-1 holds a token and the tracker
// entry; auto-1 is a Cursor Automation, with the tracker and ledger entries.
func tokenCatalog(t *testing.T, withStaticHarness bool, agentBlock string) httpcatalog.Catalog {
	t.Helper()
	harnesses := `{"name":"cursor","trustDomain":{"issuer":"https://issuer.example","keys":"in-cluster","audience":"gatehouse"},
	  "identity":{"kind":"session-jwt","ownerKind":"ReplicaSet","namespaces":["cursor"],"imageDigests":["sha256:1111111111111111111111111111111111111111111111111111111111111111"],"requester":{"kind":"cursor-oidc"}},
	  "path":{"kind":"sidecar"},"authorization":{"mode":"automation","poolName":"automations"},"client":{"proxyEnv":"GATEHOUSE_HTTPS_PROXY","caFileEnv":"GATEHOUSE_CA_FILE"}}`
	if withStaticHarness {
		harnesses += `,{"name":"token-agents","identity":{"kind":"static-token"},"path":{"kind":"direct"},
		  "authorization":{"mode":"automation","poolName":"automations"},"client":{"proxyEnv":"EXAMPLE_PROXY","caFileEnv":"EXAMPLE_CA_FILE"}}`
	}
	entry := func(name string) string {
		return `{"name":"` + name + `","host":"api.` + name + `.example","pathPrefixes":["/v1/"],"methods":["GET"],"header":"Authorization","scheme":"Bearer",` +
			`"placeholder":"__vault_KEY__","key":{"mount":"gatehouse","path":"vendors/x","field":"key"},"pools":["automations"]}`
	}
	c, err := httpcatalog.Parse([]byte(`{"harnesses":[` + harnesses + `],
		"pools":[{"name":"automations","namespace":"cursor","serviceAccount":"worker","identity":"cursor-automation"}],
		"entries":[` + entry("tracker") + `,` + entry("ledger") + `],
		"automations":[{"id":"auto-1","name":"explorer","owner":"platform-team","entries":["tracker","ledger"]},` + agentBlock + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// tokenAgentExpires is inside the longest a token may live, and still ahead
// when the tests run.
var tokenAgentExpires = time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339)

var tokenAgent = `{"id":"agent-1","name":"agent-one","owner":"platform-team","entries":["tracker"],"tokenSHA256":["` + tokenAgentHash + `"],"expires":"` + tokenAgentExpires + `"}`

func TestTokenAgentIsDecidedForItsBlock(t *testing.T) {
	catalog := tokenCatalog(t, true, tokenAgent)
	pool, _ := catalog.Pool("automations")
	who, refusal := Resolve(context.Background(), pool, "", Claims{TokenAgent: "agent-1"}, nil, nil)
	if refusal != "" || who.Kind != "automation" || who.Subject != "agent-1" || who.AutomationName != "agent-one" || who.AutomationOwner != "platform-team" ||
		who.Source != SourceStaticToken || who.Automation != "agent-1" || who.Audited() != "" || who.BranchSegment() != "automation-agent-1" {
		t.Fatalf("%q %+v", refusal, who)
	}
	// Its entries are the block's, and the pool's grant is the ceiling.
	ctx := context.Background()
	for entry, allowed := range map[string]bool{"tracker": true, "ledger": false} {
		e, _ := catalog.Match("api."+entry+".example", 443, "GET", "/v1/x", "automations")
		d := Decide(ctx, &entitlement.Cache{}, pool, *e, who)
		if d.Allowed != allowed {
			t.Errorf("%s: %+v", entry, d)
		}
	}
	// A block with no write key keeps the pool's write grant, as a Cursor
	// Automation's does; the write key limits it the same way.
	if !who.MayWrite("tracker") {
		t.Error("a block with no write key lost the pool's grant")
	}
}

func TestTokenAgentRefusals(t *testing.T) {
	ctx := context.Background()
	for name, tc := range map[string]struct {
		catalog httpcatalog.Catalog
		session string
		claims  Claims
		want    string
	}{
		"a block with no token":              {tokenCatalog(t, true, tokenAgent), "", Claims{TokenAgent: "auto-1"}, "automation_unlisted"},
		"an unlisted agent":                  {tokenCatalog(t, true, tokenAgent), "", Claims{TokenAgent: "agent-9"}, "automation_unlisted"},
		"a pool with no static harness":      {tokenCatalog(t, false, tokenAgent), "", Claims{TokenAgent: "agent-1"}, "automation_unlisted"},
		"a runner session beside the token":  {tokenCatalog(t, true, tokenAgent), "run.token", Claims{TokenAgent: "agent-1"}, "session_unexpected"},
		"an attested requester with a token": {tokenCatalog(t, true, tokenAgent), "", Claims{TokenAgent: "agent-1", AttestedRequester: "someone"}, "requester_unexpected"},
	} {
		pool, _ := tc.catalog.Pool("automations")
		if _, got := Resolve(ctx, pool, tc.session, tc.claims, nil, &authorizetest.MemBinder{}); got != tc.want {
			t.Errorf("%s: %q", name, got)
		}
	}
}

// A Cursor run token that names a token agent's id is refused: the vendor's
// ids and the catalog's agent ids never alias, so a run cannot borrow a
// token agent's entries, and a token cannot borrow a run's.
func TestCursorRunCannotUseATokenAgentsBlock(t *testing.T) {
	catalog := tokenCatalog(t, true, tokenAgent)
	pool, _ := catalog.Pool("automations")
	runs := cursorRuns{
		"run-auto-1": automationRun("alice@example.com", "bc-1", "auto-1"),
		"run-agent":  automationRun("alice@example.com", "bc-2", "agent-1"),
	}
	resolve := func(token, run string) string {
		_, got := Resolve(context.Background(), pool, token, Claims{Pod: "pod-" + token, ClaimedRun: run}, runs, &authorizetest.MemBinder{})
		return got
	}
	if got := resolve("run-auto-1", "bc-1"); got != "" {
		t.Errorf("a Cursor Automation: %q", got)
	}
	if got := resolve("run-agent", "bc-2"); got != "automation_unlisted" {
		t.Errorf("a run naming a token agent: %q", got)
	}
}

var gumloopAgent = `{"id":"gl-1","name":"gumloop-one","owner":"platform-team","entries":["tracker"],"gumloop":{"orgID":"org-1"}}`

func TestGumloopAgentIsDecidedForItsBlockAndNamesItsSource(t *testing.T) {
	catalog := tokenCatalog(t, true, gumloopAgent)
	pool, _ := catalog.Pool("automations")
	who, refusal := Resolve(context.Background(), pool, "", Claims{TokenAgent: "gl-1", TokenSource: SourceGumloopOIDC}, nil, nil)
	if refusal != "" || who.Kind != "automation" || who.Subject != "gl-1" || who.Source != SourceGumloopOIDC || who.Automation != "gl-1" || who.Audited() != "" {
		t.Fatalf("%q %+v", refusal, who)
	}
	// An unnamed source stays a static token's.
	if who, _ = Resolve(context.Background(), pool, "", Claims{TokenAgent: "gl-1"}, nil, nil); who.Source != SourceStaticToken {
		t.Errorf("source %q", who.Source)
	}
	// A pool with no static harness serves no Gumloop agent either.
	bare, _ := tokenCatalog(t, false, gumloopAgent).Pool("automations")
	if _, got := Resolve(context.Background(), bare, "", Claims{TokenAgent: "gl-1", TokenSource: SourceGumloopOIDC}, nil, nil); got != "automation_unlisted" {
		t.Errorf("no static harness: %q", got)
	}
}

// An org-wide block's requests name the verified Gumloop owner, so one org's owners are told apart in the audit row.
func TestGumloopOwnerIsAuditedAsTheRunPerson(t *testing.T) {
	pool, _ := tokenCatalog(t, true, gumloopAgent).Pool("automations")
	who, refusal := Resolve(context.Background(), pool, "", Claims{TokenAgent: "gl-1", TokenSource: SourceGumloopOIDC, TokenOwner: "owner-7"}, nil, nil)
	if refusal != "" || who.Audited() != "owner-7" {
		t.Fatalf("%q %+v", refusal, who)
	}
	if who, _ = Resolve(context.Background(), pool, "", Claims{TokenAgent: "gl-1", TokenOwner: "owner-7"}, nil, nil); who.Audited() != "" {
		t.Errorf("a static token carried an owner: %q", who.Audited())
	}
}

func TestCursorRunCannotUseAGumloopAgentsBlock(t *testing.T) {
	pool, _ := tokenCatalog(t, true, gumloopAgent).Pool("automations")
	runs := cursorRuns{"run-gl": automationRun("alice@example.com", "bc-1", "gl-1")}
	if _, got := Resolve(context.Background(), pool, "run-gl", Claims{Pod: "pod-1", ClaimedRun: "bc-1"}, runs, &authorizetest.MemBinder{}); got != "automation_unlisted" {
		t.Errorf("a run naming a Gumloop agent: %q", got)
	}
}

func TestAttributeNamesAGumloopAgentAndNoRunBorrowsItsBlock(t *testing.T) {
	pool, _ := tokenCatalog(t, true, gumloopAgent).Pool("automations")
	got := Attribute(context.Background(), pool, "", Claims{TokenAgent: "gl-1", TokenSource: SourceGumloopOIDC}, nil)
	if got.Source != SourceGumloopOIDC || got.Automation != "gl-1" || got.AutomationName != "gumloop-one" {
		t.Fatalf("%+v", got)
	}
	runs := cursorRuns{"run-gl": automationRun("alice@example.com", "bc-1", "gl-1")}
	if got := Attribute(context.Background(), pool, "run-gl", Claims{}, runs); got.AutomationName != "" || got.AutomationOwner != "" {
		t.Errorf("a run naming a Gumloop agent was given its block's name: %+v", got)
	}
}
