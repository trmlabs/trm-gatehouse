package authorize

import (
	"context"
	"testing"

	"github.com/Infisical/agent-vault/internal/authorize/authorizetest"
	"github.com/Infisical/agent-vault/internal/entitlement"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/runnerid"
)

const automationGroup = "11111111-2222-3333-4444-555555555555"

// automationCatalog has one pool deciding per Automation, a T0 and a T1
// entry granted to it, and two Automations: one listing both entries, one
// listing only the T0 entry.
func automationCatalog(t *testing.T) httpcatalog.Catalog {
	t.Helper()
	entry := func(name, extra string) string {
		return `{"name":"` + name + `","host":"api.` + name + `.example","pathPrefixes":["/v1/"],"methods":["GET"],"header":"Authorization","scheme":"Bearer",` +
			`"placeholder":"__vault_KEY__","key":{"mount":"gatehouse","path":"vendors/x","field":"key"},"pools":["automations"]` + extra + `}`
	}
	c, err := httpcatalog.Parse([]byte(`{
		"pools":[{"name":"automations","namespace":"cursor","serviceAccount":"worker","identity":"cursor-automation","ceiling":"T1"}],
		"entries":[` + entry("tracker", "") + `,` + entry("ledger", `,"tier":"T1","requires":["`+automationGroup+`"]`) + `],
		"automations":[
			{"id":"auto-1","name":"explorer","owner":"alice@example.com","entries":["tracker","ledger"]},
			{"id":"auto-2","name":"auditor","owner":"gone@example.com","entries":["tracker","ledger"]},
			{"id":"auto-3","name":"reader","owner":"alice@example.com","entries":["tracker"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

var automationRuns = cursorRuns{
	"explorer": {Kind: runnerid.KindPerson, Subject: "alice@example.com", Owner: "user:1", Run: "bc-1", Source: "AUTOMATIONS", Automation: "auto-1"},
	"auditor":  {Kind: runnerid.KindAgent, Subject: "service_account:9", Owner: "service_account:9", Run: "bc-2", Source: "AUTOMATIONS", Automation: "auto-2"},
	"reader":   {Kind: runnerid.KindPerson, Subject: "alice@example.com", Owner: "user:1", Run: "bc-3", Source: "AUTOMATIONS", Automation: "auto-3"},
	"unlisted": {Kind: runnerid.KindPerson, Subject: "alice@example.com", Owner: "user:1", Run: "bc-4", Source: "AUTOMATIONS", Automation: "auto-9"},
	"web":      {Kind: runnerid.KindPerson, Subject: "alice@example.com", Owner: "user:1", Run: "bc-5", Source: "WEBSITE"},
	"slack":    {Kind: runnerid.KindPerson, Subject: "alice@example.com", Owner: "user:1", Run: "bc-6", Source: "SLACK"},
	"no-id":    {Kind: runnerid.KindPerson, Subject: "alice@example.com", Owner: "user:1", Run: "bc-7", Source: "AUTOMATIONS"},
	"no-src":   {Kind: runnerid.KindPerson, Subject: "alice@example.com", Owner: "user:1", Run: "bc-8", Automation: "auto-1"},
}

// directoryOf answers group lookups from a fixed table; a person not in it is
// a disabled account.
type directoryOf map[string][]string

func (d directoryOf) Lookup(_ context.Context, subject string, groups []string) (entitlement.Person, error) {
	member, ok := d[subject]
	if !ok {
		return entitlement.Person{ObjectID: "oid-" + subject}, nil
	}
	var in []string
	for _, g := range groups {
		for _, m := range member {
			if g == m {
				in = append(in, g)
			}
		}
	}
	return entitlement.Person{ObjectID: "oid-" + subject, Enabled: true, MemberOf: in}, nil
}

func TestAutomationRunNamesItsAutomation(t *testing.T) {
	pool, _ := automationCatalog(t).Pool("automations")
	who, refusal := Resolve(context.Background(), pool, "explorer", Claims{Pod: "pod-a", ClaimedRun: "bc-1"}, automationRuns, &authorizetest.MemBinder{})
	if refusal != "" || who.Kind != "automation" || who.Subject != "auto-1" || who.AutomationName != "explorer" ||
		who.AutomationOwner != "alice@example.com" || who.Source != "AUTOMATIONS" || who.Automation != "auto-1" || who.TokenSHA256 != "sha-explorer" {
		t.Fatalf("%q %+v", refusal, who)
	}
	// A service account's Automation is decided the same way: by the catalog.
	who, refusal = Resolve(context.Background(), pool, "auditor", Claims{Pod: "pod-b", ClaimedRun: "bc-2"}, automationRuns, &authorizetest.MemBinder{})
	if refusal != "" || who.Subject != "auto-2" || who.AutomationOwner != "gone@example.com" {
		t.Fatalf("service account automation: %q %+v", refusal, who)
	}
}

// Every request on an automation pool comes from a listed Automation, T0
// included; the refusal still records what the token said.
func TestAutomationPoolRefusesOtherRuns(t *testing.T) {
	pool, _ := automationCatalog(t).Pool("automations")
	for token, want := range map[string]string{
		"unlisted": "automation_unlisted",
		"web":      "not_automation",
		"slack":    "not_automation",
		"no-id":    "not_automation",
		"no-src":   "not_automation",
		"forged":   "session_token",
		"":         "session_missing",
	} {
		run := automationRuns[token]
		who, refusal := Resolve(context.Background(), pool, token, Claims{Pod: "pod-" + token, ClaimedRun: run.Run}, automationRuns, &authorizetest.MemBinder{})
		if refusal != want || who.Kind != "none" || who.AutomationName != "" {
			t.Errorf("%q: %q %+v, want %s", token, refusal, who, want)
		}
		if token != "forged" && token != "" && (who.Source != run.Source || who.Automation != run.Automation) {
			t.Errorf("%q: audit fields %+v", token, who)
		}
	}
}

func TestAutomationUsesOnlyItsEntriesOnItsOwnersAccount(t *testing.T) {
	catalog := automationCatalog(t)
	pool, _ := catalog.Pool("automations")
	cache := &entitlement.Cache{Source: directoryOf{"alice@example.com": {automationGroup}}}
	ctx := context.Background()
	decide := func(token, run, entry string) entitlement.Decision {
		t.Helper()
		who, refusal := Resolve(ctx, pool, token, Claims{Pod: "pod-" + token, ClaimedRun: run}, automationRuns, &authorizetest.MemBinder{})
		if refusal != "" {
			t.Fatalf("%s: %q", token, refusal)
		}
		e, err := catalog.Match("api."+entry+".example", 443, "GET", "/v1/x", "automations")
		if err != nil {
			t.Fatal(err)
		}
		return Decide(ctx, cache, pool, *e, who)
	}
	if d := decide("explorer", "bc-1", "tracker"); !d.Allowed || d.Outcome != "t0" {
		t.Errorf("explorer T0: %+v", d)
	}
	if d := decide("explorer", "bc-1", "ledger"); !d.Allowed || d.Outcome != "entitled" || d.ObjectID != "oid-alice@example.com" {
		t.Errorf("explorer T1 on its owner's account: %+v", d)
	}
	// Not listed for this Automation, though granted to the pool: refused, T0 too.
	if d := decide("reader", "bc-3", "ledger"); d.Allowed || d.Outcome != "automation_not_granted" || d.Tier != "T1" {
		t.Errorf("reader T1: %+v", d)
	}
	// An owner whose account is gone takes the Automation's tiered access with it.
	if d := decide("auditor", "bc-2", "ledger"); d.Allowed || d.Outcome != "account_disabled" {
		t.Errorf("auditor with a disabled owner: %+v", d)
	}
	if d := decide("auditor", "bc-2", "tracker"); !d.Allowed {
		t.Errorf("auditor T0: %+v", d)
	}
	// A requester that is not an Automation is never served on the pool.
	e, _ := catalog.Match("api.tracker.example", 443, "GET", "/v1/x", "automations")
	for _, who := range []Requester{{Kind: "none"}, {Kind: "person", Subject: "alice@example.com"}, {Kind: "automation", Subject: "auto-9"}} {
		if d := Decide(ctx, cache, pool, *e, who); d.Allowed || d.Outcome != "automation_not_granted" {
			t.Errorf("%+v: %+v", who, d)
		}
	}
}

// A person pool is unchanged: an Automation's run there is its person's, as
// before, and only the audit fields are new.
func TestPersonPoolIsUnchangedForAutomationRuns(t *testing.T) {
	who, refusal := Resolve(context.Background(), cursorPool, "explorer", Claims{Pod: "pod-a", ClaimedRun: "bc-1"}, automationRuns, &authorizetest.MemBinder{})
	if refusal != "" || who.Kind != "person" || who.Subject != "alice@example.com" || who.AutomationName != "" || who.Source != "AUTOMATIONS" || who.Automation != "auto-1" {
		t.Fatalf("%q %+v", refusal, who)
	}
	who, refusal = Resolve(context.Background(), cursorPool, "alice-1", Claims{Pod: "pod-b", ClaimedRun: "bc-1"}, runs, &authorizetest.MemBinder{})
	if refusal != "" || who.Kind != "person" || who.Source != "" || who.Automation != "" {
		t.Fatalf("person run: %q %+v", refusal, who)
	}
}
