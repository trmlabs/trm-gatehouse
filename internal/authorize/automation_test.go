package authorize

import (
	"context"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/authorize/authorizetest"
	"github.com/Infisical/agent-vault/internal/entitlement"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/runnerid"
)

const (
	automationGroup = "11111111-2222-3333-4444-555555555555"
	teamGroup       = "66666666-7777-8888-9999-000000000000"
)

// automationCatalog has one pool deciding per Automation, a T0 and a T1
// entry granted to it, and three Automations: auto-1 (alice's, which her team
// may also run), auto-2 (owned by an account that is gone) and auto-3
// (alice's alone, the T0 entry only).
func automationCatalog(t *testing.T) httpcatalog.Catalog {
	t.Helper()
	entry := func(name, extra string) string {
		return `{"name":"` + name + `","host":"api.` + name + `.example","pathPrefixes":["/v1/"],"methods":["GET"],"header":"Authorization","scheme":"Bearer",` +
			`"placeholder":"__vault_KEY__","key":{"mount":"gatehouse","path":"vendors/x","field":"key"},"pools":["automations"]` + extra + `}`
	}
	c, err := httpcatalog.Parse([]byte(`{
		"pools":[{"name":"automations","namespace":"cursor","serviceAccount":"worker","identity":"cursor-automation","ceiling":"T2"}],
		"entries":[` + entry("tracker", "") + `,` + entry("ledger", `,"tier":"T1","requires":["`+automationGroup+`"]`) + `,` +
		entry("vault", `,"tier":"T2","requires":["`+automationGroup+`"]`) + `],
		"automations":[
			{"id":"auto-1","name":"explorer","owner":"alice@example.com","runnerGroup":"` + teamGroup + `","entries":["tracker","ledger","vault"]},
			{"id":"auto-2","name":"auditor","owner":"gone@example.com","entries":["tracker","ledger"]},
			{"id":"auto-3","name":"reader","owner":"alice@example.com","entries":["tracker"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func automationRun(person, run, automation string) runnerid.Session {
	return runnerid.Session{Kind: runnerid.KindPerson, Subject: person, Owner: "user:" + person, Run: run, Source: "AUTOMATIONS", Automation: automation}
}

var automationRuns = cursorRuns{
	"explorer":       automationRun("alice@example.com", "bc-1", "auto-1"),
	"auditor":        automationRun("gone@example.com", "bc-2", "auto-2"),
	"reader":         automationRun("alice@example.com", "bc-3", "auto-3"),
	"bob-explorer":   automationRun("bob@example.com", "bc-10", "auto-1"),
	"carol-explorer": automationRun("carol@example.com", "bc-11", "auto-1"),
	"dave-explorer":  automationRun("dave@example.com", "bc-12", "auto-1"),
	"erin-explorer":  automationRun("erin@example.com", "bc-15", "auto-1"),
	"bob-reader":     automationRun("bob@example.com", "bc-13", "auto-3"),
	"svc":            {Kind: runnerid.KindAgent, Subject: "service_account:9", Owner: "service_account:9", Run: "bc-14", Source: "AUTOMATIONS", Automation: "auto-1"},
	"unlisted":       automationRun("alice@example.com", "bc-4", "auto-9"),
	"web":            {Kind: runnerid.KindPerson, Subject: "alice@example.com", Owner: "user:1", Run: "bc-5", Source: "WEBSITE"},
	"slack":          {Kind: runnerid.KindPerson, Subject: "alice@example.com", Owner: "user:1", Run: "bc-6", Source: "SLACK"},
	"no-id":          {Kind: runnerid.KindPerson, Subject: "alice@example.com", Owner: "user:1", Run: "bc-7", Source: "AUTOMATIONS"},
	"no-src":         {Kind: runnerid.KindPerson, Subject: "alice@example.com", Owner: "user:1", Run: "bc-8", Automation: "auto-1"},
}

// directoryOf answers group lookups from a fixed table; a person not in it,
// or listed with "disabled", is a disabled account.
type directoryOf map[string][]string

func (d directoryOf) Lookup(_ context.Context, subject string, groups []string) (entitlement.Person, error) {
	member, ok := d[subject]
	if !ok {
		return entitlement.Person{ObjectID: "oid-" + subject}, nil
	}
	enabled := true
	for _, m := range member {
		enabled = enabled && m != "disabled"
	}
	var in []string
	for _, g := range groups {
		for _, m := range member {
			if g == m {
				in = append(in, g)
			}
		}
	}
	return entitlement.Person{ObjectID: "oid-" + subject, Enabled: enabled, MemberOf: in}, nil
}

func TestAutomationRunNamesItsAutomation(t *testing.T) {
	pool, _ := automationCatalog(t).Pool("automations")
	who, refusal := Resolve(context.Background(), pool, "explorer", Claims{Pod: "pod-a", ClaimedRun: "bc-1"}, automationRuns, &authorizetest.MemBinder{})
	if refusal != "" || who.Kind != "automation" || who.Subject != "auto-1" || who.AutomationName != "explorer" ||
		who.AutomationOwner != "alice@example.com" || who.RunPerson != "alice@example.com" || who.Audited() != "alice@example.com" ||
		who.Source != "AUTOMATIONS" || who.Automation != "auto-1" || who.TokenSHA256 != "sha-explorer" {
		t.Fatalf("%q %+v", refusal, who)
	}
	// The audit names the person whose run it is, not the catalog owner.
	who, _ = Resolve(context.Background(), pool, "bob-explorer", Claims{Pod: "pod-b", ClaimedRun: "bc-10"}, automationRuns, &authorizetest.MemBinder{})
	if who.Audited() != "bob@example.com" || who.AutomationOwner != "alice@example.com" {
		t.Fatalf("bob's run: %+v", who)
	}
}

// Every request on an automation pool comes from a listed Automation run by
// a person, T0 included; the refusal still records what the token said.
func TestAutomationPoolRefusesOtherRuns(t *testing.T) {
	pool, _ := automationCatalog(t).Pool("automations")
	for token, want := range map[string]string{
		"unlisted": "automation_unlisted",
		"web":      "not_automation",
		"slack":    "not_automation",
		"no-id":    "not_automation",
		"no-src":   "not_automation",
		"svc":      "automation_no_person",
		"forged":   "session_token",
		"":         "session_missing",
	} {
		run := automationRuns[token]
		who, refusal := Resolve(context.Background(), pool, token, Claims{Pod: "pod-" + token, ClaimedRun: run.Run}, automationRuns, &authorizetest.MemBinder{})
		if refusal != want || who.Kind != "none" || who.AutomationName != "" || who.Audited() != "" {
			t.Errorf("%q: %q %+v, want %s", token, refusal, who, want)
		}
		if token != "forged" && token != "" && (who.Source != run.Source || who.Automation != run.Automation) {
			t.Errorf("%q: audit fields %+v", token, who)
		}
	}
}

func TestAutomationDecisions(t *testing.T) {
	catalog := automationCatalog(t)
	pool, _ := catalog.Pool("automations")
	cache := &entitlement.Cache{Source: directoryOf{
		"alice@example.com": {automationGroup, teamGroup},
		"bob@example.com":   {teamGroup},
		"carol@example.com": {},
		"erin@example.com":  {teamGroup, "disabled"},
	}}
	ctx := context.Background()
	decide := func(token, entry string) entitlement.Decision {
		t.Helper()
		run := automationRuns[token]
		who, refusal := Resolve(ctx, pool, token, Claims{Pod: "pod-" + token, ClaimedRun: run.Run}, automationRuns, &authorizetest.MemBinder{})
		if refusal != "" {
			t.Fatalf("%s: %q", token, refusal)
		}
		e, err := catalog.Match("api."+entry+".example", 443, "GET", "/v1/x", "automations")
		if err != nil {
			t.Fatal(err)
		}
		return Decide(ctx, cache, pool, *e, who)
	}
	for _, c := range []struct {
		token, entry, outcome string
		allowed               bool
	}{
		{"explorer", "tracker", "t0", true},
		{"explorer", "ledger", "entitled", true},
		// A team member runs it on the owner's account.
		{"bob-explorer", "tracker", "t0", true},
		{"bob-explorer", "ledger", "entitled", true},
		// Not the owner and not in the runner group, or disabled: refused, T0 too.
		{"carol-explorer", "tracker", "automation_runner", false},
		{"dave-explorer", "tracker", "automation_runner", false},
		// In the runner group, but the account is disabled.
		{"erin-explorer", "tracker", "automation_runner", false},
		{"explorer", "vault", "entitled", true},
		{"bob-explorer", "vault", "entitled", true},
		// No runner group: only the owner's runs.
		{"bob-reader", "tracker", "automation_runner", false},
		// Not listed for this Automation, though granted to the pool.
		{"reader", "ledger", "automation_not_granted", false},
		// An owner whose account is gone stops the Automation at every tier.
		{"auditor", "tracker", "account_disabled", false},
		{"auditor", "ledger", "account_disabled", false},
	} {
		d := decide(c.token, c.entry)
		if d.Allowed != c.allowed || d.Outcome != c.outcome {
			t.Errorf("%s on %s: %+v, want %s", c.token, c.entry, d, c.outcome)
		}
		// The decision is the owner's (bob is not in the ledger's group),
		// but the row's object ID is the run person's, as its requester is.
		if person := automationRuns[c.token].Subject; c.allowed && d.ObjectID != "oid-"+person {
			t.Errorf("%s on %s records object ID %q, not the run person's", c.token, c.entry, d.ObjectID)
		}
	}
	// A runner refusal records the runner and the group checked.
	if d := decide("carol-explorer", "ledger"); d.ObjectID != "oid-carol@example.com" || len(d.Groups) != 1 || d.Groups[0] != teamGroup {
		t.Errorf("carol's refusal: %+v", d)
	}
	// A requester that is not an Automation is never served on the pool.
	e, _ := catalog.Match("api.tracker.example", 443, "GET", "/v1/x", "automations")
	for _, who := range []Requester{{Kind: "none"}, {Kind: "person", Subject: "alice@example.com"}, {Kind: "automation", Subject: "auto-9"}} {
		if d := Decide(ctx, cache, pool, *e, who); d.Allowed || d.Outcome != "automation_not_granted" {
			t.Errorf("%+v: %+v", who, d)
		}
	}
	// A listed Automation with no run person is refused, not served as the owner.
	if d := Decide(ctx, cache, pool, *e, Requester{Kind: "automation", Subject: "auto-1"}); d.Allowed || d.Outcome != "automation_runner" {
		t.Errorf("no run person: %+v", d)
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
	if refusal != "" || who.Kind != "person" || who.Source != "" || who.Automation != "" || who.Audited() != "alice@example.com" {
		t.Fatalf("person run: %q %+v", refusal, who)
	}
}

// countingDirectory counts the directory calls a cache makes.
type countingDirectory struct {
	directoryOf
	calls int
}

func (d *countingDirectory) Lookup(ctx context.Context, subject string, groups []string) (entitlement.Person, error) {
	d.calls++
	return d.directoryOf.Lookup(ctx, subject, groups)
}

// Leaving the runner group takes effect for T2 at once, as a person's group
// change does on a person pool; T0 and T1 may ride the cached answer. The
// fresh refusal forgets every cached answer about the person, not only the
// runner group's.
func TestRunnerGroupIsLookedUpFreshAtT2(t *testing.T) {
	catalog := automationCatalog(t)
	pool, _ := catalog.Pool("automations")
	directory := directoryOf{"alice@example.com": {automationGroup, teamGroup}, "bob@example.com": {teamGroup}}
	source := &countingDirectory{directoryOf: directory}
	cache := &entitlement.Cache{Source: source}
	ctx := context.Background()
	who, refusal := Resolve(ctx, pool, "bob-explorer", Claims{Pod: "pod-bob", ClaimedRun: "bc-10"}, automationRuns, &authorizetest.MemBinder{})
	if refusal != "" {
		t.Fatal(refusal)
	}
	entry := func(name string) httpcatalog.Entry {
		e, err := catalog.Match("api."+name+".example", 443, "GET", "/v1/x", "automations")
		if err != nil {
			t.Fatal(err)
		}
		return *e
	}
	if d := Decide(ctx, cache, pool, entry("tracker"), who); !d.Allowed {
		t.Fatalf("bob as a member: %+v", d)
	}
	// Another cached answer about bob, for another group.
	if _, _, err := cache.Lookup(ctx, "bob@example.com", []string{automationGroup}); err != nil {
		t.Fatal(err)
	}
	directory["bob@example.com"] = nil // removed from the group
	if d := Decide(ctx, cache, pool, entry("ledger"), who); !d.Allowed {
		t.Fatalf("T1 should ride the cached answer: %+v", d)
	}
	if d := Decide(ctx, cache, pool, entry("vault"), who); d.Allowed || d.Outcome != "automation_runner" {
		t.Fatalf("T2 after leaving the group: %+v", d)
	}
	// The fresh refusal forgot bob, so T0 is refused now too.
	if d := Decide(ctx, cache, pool, entry("tracker"), who); d.Allowed || d.Outcome != "automation_runner" {
		t.Fatalf("T0 after the fresh refusal: %+v", d)
	}
	// And his answer for the other group is gone: asking again reaches the
	// directory instead of the cache.
	before := source.calls
	if _, _, err := cache.Lookup(ctx, "bob@example.com", []string{automationGroup}); err != nil {
		t.Fatal(err)
	}
	if source.calls != before+1 {
		t.Fatal("bob's other cached answer survived the fresh refusal")
	}
}

// The owner's check for an Automation is charged to that Automation's own
// lookup budget: its busy T2 runs neither use up the owner's own budget nor
// another Automation's.
func TestAutomationOwnerChecksUseTheAutomationsBudget(t *testing.T) {
	catalog := automationCatalog(t)
	pool, _ := catalog.Pool("automations")
	now := time.Unix(1_700_000_000, 0)
	cache := &entitlement.Cache{
		Source:           directoryOf{"alice@example.com": {automationGroup, teamGroup}, "bob@example.com": {teamGroup}},
		LookupsPerMinute: 2,
		Now:              func() time.Time { return now },
	}
	ctx := context.Background()
	vault, err := catalog.Match("api.vault.example", 443, "GET", "/v1/x", "automations")
	if err != nil {
		t.Fatal(err)
	}
	decide := func(token string) entitlement.Decision {
		t.Helper()
		run := automationRuns[token]
		who, refusal := Resolve(ctx, pool, token, Claims{Pod: "pod-" + token, ClaimedRun: run.Run}, automationRuns, &authorizetest.MemBinder{})
		if refusal != "" {
			t.Fatalf("%s: %q", token, refusal)
		}
		now = now.Add(10 * time.Second) // past the recent answer an over-budget lookup may reuse
		return Decide(ctx, cache, pool, *vault, who)
	}
	// alice's and bob's runs of auto-1 share auto-1's budget for the owner check.
	for i, token := range []string{"explorer", "bob-explorer"} {
		if d := decide(token); !d.Allowed {
			t.Fatalf("request %d: %+v", i, d)
		}
	}
	if d := decide("explorer"); d.Allowed || d.Outcome != "entitlement_rate_limited" {
		t.Fatalf("third T2 request within the minute: %+v", d)
	}
	// alice's own budget is untouched, so her own T2 sessions are still served.
	if _, _, err := cache.Fresh(ctx, "alice@example.com", []string{automationGroup}); err != nil {
		t.Fatalf("alice's own lookup after her Automation's: %v", err)
	}
}

// A refusal at the runner check describes the runner group's lookup: the age
// of a cached answer, and the runner group on a lookup that was rate limited.
func TestRunnerCheckRefusalsDescribeTheRunnerLookup(t *testing.T) {
	catalog := automationCatalog(t)
	pool, _ := catalog.Pool("automations")
	now := time.Unix(1_700_000_000, 0)
	cache := &entitlement.Cache{
		Source:           directoryOf{"alice@example.com": {automationGroup, teamGroup}, "bob@example.com": {teamGroup}, "carol@example.com": {}},
		LookupsPerMinute: 1,
		Now:              func() time.Time { return now },
	}
	ctx := context.Background()
	decide := func(token, name string) entitlement.Decision {
		t.Helper()
		run := automationRuns[token]
		who, refusal := Resolve(ctx, pool, token, Claims{Pod: "pod-" + token, ClaimedRun: run.Run}, automationRuns, &authorizetest.MemBinder{})
		if refusal != "" {
			t.Fatalf("%s: %q", token, refusal)
		}
		e, err := catalog.Match("api."+name+".example", 443, "GET", "/v1/x", "automations")
		if err != nil {
			t.Fatal(err)
		}
		return Decide(ctx, cache, pool, *e, who)
	}
	// carol is not in the runner group. Her T0 refusal is cached, so the
	// next one two minutes later rides that answer and says how old it is.
	if d := decide("carol-explorer", "tracker"); d.Outcome != "automation_runner" || d.CacheAge != 0 {
		t.Fatalf("first refusal: %+v", d)
	}
	now = now.Add(2 * time.Minute)
	if d := decide("carol-explorer", "tracker"); d.Outcome != "automation_runner" || d.CacheAge != 2*time.Minute ||
		len(d.Groups) != 1 || d.Groups[0] != teamGroup || d.ObjectID != "oid-carol@example.com" {
		t.Fatalf("cached refusal: %+v", d)
	}
	// bob's second T2 run within the minute is over his own lookup budget.
	if d := decide("bob-explorer", "vault"); !d.Allowed {
		t.Fatalf("bob's first T2 run: %+v", d)
	}
	now = now.Add(10 * time.Second) // past the recent answer an over-budget lookup may reuse
	if d := decide("bob-explorer", "vault"); d.Outcome != "entitlement_rate_limited" || len(d.Groups) != 1 || d.Groups[0] != teamGroup {
		t.Fatalf("over the runner's budget: %+v", d)
	}
}
