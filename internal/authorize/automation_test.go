package authorize

import (
	"context"
	"slices"
	"testing"

	"github.com/Infisical/agent-vault/internal/authorize/authorizetest"
	"github.com/Infisical/agent-vault/internal/entitlement"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/runnerid"
)

const (
	automationGroup = "11111111-2222-3333-4444-555555555555"
	// ownerGroup is auto-2's owning team, named by object id.
	ownerGroup = "66666666-7777-8888-9999-000000000000"
)

// automationCatalog has one pool deciding per Automation, a T0, a T1 and a
// T2 entry granted to it, and three Automations: auto-1 (every entry, owned
// by a team named by its name), auto-2 (T0 and T1, a team named by its object
// id) and auto-3 (T0 and T2, an owner still given as a contact email, as
// catalogs did before owners named teams).
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
			{"id":"auto-1","name":"explorer","owner":"platform-team","entries":["tracker","ledger","vault"]},
			{"id":"auto-2","name":"auditor","owner":"` + ownerGroup + `","entries":["tracker","ledger"]},
			{"id":"auto-3","name":"reader","owner":"alice@example.com","entries":["tracker","vault"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func automationRun(person, run, automation string) runnerid.Session {
	return runnerid.Session{Kind: runnerid.KindPerson, Subject: person, Owner: "user:" + person, Run: run, Source: "AUTOMATIONS", Automation: automation}
}

var automationRuns = cursorRuns{
	"explorer":     automationRun("alice@example.com", "bc-1", "auto-1"),
	"auditor":      automationRun("gone@example.com", "bc-2", "auto-2"),
	"reader":       automationRun("alice@example.com", "bc-3", "auto-3"),
	"bob-explorer": automationRun("bob@example.com", "bc-10", "auto-1"),
	// A service account's run, and a person's outside the configured
	// domains: the token names no person.
	"svc":      {Kind: runnerid.KindAgent, Subject: "service_account:9", Owner: "service_account:9", Run: "bc-14", Source: "AUTOMATIONS", Automation: "auto-1"},
	"outsider": {Kind: runnerid.KindNone, Owner: "user:15", Run: "bc-15", Source: "AUTOMATIONS", Automation: "auto-2"},
	"unlisted": automationRun("alice@example.com", "bc-4", "auto-9"),
	"web":      {Kind: runnerid.KindPerson, Subject: "alice@example.com", Owner: "user:1", Run: "bc-5", Source: "WEBSITE"},
	"slack":    {Kind: runnerid.KindPerson, Subject: "alice@example.com", Owner: "user:1", Run: "bc-6", Source: "SLACK"},
	"no-id":    {Kind: runnerid.KindPerson, Subject: "alice@example.com", Owner: "user:1", Run: "bc-7", Source: "AUTOMATIONS"},
	"no-src":   {Kind: runnerid.KindPerson, Subject: "alice@example.com", Owner: "user:1", Run: "bc-8", Automation: "auto-1"},
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

// countingDirectory counts the directory calls a cache makes.
type countingDirectory struct {
	directoryOf
	calls int
}

func (d *countingDirectory) Lookup(ctx context.Context, subject string, groups []string) (entitlement.Person, error) {
	d.calls++
	return d.directoryOf.Lookup(ctx, subject, groups)
}

func TestAutomationRunNamesItsAutomation(t *testing.T) {
	pool, _ := automationCatalog(t).Pool("automations")
	who, refusal := Resolve(context.Background(), pool, "explorer", Claims{Pod: "pod-a", ClaimedRun: "bc-1"}, automationRuns, &authorizetest.MemBinder{})
	if refusal != "" || who.Kind != "automation" || who.Subject != "auto-1" || who.AutomationName != "explorer" ||
		who.AutomationOwner != "platform-team" || who.RunPerson != "alice@example.com" || who.Audited() != "alice@example.com" ||
		who.Source != "AUTOMATIONS" || who.Automation != "auto-1" || who.TokenSHA256 != "sha-explorer" {
		t.Fatalf("%q %+v", refusal, who)
	}
	// The audit names the person whose run it is, whoever that is.
	who, _ = Resolve(context.Background(), pool, "bob-explorer", Claims{Pod: "pod-b", ClaimedRun: "bc-10"}, automationRuns, &authorizetest.MemBinder{})
	if who.Audited() != "bob@example.com" || who.AutomationOwner != "platform-team" {
		t.Fatalf("bob's run: %+v", who)
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
		if refusal != want || who.Kind != "none" || who.AutomationName != "" || who.Audited() != "" {
			t.Errorf("%q: %q %+v, want %s", token, refusal, who, want)
		}
		if token != "forged" && token != "" && (who.Source != run.Source || who.Automation != run.Automation) {
			t.Errorf("%q: audit fields %+v", token, who)
		}
	}
}

// An Automation's run whose token names no person, a service account's or a
// person's outside the configured domains, is the Automation's: it is served
// its own entries, at every tier, and the audit row names no requester.
func TestAutomationRunWithNoPersonIsServedItsOwnEntries(t *testing.T) {
	catalog := automationCatalog(t)
	pool, _ := catalog.Pool("automations")
	ctx := context.Background()
	for token, c := range map[string]struct {
		automation string
		served     []string
		refused    []string
	}{
		"svc":      {"auto-1", []string{"tracker", "ledger", "vault"}, nil},
		"outsider": {"auto-2", []string{"tracker", "ledger"}, []string{"vault"}},
	} {
		run := automationRuns[token]
		who, refusal := Resolve(ctx, pool, token, Claims{Pod: "pod-" + token, ClaimedRun: run.Run}, automationRuns, &authorizetest.MemBinder{})
		if refusal != "" || who.Kind != "automation" || who.Subject != c.automation || who.RunPerson != "" || who.Audited() != "" {
			t.Fatalf("%s: %q %+v", token, refusal, who)
		}
		for _, name := range append(append([]string(nil), c.served...), c.refused...) {
			e, err := catalog.Match("api."+name+".example", 443, "GET", "/v1/x", "automations")
			if err != nil {
				t.Fatal(err)
			}
			// No directory at all: the Automation's grants decide.
			d := Decide(ctx, nil, pool, *e, who)
			if granted := slices.Contains(c.served, name); d.Allowed != granted {
				t.Errorf("%s on %s: %+v", token, name, d)
			}
		}
	}
}

// An Automation is decided on the entries the catalog lists for it, and on
// nothing about a person: whoever's run it is, in any group or none, is
// served the Automation's entries and nothing else, and the directory is
// never asked. The pool's ceiling still caps the tier.
func TestAutomationDecisions(t *testing.T) {
	catalog := automationCatalog(t)
	pool, _ := catalog.Pool("automations")
	// Nobody is in any group, and gone@example.com has no account.
	source := &countingDirectory{directoryOf: directoryOf{
		"alice@example.com": {},
		"bob@example.com":   {},
	}}
	cache := &entitlement.Cache{Source: source}
	ctx := context.Background()
	decide := func(pool httpcatalog.Pool, token, entry string) entitlement.Decision {
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
		token, entry, tier, outcome string
		allowed                     bool
	}{
		{"explorer", "tracker", "T0", "t0", true},
		{"explorer", "ledger", "T1", "automation_granted", true},
		{"explorer", "vault", "T2", "automation_granted", true},
		// Not a member of the owning team, and in no group: the same.
		{"bob-explorer", "tracker", "T0", "t0", true},
		{"bob-explorer", "vault", "T2", "automation_granted", true},
		// A run person with no account changes nothing either.
		{"auditor", "ledger", "T1", "automation_granted", true},
		// An owner given as a contact email gates nothing: its own run is
		// served though that person is in no group.
		{"reader", "vault", "T2", "automation_granted", true},
		// Not listed for this Automation, though granted to the pool.
		{"auditor", "vault", "T2", "automation_not_granted", false},
		{"reader", "ledger", "T1", "automation_not_granted", false},
	} {
		d := decide(pool, c.token, c.entry)
		if d.Allowed != c.allowed || d.Outcome != c.outcome || d.Tier != c.tier || d.ObjectID != "" || len(d.Groups) != 0 || d.CacheAge != 0 {
			t.Errorf("%s on %s: %+v, want %s", c.token, c.entry, d, c.outcome)
		}
	}
	if source.calls != 0 {
		t.Errorf("the directory was asked %d times", source.calls)
	}
	// The pool's ceiling, checked again on every request, caps a listed entry.
	lowered := pool
	lowered.Ceiling = "T1"
	if d := decide(lowered, "explorer", "vault"); d.Allowed || d.Outcome != "pool_ceiling" {
		t.Errorf("above the ceiling: %+v", d)
	}
	// A requester that is not a listed Automation is never served on the pool.
	e, _ := catalog.Match("api.tracker.example", 443, "GET", "/v1/x", "automations")
	for _, who := range []Requester{{Kind: "none"}, {Kind: "person", Subject: "alice@example.com"}, {Kind: "automation", Subject: "auto-9"}, {Kind: "automation"},
		{Kind: "person", Subject: "auto-1"}, {Kind: "none", Subject: "auto-1"}} {
		if d := Decide(ctx, cache, pool, *e, who); d.Allowed || d.Outcome != "automation_not_granted" {
			t.Errorf("%+v: %+v", who, d)
		}
	}
}

// An Automation's run on a person pool is refused unless the pool opts in,
// so by default the catalog's Automation list is the only way an Automation
// gets access. Either sign of an Automation counts, and the refusal still
// records what the token said. A person's own run is unaffected.
func TestPersonPoolRefusesAutomationRunsUnlessItOptsIn(t *testing.T) {
	ctx := context.Background()
	for _, token := range []string{"explorer", "no-id", "no-src", "svc"} {
		run := automationRuns[token]
		who, refusal := Resolve(ctx, cursorPool, token, Claims{Pod: "pod-" + token, ClaimedRun: run.Run}, automationRuns, &authorizetest.MemBinder{})
		if refusal != "automation_on_person_pool" || who.Kind != "none" || who.Audited() != "" || who.Source != run.Source || who.Automation != run.Automation {
			t.Errorf("%s: %q %+v", token, refusal, who)
		}
	}
	// Opted in, the run is its person's, with the audit fields.
	optedIn := httpcatalog.Pool{Identity: "cursor-session", AutomationRunsAsPerson: true}
	who, refusal := Resolve(ctx, optedIn, "explorer", Claims{Pod: "pod-a", ClaimedRun: "bc-1"}, automationRuns, &authorizetest.MemBinder{})
	if refusal != "" || who.Kind != "person" || who.Subject != "alice@example.com" || who.AutomationName != "" || who.Source != "AUTOMATIONS" || who.Automation != "auto-1" {
		t.Fatalf("opted in: %q %+v", refusal, who)
	}
	// Opting in serves a person, never a run that names none.
	if _, refusal := Resolve(ctx, optedIn, "svc", Claims{Pod: "pod-svc", ClaimedRun: "bc-14"}, automationRuns, &authorizetest.MemBinder{}); refusal != "no_person" {
		t.Fatalf("service account opted in: %q", refusal)
	}
	// A person's run, from any surface, is served on either pool.
	for _, pool := range []httpcatalog.Pool{cursorPool, optedIn} {
		who, refusal = Resolve(ctx, pool, "alice-1", Claims{Pod: "pod-b", ClaimedRun: "bc-1"}, runs, &authorizetest.MemBinder{})
		if refusal != "" || who.Kind != "person" || who.Source != "" || who.Automation != "" || who.Audited() != "alice@example.com" {
			t.Fatalf("person run: %q %+v", refusal, who)
		}
		who, refusal = Resolve(ctx, pool, "slack", Claims{Pod: "pod-c", ClaimedRun: "bc-6"}, automationRuns, &authorizetest.MemBinder{})
		if refusal != "" || who.Kind != "person" || who.Source != "SLACK" || who.Audited() != "alice@example.com" {
			t.Fatalf("person run from Slack: %q %+v", refusal, who)
		}
	}
}
