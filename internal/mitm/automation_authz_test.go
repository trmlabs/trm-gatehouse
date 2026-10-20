package mitm

import (
	"context"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/auditchain"
	"github.com/Infisical/agent-vault/internal/authorize/authorizetest"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/entitlement"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/runnerid"
)

// cursorRunner verifies Cursor run tokens from a fixed table.
type cursorRunner map[string]runnerid.Session

func (cursorRunner) Verify(context.Context, string) (runnerid.Session, error) {
	return runnerid.Session{}, runnerid.ErrUnverifiable
}

func (c cursorRunner) VerifyCursor(_ context.Context, token string) (runnerid.Session, error) {
	s, ok := c[token]
	if !ok {
		return runnerid.Session{}, runnerid.ErrInvalid
	}
	s.TokenSHA256, s.Expires = "sha-"+token, time.Now().Add(5*time.Minute)
	return s, nil
}

// Every audit row from an automation pool names the Automation and its
// owning team, allowed or refused, and the row passes the chain's own
// validation. The requester is the person the run names, if any, and decides
// nothing: whoever's run it is, or no person's, the Automation is served its
// own entries, with no directory answer in the row.
func TestAutomationAuditRowsNameTheAutomation(t *testing.T) {
	catalog, err := httpcatalog.Parse([]byte(`{"pools":[{"name":"automations","namespace":"n","serviceAccount":"worker","identity":"cursor-automation"}],
	 "entries":[{"name":"open","host":"api.vendor.example","pathPrefixes":["/open/"],"methods":["GET"],"header":"Authorization","placeholder":"__vault_KEY__","key":{"mount":"gatehouse","path":"vendors/p","field":"f"},"pools":["automations"]},
	  {"name":"other","host":"api.other.example","pathPrefixes":["/"],"methods":["GET"],"header":"Authorization","placeholder":"__vault_KEY__","key":{"mount":"gatehouse","path":"vendors/q","field":"f"},"pools":["automations"]}],
	 "automations":[{"id":"auto-1","name":"explorer","owner":"platform-team","entries":["open"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	runner := cursorRunner{
		"listed":   {Kind: runnerid.KindPerson, Subject: "owner@example.com", Owner: "user:1", Run: "bc-1", Source: "AUTOMATIONS", Automation: "auto-1"},
		"unlisted": {Kind: runnerid.KindPerson, Subject: "owner@example.com", Owner: "user:1", Run: "bc-2", Source: "AUTOMATIONS", Automation: "auto-9"},
		"runner":   {Kind: runnerid.KindPerson, Subject: "bob@example.com", Owner: "user:2", Run: "bc-3", Source: "AUTOMATIONS", Automation: "auto-1"},
		"svc":      {Kind: runnerid.KindAgent, Subject: "service_account:4", Owner: "service_account:4", Run: "bc-4", Source: "AUTOMATIONS", Automation: "auto-1"},
	}
	// The directory knows no one: an Automation never needs it.
	p := &Proxy{adapter: &HeaderAdapter{Catalog: catalog, Runner: runner, Sessions: &authorizetest.MemBinder{},
		Entitlements: &entitlement.Cache{Source: directory{}}}}
	open, _ := catalog.Match("api.vendor.example", 443, "GET", "/open/x", "automations")
	other, _ := catalog.Match("api.other.example", 443, "GET", "/x", "automations")
	// A {requester} push prefix names the Automation, never the run's
	// person, so every run of one Automation shares its branches.
	for _, c := range []struct {
		token                                              string
		entry                                              *httpcatalog.Entry
		refusal, decision, name, owner, requester, segment string
	}{
		{"listed", open, "", "t0", "explorer", "platform-team", "owner@example.com", "automation-auto-1"},
		{"runner", open, "", "t0", "explorer", "platform-team", "bob@example.com", "automation-auto-1"},
		{"svc", open, "", "t0", "explorer", "platform-team", "", "automation-auto-1"},
		{"svc", other, "automation_not_granted", "automation_not_granted", "explorer", "platform-team", "", "automation-auto-1"},
		{"unlisted", open, "automation_unlisted", "", "", "", "", ""},
	} {
		event := auditchain.Event{Event: auditchain.EventHTTPRequest}
		run := runner[c.token].Run
		who, got := p.authorize(withSessionToken(context.Background(), c.token), &brokercore.ProxyScope{Pool: "automations", AgentID: "a", WorkloadID: "pod-" + c.token, ClaimedRun: run}, c.entry, &event)
		if got != c.refusal || event.Decision != c.decision || event.Source != "AUTOMATIONS" || event.Automation != runner[c.token].Automation ||
			event.AutomationName != c.name || event.AutomationOwner != c.owner || event.Requester != c.requester || event.TokenSHA256 != "sha-"+c.token ||
			event.RequesterOID != "" || event.Groups != "" || event.RequesterDepartment != "" || who.BranchSegment() != c.segment {
			t.Errorf("%s on %s: %q %+v, branch segment %q", c.token, c.entry.Name, got, event, who.BranchSegment())
		}
		if err := event.Validate(); err != nil {
			t.Errorf("%s: audit row refused: %v", c.token, err)
		}
	}
}
