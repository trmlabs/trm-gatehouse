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

// Every audit row from an automation pool names the Automation, allowed or
// refused, and the row passes the chain's own validation.
func TestAutomationAuditRowsNameTheAutomation(t *testing.T) {
	catalog, err := httpcatalog.Parse([]byte(`{"pools":[{"name":"automations","namespace":"n","serviceAccount":"worker","identity":"cursor-automation"}],
	 "entries":[{"name":"open","host":"api.vendor.example","pathPrefixes":["/open/"],"methods":["GET"],"header":"Authorization","placeholder":"__vault_KEY__","key":{"mount":"gatehouse","path":"vendors/p","field":"f"},"pools":["automations"]}],
	 "automations":[{"id":"auto-1","name":"explorer","owner":"owner@example.com","entries":["open"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	runner := cursorRunner{
		"listed":   {Kind: runnerid.KindPerson, Subject: "owner@example.com", Owner: "user:1", Run: "bc-1", Source: "AUTOMATIONS", Automation: "auto-1"},
		"unlisted": {Kind: runnerid.KindPerson, Subject: "owner@example.com", Owner: "user:1", Run: "bc-2", Source: "AUTOMATIONS", Automation: "auto-9"},
	}
	p := &Proxy{adapter: &HeaderAdapter{Catalog: catalog, Runner: runner, Sessions: &authorizetest.MemBinder{},
		Entitlements: &entitlement.Cache{Source: directory{"owner@example.com": {}}}}}
	open, _ := catalog.Match("api.vendor.example", 443, "GET", "/open/x", "automations")
	for token, want := range map[string]struct{ refusal, name, owner, requester string }{
		"listed":   {"", "explorer", "owner@example.com", "owner@example.com"},
		"unlisted": {"automation_unlisted", "", "", ""},
	} {
		event := auditchain.Event{Event: auditchain.EventHTTPRequest}
		run := runner[token].Run
		got := p.authorize(withSessionToken(context.Background(), token), &brokercore.ProxyScope{Pool: "automations", AgentID: "a", WorkloadID: "pod-" + token, ClaimedRun: run}, open, &event)
		if got != want.refusal || event.Source != "AUTOMATIONS" || event.Automation != runner[token].Automation ||
			event.AutomationName != want.name || event.AutomationOwner != want.owner || event.Requester != want.requester || event.TokenSHA256 != "sha-"+token {
			t.Errorf("%s: %q %+v", token, got, event)
		}
		if err := event.Validate(); err != nil {
			t.Errorf("%s: audit row refused: %v", token, err)
		}
	}
}
