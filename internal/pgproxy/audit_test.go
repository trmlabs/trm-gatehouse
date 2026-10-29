package pgproxy

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/auditchain"
	"github.com/Infisical/agent-vault/internal/brokercore"
)

type recordingAudit struct {
	mu        sync.Mutex
	events    []auditchain.Event
	admitErr  error
	failEvent string
}

func (a *recordingAudit) Admit() error { a.mu.Lock(); defer a.mu.Unlock(); return a.admitErr }

func (a *recordingAudit) Record(e auditchain.Event) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if e.Event == a.failEvent {
		return errors.New("audit write failed")
	}
	if err := e.Validate(); err != nil {
		return err
	}
	a.events = append(a.events, e)
	return nil
}

func (a *recordingAudit) recorded() []auditchain.Event {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]auditchain.Event(nil), a.events...)
}

func auditedBroker(t *testing.T, audit *recordingAudit, minter *fakeMinter, upstreamAddr string, authErr error) string {
	t.Helper()
	_, addr := startBroker(t, Options{
		Auth:      &fakeAuth{scope: &AgentScope{VaultID: "vault-1", ActorID: "agent-uuid-1", Pool: "pool-agent", WorkloadID: "pod-uid-1"}, err: authErr},
		Databases: &fakeResolver{svc: &DatabaseService{Name: "analytics", Addr: upstreamAddr, Mount: "database", Role: "readonly"}},
		Leases:    minter,
		Audit:     audit,
	})
	return addr
}

// A served session leaves exactly one open and one close row, attributed to
// the verified pool, Pod and binding, and never to a credential.
func TestBrokerAuditsSessionLifecycle(t *testing.T) {
	lease := newLease()
	upstream := startFakeUpstream(t, authTrust, lease.Password)
	audit := &recordingAudit{}
	addr := auditedBroker(t, audit, &fakeMinter{lease: lease}, upstream.addr(), nil)
	if _, err := runAgentQuery(t, addr, "agent-vault-token-xyz", "appdb", "SELECT 1"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 2*time.Second, func() bool { return len(audit.recorded()) == 2 }, "session close row")
	got := audit.recorded()
	if got[0].Event != auditchain.EventSessionOpen || got[1].Event != auditchain.EventSessionClose || got[0].Session == "" || got[0].Session != got[1].Session {
		t.Fatalf("lifecycle rows: %+v", got)
	}
	for _, e := range got {
		if e.Pool != "pool-agent" || e.Agent != "agent-uuid-1" || e.PodUID != "pod-uid-1" || e.Binding != "vault-1/analytics" {
			t.Fatalf("attribution: %+v", e)
		}
		for _, secret := range []string{lease.Password, lease.Username, lease.ID, "agent-vault-token-xyz"} {
			if strings.Contains(e.Session+e.Outcome+e.Requester, secret) {
				t.Fatal("credential material in audit row")
			}
		}
	}
}

// An unwritable or overdue trail refuses before any credential is minted.
func TestBrokerRefusesSessionWhenAuditUnavailable(t *testing.T) {
	minter := &fakeMinter{lease: newLease()}
	audit := &recordingAudit{admitErr: auditchain.ErrCheckpointOverdue}
	addr := auditedBroker(t, audit, minter, "unused:5432", nil)
	if _, err := runAgentQuery(t, addr, "token", "appdb", "SELECT 1"); err == nil || !strings.Contains(err.Error(), "audit unavailable") {
		t.Fatalf("session admitted without audit: %v", err)
	}
	if minter.mintCallCount() != 0 {
		t.Fatal("credential minted while audit unavailable")
	}
	if got := audit.recorded(); len(got) != 1 || got[0].Event != auditchain.EventDenied || got[0].Outcome != "audit_unavailable" || got[0].Agent != "agent-uuid-1" {
		t.Fatalf("refusal rows: %+v", got)
	}
}

// If the session row cannot be written, no query runs and the lease is revoked.
func TestBrokerRevokesWhenSessionRowFails(t *testing.T) {
	lease := newLease()
	upstream := startFakeUpstream(t, authTrust, lease.Password)
	minter := &fakeMinter{lease: lease}
	audit := &recordingAudit{failEvent: auditchain.EventSessionOpen}
	addr := auditedBroker(t, audit, minter, upstream.addr(), nil)
	if _, err := runAgentQuery(t, addr, "token", "appdb", "SELECT 1"); err == nil {
		t.Fatal("query ran without a session row")
	}
	waitFor(t, 2*time.Second, func() bool { return len(minter.revokedLeases()) == 1 }, "lease revoked")
	for _, e := range audit.recorded() {
		if e.Event == auditchain.EventSessionClose {
			t.Fatal("close row for a session that never opened")
		}
	}
}

func TestBrokerAuditsDenials(t *testing.T) {
	audit := &recordingAudit{}
	addr := auditedBroker(t, audit, &fakeMinter{mintErr: errors.New("vault down")}, "unused:5432", nil)
	_, _ = runAgentQuery(t, addr, "token", "appdb", "SELECT 1")
	unauth := &recordingAudit{}
	addr = auditedBroker(t, unauth, &fakeMinter{}, "unused:5432", errors.New("bad token"))
	_, _ = runAgentQuery(t, addr, "token", "appdb", "SELECT 1")
	if got := audit.recorded(); len(got) != 1 || got[0].Outcome != "credential" || got[0].Binding != "vault-1/analytics" {
		t.Fatalf("mint denial: %+v", got)
	}
	if got := unauth.recorded(); len(got) != 1 || got[0].Outcome != "authentication" || got[0].Pool != "" || got[0].PodUID != "" {
		t.Fatalf("authentication denial: %+v", got)
	} // A signing-key refusal's row names the check, the token's kid and the peer.
	keyed := &recordingAudit{}
	refusal := brokercore.WithPeer(brokercore.DeniedKey("token_keys_pinned_mismatch", `k"1`), netip.MustParseAddr("10.20.30.40"))
	addr = auditedBroker(t, keyed, &fakeMinter{}, "unused:5432", refusal)
	_, _ = runAgentQuery(t, addr, "token", "appdb", "SELECT 1")
	if got := keyed.recorded(); len(got) != 1 || got[0].Decision != "identity_token_keys_pinned_mismatch" || got[0].Kid != "invalid" ||
		len(got[0].KidSHA256) != 12 || got[0].Peer != "10.20.30.40" {
		t.Fatalf("key refusal row: %+v", got)
	}
}

// failingAudit is a trail whose failure the test triggers.
type failingAudit struct {
	recordingAudit
	failed chan struct{}
}

func (a *failingAudit) Failed() <-chan struct{} { return a.failed }

// When the trail fails, sessions already open end: nothing they do could be
// recorded, and Admit only gates new ones.
func TestBrokerEndsOpenSessionsWhenTheAuditTrailFails(t *testing.T) {
	lease := newLease()
	upstream := startFakeUpstream(t, authTrust, lease.Password)
	audit := &failingAudit{failed: make(chan struct{})}
	_, addr := startBroker(t, Options{
		Auth:      &fakeAuth{scope: &AgentScope{VaultID: "vault-1", ActorID: "pool-agent", WorkloadID: "pod-uid-1"}},
		Databases: &fakeResolver{svc: &DatabaseService{Name: "analytics", Addr: upstream.addr(), Mount: "database", Role: "readonly"}},
		Leases:    &fakeMinter{lease: lease},
		Audit:     audit,
	})
	session := openAgentSession(t, addr, "agent-vault-token-xyz", "appdb")
	conn := session.conn
	t.Cleanup(func() { _ = conn.Close() })
	close(audit.failed)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 256)
	for {
		if _, err := conn.Read(buf); err != nil {
			var timeout net.Error
			if errors.As(err, &timeout) && timeout.Timeout() {
				t.Fatal("open session survived the audit trail failing")
			}
			return
		}
	}
}

// Pre-authentication denied rows are capped: a burst, then a steady rate,
// with what was dropped counted in the operational log.
func TestPreAuthDeniedRowsAreRateLimited(t *testing.T) {
	var logs strings.Builder
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	var l deniedLimiter
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	allowed := 0
	for range 100 {
		if l.allow(now, logger) {
			allowed++
		}
	}
	if allowed != deniedBurst {
		t.Fatalf("burst allowed %d rows, want %d", allowed, deniedBurst)
	}
	if !strings.Contains(logs.String(), "suppressed") {
		t.Fatalf("dropped rows not reported: %q", logs.String())
	}
	now = now.Add(time.Second)
	allowed = 0
	for range 100 {
		if l.allow(now, logger) {
			allowed++
		}
	}
	if allowed != deniedPerSecond {
		t.Fatalf("one second later allowed %d rows, want %d", allowed, deniedPerSecond)
	}
}

// slowMinter takes delay to mint, as Vault role DDL can.
type slowMinter struct {
	*fakeMinter
	delay time.Duration
}

func (m slowMinter) Mint(ctx context.Context, scope AgentScope, svc *DatabaseService) (*Lease, error) {
	time.Sleep(m.delay)
	return m.fakeMinter.Mint(ctx, scope, svc)
}

// departmentResolver admits and reports a person, with the object ID and a
// directory department that has stray white space.
type departmentResolver struct{ svc *DatabaseService }

func (r departmentResolver) ResolveDatabase(ctx context.Context, _ AgentScope, _ string) (*DatabaseService, error) {
	RecordRequester(ctx, Requester{Kind: "person", Subject: "user_1", ObjectID: "oid-1", Tier: "T1", Decision: "entitled", Department: "  Data   Science "})
	return r.svc, nil
}

// session_open records how long admission took, the credential mint
// included, and the person's object ID and department as the directory gave
// them.
func TestBrokerSessionOpenRecordsAdmissionTimeAndDepartment(t *testing.T) {
	lease := newLease()
	upstream := startFakeUpstream(t, authTrust, lease.Password)
	audit := &recordingAudit{}
	_, addr := startBroker(t, Options{
		Auth:      &fakeAuth{scope: &AgentScope{VaultID: "vault-1", ActorID: "agent-uuid-1", Pool: "pool-agent", WorkloadID: "pod-uid-1"}},
		Databases: departmentResolver{svc: &DatabaseService{Name: "analytics", Addr: upstream.addr(), Mount: "database", Role: "readonly"}},
		Leases:    slowMinter{fakeMinter: &fakeMinter{lease: lease}, delay: 120 * time.Millisecond},
		Audit:     audit,
	})
	if _, err := runAgentQuery(t, addr, "token", "appdb", "SELECT 1"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 2*time.Second, func() bool { return len(audit.recorded()) == 2 }, "session close row")
	got := audit.recorded()
	if got[0].Event != auditchain.EventSessionOpen || got[0].Duration < 120 || got[0].RequesterDepartment != "Data Science" || got[0].RequesterOID != "oid-1" {
		t.Fatalf("session_open row: %+v; want durationMs of at least the mint, the object ID and the canonical department", got[0])
	}
	if got[1].Duration != 0 {
		t.Fatalf("session_close row carries a duration: %+v", got[1])
	}
}

// automationResolver reports a listed Automation's run, as the catalog
// resolver does: the person the run's token names, the owning team, and no
// directory answer. It refuses when refusal is set.
type automationResolver struct {
	svc     *DatabaseService
	refusal string
}

func (r automationResolver) ResolveDatabase(ctx context.Context, _ AgentScope, _ string) (*DatabaseService, error) {
	decision := "automation_granted"
	if r.refusal != "" {
		decision = r.refusal
	}
	RecordRequester(ctx, Requester{Kind: "automation", Subject: "bob@example.com", Tier: "T1", Decision: decision,
		Source: "AUTOMATIONS", Automation: "auto-1", AutomationName: "explorer", AutomationOwner: "platform-team"})
	if r.refusal != "" {
		return nil, &RefusedError{Outcome: r.refusal}
	}
	return r.svc, nil
}

// A database row from an Automation's run names the person whose run it is
// as the requester, with the run's source, the Automation and its owning
// team, admitted or refused.
func TestBrokerRowsNameAnAutomationsRun(t *testing.T) {
	for _, refusal := range []string{"", "automation_not_granted"} {
		lease := newLease()
		svc := &DatabaseService{Name: "analytics", Addr: "unused:5432", Mount: "database", Role: "readonly"}
		want, rows := auditchain.EventDenied, 1
		if refusal == "" {
			svc.Addr = startFakeUpstream(t, authTrust, lease.Password).addr()
			want, rows = auditchain.EventSessionOpen, 2
		}
		audit := &recordingAudit{}
		_, addr := startBroker(t, Options{
			Auth:      &fakeAuth{scope: &AgentScope{VaultID: "vault-1", ActorID: "agent-uuid-1", Pool: "automations", WorkloadID: "pod-uid-1"}},
			Databases: automationResolver{svc: svc, refusal: refusal},
			Leases:    &fakeMinter{lease: lease},
			Audit:     audit,
		})
		_, _ = runAgentQuery(t, addr, "token", "appdb", "SELECT 1")
		waitFor(t, 2*time.Second, func() bool { return len(audit.recorded()) == rows }, "audit rows")
		row := audit.recorded()[0]
		if row.Event != want || row.RequesterKind != "automation" || row.Requester != "bob@example.com" || row.RequesterOID != "" ||
			row.Source != "AUTOMATIONS" || row.Automation != "auto-1" || row.AutomationName != "explorer" || row.AutomationOwner != "platform-team" {
			t.Fatalf("refusal %q: row %+v", refusal, row)
		}
	}
}

// A refusal before the catalog resolves a database names the database the
// client asked for; a name that is not plain is recorded as "invalid".
func TestBrokerRefusalNamesTheRequestedDatabase(t *testing.T) {
	for asked, want := range map[string]string{"reporting": "reporting", "has space": "invalid"} {
		audit := &recordingAudit{}
		_, addr := startBroker(t, Options{
			Auth:      &fakeAuth{scope: &AgentScope{VaultID: "vault-1", ActorID: "agent-uuid-1", Pool: "pool-agent", WorkloadID: "pod-uid-1"}},
			Databases: &fakeResolver{err: errors.New("no such database")},
			Leases:    &fakeMinter{},
			Audit:     audit,
		})
		_, _ = runAgentQuery(t, addr, "token", asked, "SELECT 1")
		got := audit.recorded()
		if len(got) != 1 || got[0].Outcome != "no_database" || got[0].Database != want || got[0].Binding != "" {
			t.Fatalf("%q: refusal rows %+v; want no_database naming %q", asked, got, want)
		}
	}
	// Once a binding names the database, the row carries no separate name.
	audit := &recordingAudit{}
	addr := auditedBroker(t, audit, &fakeMinter{mintErr: errors.New("vault down")}, "unused:5432", nil)
	_, _ = runAgentQuery(t, addr, "token", "appdb", "SELECT 1")
	if got := audit.recorded(); len(got) != 1 || got[0].Outcome != "credential" || got[0].Database != "" {
		t.Fatalf("mint denial: %+v", got)
	}
}
