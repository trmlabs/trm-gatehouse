package pgproxy

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// acceptanceMinter issues one lease per actor and records revocations and mints.
type acceptanceMinter struct {
	mu      sync.Mutex
	minted  map[string]int
	revoked map[string]bool
}

func newAcceptanceMinter() *acceptanceMinter {
	return &acceptanceMinter{minted: map[string]int{}, revoked: map[string]bool{}}
}

func (m *acceptanceMinter) Mint(_ context.Context, scope AgentScope, _ *DatabaseService) (*Lease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.minted[scope.ActorID]++
	id := fmt.Sprintf("lease-%s-%d", scope.ActorID, m.minted[scope.ActorID])
	return &Lease{ID: id, Username: "v-" + id, Password: "pw", ExpiresAt: time.Now().Add(time.Hour), Renewable: true}, nil
}

func (m *acceptanceMinter) Renew(context.Context, string, time.Duration) (time.Time, error) {
	return time.Now().Add(time.Hour), nil
}

func (m *acceptanceMinter) Revoke(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revoked[id] = true
	return nil
}

func (m *acceptanceMinter) mints(actor string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.minted[actor]
}

func (m *acceptanceMinter) revokedFor(actor string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id := range m.revoked {
		if len(id) > len("lease-"+actor+"-") && id[:len("lease-"+actor+"-")] == "lease-"+actor+"-" {
			return true
		}
	}
	return false
}

// gate lets a test withdraw tokens, bindings and the verifier at will.
type gate struct {
	withdrawn   sync.Map // token -> struct{}
	bindingGone sync.Map // database name -> struct{}
	verifierOut atomic.Bool
	deadlines   sync.Map // token -> time.Time
	widened     sync.Map // token -> struct{}: its grant carries the broader role
}

func (g *gate) Authenticate(_ context.Context, token, _ string) (*AgentScope, error) {
	if g.verifierOut.Load() {
		return nil, errors.New("verifier unavailable")
	}
	if _, gone := g.withdrawn.Load(token); gone {
		return nil, errors.New("withdrawn")
	}
	scope := &AgentScope{VaultID: "v", ActorID: token}
	if at, ok := g.deadlines.Load(token); ok {
		scope.NotAfter = at.(time.Time)
	}
	return scope, nil
}

func (g *gate) ResolveDatabase(_ context.Context, scope AgentScope, requested string) (*DatabaseService, error) {
	if _, gone := g.bindingGone.Load(requested); gone {
		return nil, errors.New("binding removed")
	}
	role := "readonly"
	if _, wide := g.widened.Load(scope.ActorID); wide {
		role = "admin"
	}
	if requested == "canary-admin" {
		if role != "admin" {
			return nil, &RefusedError{Outcome: "not_granted"}
		}
	}
	return &DatabaseService{Name: requested, Addr: acceptanceUpstream, Mount: "database", Role: role, SSLMode: "disable"}, nil
}

var acceptanceUpstream string

const acceptanceInterval, acceptanceTimeout = 20 * time.Millisecond, 200 * time.Millisecond

func acceptanceBroker(t *testing.T) (*gate, *acceptanceMinter, string) {
	t.Helper()
	g, minter, addr, _ := acceptanceBrokerAudited(t)
	return g, minter, addr
}

func acceptanceBrokerAudited(t *testing.T) (*gate, *acceptanceMinter, string, *recordingAudit) {
	t.Helper()
	up := startFakeUpstream(t, authTrust, "")
	acceptanceUpstream = up.addr()
	g, minter := &gate{}, newAcceptanceMinter()
	audit := &recordingAudit{}
	_, addr := startBroker(t, Options{Auth: g, Databases: g, Leases: minter, Audit: audit,
		AuthorizationInterval: acceptanceInterval, AuthorizationTimeout: acceptanceTimeout})
	return g, minter, addr, audit
}

// ended reports whether the session's connection has been closed by the broker.
func ended(s *agentSession) bool {
	_, err := s.query("SELECT 1")
	return err != nil
}

func waitEnded(t *testing.T, s *agentSession, who string) time.Duration {
	t.Helper()
	began := time.Now()
	waitFor(t, 5*time.Second, func() bool { return ended(s) }, who+" session kept running")
	return time.Since(began)
}

func requireAlive(t *testing.T, s *agentSession, who string) {
	t.Helper()
	if _, err := s.query("SELECT 1"); err != nil {
		t.Fatalf("%s session ended: %v", who, err)
	}
}

func TestWithdrawnAgentEndsAloneWithinTheRecheckBound(t *testing.T) {
	g, minter, addr := acceptanceBroker(t)
	a := openAgentSession(t, addr, "agent-a", "canary")
	defer a.close()
	b := openAgentSession(t, addr, "agent-b", "canary")
	defer b.close()
	requireAlive(t, a, "A")
	requireAlive(t, b, "B")

	g.withdrawn.Store("agent-a", struct{}{})
	took := waitEnded(t, a, "withdrawn A")
	if bound := acceptanceInterval + acceptanceTimeout + time.Second; took > bound {
		t.Fatalf("A ended after %v, want within %v", took, bound)
	}
	waitFor(t, 5*time.Second, func() bool { return minter.revokedFor("agent-a") }, "A's database credential not revoked")
	time.Sleep(3 * acceptanceInterval)
	requireAlive(t, b, "B")
	if minter.revokedFor("agent-b") {
		t.Fatal("B's credential was revoked with A's")
	}
	before := minter.mints("agent-a")
	if code := connectExpectCode(t, addr, "agent-a", "canary"); code == "OK" || code == "" {
		t.Fatalf("withdrawn A opened a new session: %q", code)
	}
	if minter.mints("agent-a") != before {
		t.Fatal("a database credential was issued to withdrawn A")
	}
	if code := connectExpectCode(t, addr, "agent-b", "canary"); code != "OK" {
		t.Fatalf("B's fresh session = %q, want OK", code)
	}
}

// A grant deleted and restored with the proxy-only role revives no old session and admits no broader role.
func TestRestoredGrantAdmitsFreshWorkOnlyWithTheProxyOnlyRole(t *testing.T) {
	g, minter, addr := acceptanceBroker(t)
	old := openAgentSession(t, addr, "agent-a", "canary")
	defer old.close()
	b := openAgentSession(t, addr, "agent-b", "canary")
	defer b.close()

	g.withdrawn.Store("agent-a", struct{}{})
	waitEnded(t, old, "A while its grant is deleted")
	g.withdrawn.Delete("agent-a")
	time.Sleep(3 * acceptanceInterval)
	if !ended(old) {
		t.Fatal("a session ended by the withdrawal came back with the restored grant")
	}
	fresh := openAgentSession(t, addr, "agent-a", "canary")
	defer fresh.close()
	requireAlive(t, fresh, "A's fresh")
	requireAlive(t, b, "B")

	before := minter.mints("agent-a")
	if code := connectExpectCode(t, addr, "agent-a", "canary-admin"); code != "42501" {
		t.Fatalf("a broader role under the proxy-only grant = %q, want 42501", code)
	}
	if minter.mints("agent-a") != before {
		t.Fatal("a credential was issued for the broader role")
	}
	g.widened.Store("agent-a", struct{}{})
	waitEnded(t, fresh, "A's session once its grant widened")
	requireAlive(t, b, "B")
}

func TestRemovedBindingEndsOnlyItsSessions(t *testing.T) {
	g, minter, addr := acceptanceBroker(t)
	a := openAgentSession(t, addr, "agent-a", "canary-isolation-a")
	defer a.close()
	b := openAgentSession(t, addr, "agent-b", "canary")
	defer b.close()

	g.bindingGone.Store("canary-isolation-a", struct{}{})
	waitEnded(t, a, "session on the removed binding")
	waitFor(t, 5*time.Second, func() bool { return minter.revokedFor("agent-a") }, "removed binding's credential not revoked")
	time.Sleep(3 * acceptanceInterval)
	requireAlive(t, b, "B")
	before := minter.mints("agent-a")
	if code := connectExpectCode(t, addr, "agent-a", "canary-isolation-a"); code == "OK" || code == "" {
		t.Fatalf("a removed binding admitted a session: %q", code)
	}
	if minter.mints("agent-a") != before {
		t.Fatal("a database credential was issued through the removed binding")
	}
	if code := connectExpectCode(t, addr, "agent-a", "canary"); code != "OK" {
		t.Fatalf("A through the unchanged binding = %q, want OK", code)
	}
}

func TestTaskDeadlineEndsOnlyItsOwnersSessionsAndRefusesNewOnes(t *testing.T) {
	g, minter, addr, audit := acceptanceBrokerAudited(t)
	g.deadlines.Store("agent-a", time.Now().Add(400*time.Millisecond))
	g.deadlines.Store("agent-b", time.Now().Add(time.Hour))
	a := openAgentSession(t, addr, "agent-a", "canary")
	defer a.close()
	b := openAgentSession(t, addr, "agent-b", "canary")
	defer b.close()
	requireAlive(t, a, "A before its deadline")

	wantNotice(t, a, "08006", "deadline")
	waitFor(t, 5*time.Second, func() bool { return minter.revokedFor("agent-a") }, "expired task's credential not revoked")
	requireAlive(t, b, "B")
	before := minter.mints("agent-a")
	if code := connectExpectCode(t, addr, "agent-a", "canary"); code != "28000" {
		t.Fatalf("a session past the task deadline = %q, want 28000", code)
	}
	if minter.mints("agent-a") != before {
		t.Fatal("a database credential was issued after the task deadline")
	}
	refused := false
	for _, e := range audit.recorded() {
		refused = refused || e.Outcome == "deadline"
	}
	if !refused {
		t.Fatal("the refusal past the task deadline was not audited")
	}
}

func TestVerifierOutageDeniesEverySessionThenRecovers(t *testing.T) {
	g, minter, addr := acceptanceBroker(t)
	a := openAgentSession(t, addr, "agent-a", "canary")
	defer a.close()
	b := openAgentSession(t, addr, "agent-b", "canary")
	defer b.close()

	g.verifierOut.Store(true)
	waitEnded(t, a, "A during the verifier outage")
	waitEnded(t, b, "B during the verifier outage")
	minted := minter.mints("agent-a") + minter.mints("agent-b")
	for _, token := range []string{"agent-a", "agent-b", "static-fallback"} {
		if code := connectExpectCode(t, addr, token, "canary"); code == "OK" || code == "" {
			t.Fatalf("%s opened a session with the verifier down: %q", token, code)
		}
	}
	if got := minter.mints("agent-a") + minter.mints("agent-b") + minter.mints("static-fallback"); got != minted {
		t.Fatalf("credentials issued during the outage: %d, want %d", got, minted)
	}

	g.verifierOut.Store(false)
	for _, token := range []string{"agent-a", "agent-b"} {
		if code := connectExpectCode(t, addr, token, "canary"); code != "OK" {
			t.Fatalf("%s after the verifier returned = %q, want OK", token, code)
		}
	}
}

// The acceptance runbook measures withdrawal against 35 s (end) and 45 s (role gone).
func TestDefaultWithdrawalBoundsFitTheAcceptanceWindow(t *testing.T) {
	b := New("", Options{})
	if b.opts.AuthorizationInterval != 30*time.Second || b.opts.AuthorizationTimeout != 5*time.Second || leaseRevokeTimeout != 4*time.Second {
		t.Fatalf("recheck %v, verifier deadline %v, revoke %v: update the acceptance runbook with any change",
			b.opts.AuthorizationInterval, b.opts.AuthorizationTimeout, leaseRevokeTimeout)
	}
	end := b.opts.AuthorizationInterval + b.opts.AuthorizationTimeout
	if end > 35*time.Second || end+leaseRevokeTimeout > 45*time.Second {
		t.Fatalf("withdrawal ends within %v and clears within %v, past the 35 s and 45 s thresholds", end, end+leaseRevokeTimeout)
	}
}
