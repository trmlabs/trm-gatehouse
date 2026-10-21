package pgproxy

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// budgetBroker serves svc through a broker that shares ledger with others.
func budgetBroker(t *testing.T, ledger SessionLedger, svc *DatabaseService) string {
	t.Helper()
	_, addr := startBroker(t, Options{
		Auth:      &fakeAuth{scope: &AgentScope{VaultID: "vault-1", ActorID: "agent-7"}},
		Databases: &fakeResolver{svc: svc},
		Leases:    &fakeMinter{lease: newLease()},
		Sessions:  ledger,
	})
	return addr
}

func (l *fakeLedger) count(key string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, k := range l.sessions {
		if k == key {
			n++
		}
	}
	return n
}

// With a shared ledger a database's maxConns is the whole fleet's: replicas
// together open no more upstream connections than it, any replica may take a
// free one however the load is spread, and a closed session frees its place.
func TestDatabaseBudgetHoldsAcrossReplicas(t *testing.T) {
	upstream := startFakeUpstream(t, authTrust, newLease().Password)
	svc := &DatabaseService{Name: "analytics", Addr: upstream.addr(), Mount: "database", Role: "readonly", SSLMode: "disable", MaxConns: 4}
	ledger := &fakeLedger{sessions: map[string]string{}}
	first, second := budgetBroker(t, ledger, svc), budgetBroker(t, ledger, svc)
	var held []*agentSession
	for _, addr := range []string{first, first, first, second} {
		held = append(held, openAgentSession(t, addr, "agent-vault-token", "appdb"))
	}
	for _, addr := range []string{first, second} {
		if code := connectExpectCode(t, addr, "agent-vault-token", "appdb"); code != "53300" {
			t.Fatalf("session past the fleet's budget: %q, want 53300", code)
		}
	}
	upstream.mu.Lock()
	accepted := upstream.accepted
	upstream.mu.Unlock()
	if accepted != 4 {
		t.Fatalf("two replicas opened %d upstream connections, budget 4", accepted)
	}
	if n := ledger.count(databaseLedgerKey(svc)); n != 4 {
		t.Fatalf("ledger counts %d sessions on the database, want 4", n)
	}
	// A session closed on one replica frees a place the other can take.
	held[0].close()
	waitFor(t, 2*time.Second, func() bool { return ledger.count(databaseLedgerKey(svc)) == 3 }, "closed session still counted")
	held = append(held[1:], openAgentSession(t, second, "agent-vault-token", "appdb"))
	for _, s := range held {
		s.close()
	}
	waitFor(t, 2*time.Second, func() bool { return ledger.count(databaseLedgerKey(svc)) == 0 }, "ended sessions still counted")
}

// Without the shared count no database connection opens: the session is
// refused as accounting unavailable before any credential is minted.
func TestDatabaseLedgerOutageRefusesSessions(t *testing.T) {
	upstream := startFakeUpstream(t, authTrust, newLease().Password)
	minter := &fakeMinter{lease: newLease()}
	_, addr := startBroker(t, Options{
		Auth:      &fakeAuth{scope: &AgentScope{VaultID: "vault-1", ActorID: "agent-7"}},
		Databases: &fakeResolver{svc: &DatabaseService{Name: "analytics", Addr: upstream.addr(), SSLMode: "disable"}},
		Leases:    minter,
		Sessions:  &fakeLedger{sessions: map[string]string{}, err: errors.New("store down")},
	})
	if code := connectExpectCode(t, addr, "agent-vault-token", "appdb"); code != "08004" {
		t.Fatalf("session without the shared count: %q, want 08004", code)
	}
	if minter.mintCallCount() != 0 {
		t.Fatal("a credential was minted without the shared count")
	}
}

// flakyLedger fails the first failures removals.
type flakyLedger struct {
	*fakeLedger
	mu       sync.Mutex
	failures int
}

func (l *flakyLedger) Remove(ctx context.Context, id string) error {
	l.mu.Lock()
	fail := l.failures > 0
	if fail {
		l.failures--
	}
	l.mu.Unlock()
	if fail {
		return errors.New("store unavailable")
	}
	return l.fakeLedger.Remove(ctx, id)
}

// A removal that fails is retried, so the row does not hold a place in the
// fleet's count for as long as this replica lives.
func TestFailedLedgerRemovalIsRetried(t *testing.T) {
	upstream := startFakeUpstream(t, authTrust, newLease().Password)
	svc := &DatabaseService{Name: "analytics", Addr: upstream.addr(), SSLMode: "disable", MaxConns: 1}
	ledger := &flakyLedger{fakeLedger: &fakeLedger{sessions: map[string]string{}}, failures: 2}
	addr := budgetBroker(t, ledger, svc)
	openAgentSession(t, addr, "agent-vault-token", "appdb").close()
	waitFor(t, 6*time.Second, func() bool { return ledger.count(databaseLedgerKey(svc)) == 0 }, "failed removal was not retried")
	openAgentSession(t, addr, "agent-vault-token", "appdb").close()
}
