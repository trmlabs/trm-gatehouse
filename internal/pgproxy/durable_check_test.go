package pgproxy

import (
	"context"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/hashicorp"
	"github.com/Infisical/agent-vault/internal/store"
)

// checkOnlyMinter runs no background pass, so the test drives every check.
func checkOnlyMinter(t *testing.T, client *hashicorp.Client, journal CleanupJournal) *DurableLeaseMinter {
	t.Helper()
	m, err := NewDurableLeaseMinter(context.Background(), client, journal, DurableLeaseOptions{
		TokenTTL: time.Second, RetryInterval: time.Hour, UnknownSettle: 100 * time.Millisecond, UnknownRecheck: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = m.Close(ctx)
	})
	return m
}

// checkAgain runs one check pass once the recheck spacing has passed.
func checkAgain(m *DurableLeaseMinter) {
	time.Sleep(2 * m.opts.UnknownRecheck)
	m.checkUnknowns()
}

func waitSettled(t *testing.T, st *store.SQLStore, m *DurableLeaseMinter) {
	t.Helper()
	waitWithin(t, 5*time.Second, "the lost issuance to settle", func() bool {
		records, err := st.SettledDatabaseCleanup(context.Background(), m.owner, m.opts.UnknownSettle)
		return err == nil && len(records) == 1
	})
}

func drainClosed(t *testing.T, st *store.SQLStore) bool {
	t.Helper()
	closed, err := st.DatabaseBindingQuarantined(context.Background(), databaseBinding("vault", drainService))
	if err != nil {
		t.Fatal(err)
	}
	return closed
}

func setFixture(f *durableVaultFixture, change func(*durableVaultFixture)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	change(f)
}

// stuckDatabase loses a response whose lease stays live, then has Vault refuse
// the orphan's revocation on two checks in a row: only the second closes the
// database.
func stuckDatabase(t *testing.T, m *DurableLeaseMinter, st *store.SQLStore, f *durableVaultFixture) {
	t.Helper()
	lostWithLiveLease(t, m, f)
	waitSettled(t, st, m)
	setFixture(f, func(f *durableVaultFixture) { f.failRevoke = true })
	checkAgain(m)
	if drainClosed(t, st) {
		t.Fatal("one refused revocation closed the database")
	}
	checkAgain(m)
	if !drainClosed(t, st) {
		t.Fatal("two refused revocations in a row left the database open")
	}
}

// reopens checks that a successful check reopens the database and the next
// clears the record, after which the database issues.
func reopens(t *testing.T, m *DurableLeaseMinter, st *store.SQLStore) {
	t.Helper()
	checkAgain(m)
	if drainClosed(t, st) {
		t.Fatal("the database stayed closed after Vault revoked the orphan")
	}
	checkAgain(m)
	if records := unresolved(t, st); len(records) != 0 {
		t.Fatalf("records remain after a clean check: %+v", records)
	}
	lease, err := m.Mint(context.Background(), AgentScope{VaultID: "vault"}, drainService)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Revoke(context.Background(), lease.ID); err != nil {
		t.Fatal(err)
	}
}

// A database closed over an unrevocable orphan stays closed while Vault
// refuses the lease list: a check that cannot finish proves nothing.
func TestAStuckDatabaseStaysClosedWhileTheLeaseListIsRefused(t *testing.T) {
	client, st, f := durableFixture(t)
	m := checkOnlyMinter(t, client, st)
	stuckDatabase(t, m, st, f)
	setFixture(f, func(f *durableVaultFixture) { f.failRevoke, f.denyList = false, true })
	for range 3 {
		checkAgain(m)
	}
	if !drainClosed(t, st) {
		t.Fatal("a refused lease list reopened a database Vault cannot clean")
	}
	if _, err := m.Mint(context.Background(), AgentScope{VaultID: "vault"}, drainService); err == nil {
		t.Fatal("the closed database issued")
	}
	setFixture(f, func(f *durableVaultFixture) { f.denyList = false })
	reopens(t, m, st)
}

// A graceful stop is not a check: the database stays closed through it, and
// the replica that takes the record over keeps it closed until its own check
// succeeds.
func TestAStuckDatabaseStaysClosedAcrossAGracefulStop(t *testing.T) {
	client, st, f := durableFixture(t)
	m := checkOnlyMinter(t, client, st)
	stuckDatabase(t, m, st, f)
	if err := m.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !drainClosed(t, st) {
		t.Fatal("a graceful stop reopened a database Vault cannot clean")
	}
	next := checkOnlyMinter(t, client, st)
	if records := unresolved(t, st); len(records) != 1 || !records[0].Quarantined {
		t.Fatalf("the record did not survive the stop closed: %+v", records)
	}
	if _, err := next.Mint(context.Background(), AgentScope{VaultID: "vault"}, drainService); err == nil {
		t.Fatal("the closed database issued after a restart")
	}
	checkAgain(next) // Vault still refuses
	if !drainClosed(t, st) {
		t.Fatal("the new replica reopened the database while Vault still refuses")
	}
	setFixture(f, func(f *durableVaultFixture) { f.failRevoke = false })
	reopens(t, next, st)
}

// A revocation that fails because Vault is overloaded or unreachable is a
// blip, never proof that the database refuses to drop the role: however many
// checks meet it, the database stays open.
func TestOrphanRevokeBlipsNeverCloseTheDatabase(t *testing.T) {
	client, st, f := durableFixture(t)
	m := checkOnlyMinter(t, client, st)
	lostWithLiveLease(t, m, f)
	waitSettled(t, st, m)
	setFixture(f, func(f *durableVaultFixture) { f.revokeStatus = http.StatusServiceUnavailable })
	for range 3 {
		checkAgain(m)
		if drainClosed(t, st) {
			t.Fatal("a Vault blip closed the database")
		}
	}
	setFixture(f, func(f *durableVaultFixture) { f.revokeStatus = 0 })
	reopens(t, m, st)
}

// countingJournal counts the reads a check pass makes.
type countingJournal struct {
	*store.SQLStore
	settled, fleet atomic.Int64
}

func (c *countingJournal) SettledDatabaseCleanup(ctx context.Context, owner string, settle time.Duration) ([]store.DatabaseCleanup, error) {
	c.settled.Add(1)
	return c.SQLStore.SettledDatabaseCleanup(ctx, owner, settle)
}

func (c *countingJournal) ListDatabaseCleanup(ctx context.Context) ([]store.DatabaseCleanup, error) {
	c.fleet.Add(1)
	return c.SQLStore.ListDatabaseCleanup(ctx)
}

// A Vault outage can leave thousands of unknown issuances. Requests for their
// databases never run the check, and one pass reads the settled set and the
// fleet's journal once and lists each mount and role once, however many
// records share them.
func TestUnknownChecksStayLinearInTheBacklog(t *testing.T) {
	client, st, f := durableFixture(t)
	journal := &countingJournal{SQLStore: st}
	m := checkOnlyMinter(t, client, journal)
	const records, roles = 2000, 4
	ctx := context.Background()
	for i := range records {
		role := fmt.Sprintf("r%d", i%roles)
		record := store.DatabaseCleanup{Accessor: fmt.Sprintf("lost-%04d", i), Binding: databaseBinding("vault", &DatabaseService{Name: role}),
			Mount: "database", Role: role, TokenTTL: time.Millisecond}
		if err := st.AddDatabaseCleanup(ctx, m.owner, record); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(2 * m.opts.UnknownSettle)
	for i := range roles {
		svc := &DatabaseService{Name: fmt.Sprintf("r%d", i), Mount: "database", Role: fmt.Sprintf("r%d", i)}
		lease, err := m.Mint(ctx, AgentScope{VaultID: "vault"}, svc)
		if err != nil {
			t.Fatal("a backlog of unknown issuances closed a database:", err)
		}
		if err := m.Revoke(ctx, lease.ID); err != nil {
			t.Fatal(err)
		}
	}
	f.mu.Lock()
	lists := f.lists
	f.mu.Unlock()
	if lists != 0 || journal.settled.Load() != 0 {
		t.Fatalf("requests ran the check: %d lease lists, %d settled reads", lists, journal.settled.Load())
	}
	started := time.Now()
	m.checkUnknowns()
	elapsed := time.Since(started)
	if left := unresolved(t, st); len(left) != 0 {
		t.Fatalf("%d of %d records left after one pass", len(left), records)
	}
	f.mu.Lock()
	lists = f.lists
	f.mu.Unlock()
	if lists != roles || journal.settled.Load() != 1 || journal.fleet.Load() != 1 {
		t.Fatalf("one pass over %d records: %d lease lists (want %d), %d settled reads, %d fleet reads (want 1 each)",
			records, lists, roles, journal.settled.Load(), journal.fleet.Load())
	}
	t.Logf("one pass cleared %d unknown issuances in %v", records, elapsed)
}
