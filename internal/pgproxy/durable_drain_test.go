package pgproxy

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/hashicorp"
	"github.com/Infisical/agent-vault/internal/store"
)

var drainService = &DatabaseService{Name: "db", Mount: "database", Role: "reader"}

func blockIssuance(f *durableVaultFixture) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mintStarted = make(chan struct{})
	f.mintRelease = make(chan struct{})
}

func waitIssuance(t *testing.T, f *durableVaultFixture) {
	t.Helper()
	select {
	case <-f.mintStarted:
	case <-time.After(10 * time.Second):
		t.Fatal("issuance not reached")
	}
}

func unresolved(t *testing.T, st *store.SQLStore) []store.DatabaseCleanup {
	t.Helper()
	records, err := st.ListDatabaseCleanup(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return records
}

// A restart arrives while a credential read is in flight: the broker's session
// context ends and the minter closes. The read finishes, its lease is
// journaled and, with no caller left to use it, revoked. Nothing is left for
// an operator, and Close reports a complete shutdown.
func TestDurableLeaseCloseLetsIssuanceUnderWayFinish(t *testing.T) {
	client, st, f := durableFixture(t)
	m := newDurableForTest(t, client, st)
	blockIssuance(f)
	caller, leave := context.WithCancel(context.Background())
	minted := make(chan error, 1)
	go func() {
		_, err := m.Mint(caller, AgentScope{VaultID: "vault"}, drainService)
		minted <- err
	}()
	waitIssuance(t, f)
	leave()
	closed := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		closed <- m.Close(ctx)
	}()
	select {
	case err := <-closed:
		t.Fatalf("close did not wait for the issuance under way: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if m.Ready() {
		t.Fatal("a draining minter reported ready")
	}
	close(f.mintRelease)
	if err := <-closed; err != nil {
		t.Fatalf("shutdown incomplete: %v", err)
	}
	if err := <-minted; !errors.Is(err, context.Canceled) {
		t.Fatalf("issuance for a departed caller returned %v", err)
	}
	if records := unresolved(t, st); len(records) != 0 {
		t.Fatalf("records left for an operator: %+v", records)
	}
	f.mu.Lock()
	if f.issued != 1 || len(f.live) != 0 {
		t.Errorf("issued %d, live %v: the drained credential was not revoked", f.issued, f.live)
	}
	f.mu.Unlock()
	if _, err := m.Mint(context.Background(), AgentScope{VaultID: "vault"}, drainService); !errors.Is(err, errDraining) {
		t.Fatalf("issuance after close returned %v", err)
	}
}

// startMidMintHelper runs a broker process against this test's Vault fixture
// and journal file, and returns once that process is inside a credential read.
func startMidMintHelper(t *testing.T, f *durableVaultFixture, path string) *exec.Cmd {
	t.Helper()
	blockIssuance(f)
	cmd := exec.Command(os.Args[0], "-test.run=^TestMidMintHelperProcess$", "-test.count=1") // #nosec G702 -- re-runs this test binary
	cmd.Env = append(os.Environ(), "GH_MID_MINT_DB="+path)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	waitIssuance(t, f)
	return cmd
}

// The incident: a routine restart sends SIGTERM to a broker process in the
// middle of a credential read. The process drains instead of abandoning the
// read, so it exits cleanly and leaves no unknown issuance behind.
func TestRestartMidMintLeavesNothingForTheOperator(t *testing.T) {
	if os.Getenv("GH_MID_MINT_DB") != "" {
		t.Skip("helper process")
	}
	path := filepath.Join(t.TempDir(), "journal.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_, _, f := durableFixtureOn(t, st)
	cmd := startMidMintHelper(t, f, path)
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	close(f.mintRelease)
	if err := cmd.Wait(); err != nil {
		t.Fatalf("broker did not stop cleanly (database cleanup shutdown incomplete): %v", err)
	}
	if records := unresolved(t, st); len(records) != 0 {
		t.Fatalf("records left for an operator: %+v", records)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.issued != 1 || len(f.live) != 0 {
		t.Fatalf("issued %d, live %v", f.issued, f.live)
	}
}

// A broker process killed in the middle of a credential read leaves an
// unknown issuance. Its successor keeps the database open throughout, keeps
// the record while Vault lists the lost credential's lease, and clears it on
// its own once the lease is gone.
func TestKilledMidMintKeepsTheDatabaseOpenAndClearsWhenVaultShowsNoLease(t *testing.T) {
	if os.Getenv("GH_MID_MINT_DB") != "" {
		t.Skip("helper process")
	}
	path := filepath.Join(t.TempDir(), "journal.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	client, _, f := durableFixtureOn(t, st)
	cmd := startMidMintHelper(t, f, path)
	if err := cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	records := unresolved(t, st)
	if len(records) != 1 || records[0].LeaseID != "" || records[0].Mount != "database" || records[0].Role != "reader" {
		t.Fatalf("want one unknown issuance naming its credential path, got %+v", records)
	}
	f.mu.Lock()
	ref := records[0].Accessor
	if !f.live[ref] {
		t.Fatal("fixture did not issue the lost credential")
	}
	f.mintStarted, f.mintRelease = nil, nil
	f.mu.Unlock()
	successor, err := NewDurableLeaseMinter(context.Background(), client, st, DurableLeaseOptions{
		OwnerTTL: 3 * time.Second, RetryInterval: 50 * time.Millisecond, UnknownSettle: 200 * time.Millisecond, UnknownRecheck: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer successor.Close(context.Background())
	lease, err := successor.Mint(context.Background(), AgentScope{VaultID: "vault"}, drainService)
	if err != nil {
		t.Fatal("database closed after a killed broker:", err)
	}
	if err := successor.Revoke(context.Background(), lease.ID); err != nil {
		t.Fatal(err)
	}
	waitWithin(t, 8*time.Second, "an automatic check after the predecessor's row expired", func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.lists >= 2
	})
	if records := unresolved(t, st); len(records) != 1 {
		t.Fatalf("unknown issuance cleared while its lease was live: %+v", records)
	}
	f.mu.Lock()
	if !f.live[ref] {
		t.Error("the broker revoked a lease too young to be an orphan")
	}
	// Vault expires the child token and revokes the lease it issued.
	delete(f.live, ref)
	f.mu.Unlock()
	waitWithin(t, 3*time.Second, "automatic reconciliation", func() bool { return len(unresolved(t, st)) == 0 })
}

// TestMidMintHelperProcess is a broker process: it starts one credential read
// and, on SIGTERM, stops as the server does: the session context ends, then
// the minter closes on the server's five-second budget.
func TestMidMintHelperProcess(t *testing.T) {
	path := os.Getenv("GH_MID_MINT_DB")
	if path == "" {
		t.Skip("run by the mid-mint restart tests")
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM)
	st, err := store.Open(path)
	if err != nil {
		os.Exit(2)
	}
	client, err := hashicorp.NewClient(context.Background(), slog.New(slog.DiscardHandler))
	if err != nil {
		os.Exit(2)
	}
	m, err := NewDurableLeaseMinter(context.Background(), client, st, DurableLeaseOptions{OwnerTTL: 3 * time.Second, RetryInterval: time.Hour, TokenTTL: time.Second})
	if err != nil {
		os.Exit(3)
	}
	session, leave := context.WithCancel(context.Background())
	go func() { _, _ = m.Mint(session, AgentScope{VaultID: "vault"}, drainService) }()
	<-signals
	leave()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	closeErr := m.Close(ctx)
	cancel()
	if closeErr != nil {
		os.Exit(5)
	}
	os.Exit(0)
}

// A lost response in a live process: the process revokes the child token with
// the token itself. The database keeps issuing, and the record clears once the
// settle time has passed and Vault lists no lease for it.
func TestLostResponseClearsAfterSettleWhenVaultListsNoLease(t *testing.T) {
	client, st, f := durableFixture(t)
	m, err := NewDurableLeaseMinter(context.Background(), client, st, DurableLeaseOptions{
		RetryInterval: 20 * time.Millisecond, UnknownSettle: 300 * time.Millisecond, UnknownRecheck: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close(context.Background())
	f.mu.Lock()
	f.loseResponse = true
	f.mu.Unlock()
	if _, err := m.Mint(context.Background(), AgentScope{VaultID: "vault"}, drainService); err == nil {
		t.Fatal("interrupted response accepted")
	}
	f.mu.Lock()
	f.loseResponse = false
	f.mu.Unlock()
	lease, err := m.Mint(context.Background(), AgentScope{VaultID: "vault"}, drainService)
	if err != nil {
		t.Fatal("database closed by a lost response:", err)
	}
	f.mu.Lock()
	lists := f.lists
	f.mu.Unlock()
	if lists != 0 {
		t.Fatalf("Vault's lease list was read %d times before the settle time", lists)
	}
	waitWithin(t, 3*time.Second, "automatic reconciliation", func() bool { return len(unresolved(t, st)) == 1 })
	if records := unresolved(t, st); records[0].LeaseID != lease.ID {
		t.Fatalf("the remaining record is not the live session's: %+v", records)
	}
	if err := m.Revoke(context.Background(), lease.ID); err != nil {
		t.Fatal(err)
	}
}

// Without proof the record stays, and its database keeps issuing.
func TestUnresolvedUnknownIssuanceNeverClosesItsDatabase(t *testing.T) {
	for _, tc := range []struct {
		name    string
		setup   func(*durableVaultFixture)
		legacy  bool
		listing bool
	}{
		{name: "lease list refused", setup: func(f *durableVaultFixture) { f.denyList = true }, listing: true},
		{name: "another client's lease on the role", setup: func(f *durableVaultFixture) {
			f.foreign = []string{"database/creds/reader/someone-else"}
		}, listing: true},
		{name: "older build's record, before its token can have expired", legacy: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, st, f := durableFixture(t)
			m, err := NewDurableLeaseMinter(context.Background(), client, st, DurableLeaseOptions{
				RetryInterval: 20 * time.Millisecond, UnknownSettle: 50 * time.Millisecond, UnknownRecheck: 20 * time.Millisecond,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer m.Close(context.Background())
			if tc.setup != nil {
				f.mu.Lock()
				tc.setup(f)
				f.mu.Unlock()
			}
			if tc.legacy {
				record := store.DatabaseCleanup{Accessor: "legacy", Binding: databaseBinding("vault", drainService)}
				if err := st.AddDatabaseCleanup(context.Background(), m.owner, record); err != nil {
					t.Fatal(err)
				}
			} else {
				f.mu.Lock()
				f.loseResponse = true
				f.mu.Unlock()
				if _, err := m.Mint(context.Background(), AgentScope{VaultID: "vault"}, drainService); err == nil {
					t.Fatal("interrupted response accepted")
				}
				f.mu.Lock()
				f.loseResponse = false
				f.mu.Unlock()
			}
			time.Sleep(500 * time.Millisecond)
			lease, err := m.Mint(context.Background(), AgentScope{VaultID: "vault"}, drainService)
			if err != nil {
				t.Fatal("an unresolved record closed its database:", err)
			}
			if err := m.Revoke(context.Background(), lease.ID); err != nil {
				t.Fatal(err)
			}
			if records := unresolved(t, st); len(records) != 1 || records[0].LeaseID != "" || records[0].Quarantined {
				t.Fatalf("unknown issuance not kept, or kept as closing its database: %+v", records)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if (f.lists > 0) != tc.listing {
				t.Fatalf("lease list read %d times", f.lists)
			}
		})
	}
}

// A record from an older build names no credential path. The first request for
// its binding is served and adopts the binding's mount and role and a token
// expiry one TokenTTL from then; after that and the settle time, Vault's lease
// list decides as for any other record.
func TestOlderBuildsUnknownIssuanceClearsAfterAdoption(t *testing.T) {
	client, st, _ := durableFixture(t)
	m, err := NewDurableLeaseMinter(context.Background(), client, st, DurableLeaseOptions{
		TokenTTL: time.Second, RetryInterval: 20 * time.Millisecond, UnknownSettle: 100 * time.Millisecond, UnknownRecheck: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close(context.Background())
	record := store.DatabaseCleanup{Accessor: "older-build", Binding: databaseBinding("vault", drainService)}
	if err := st.AddDatabaseCleanup(context.Background(), m.owner, record); err != nil {
		t.Fatal(err)
	}
	if err := st.QuarantineDatabaseCleanup(context.Background(), m.owner, "older-build"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if records := unresolved(t, st); len(records) != 1 || records[0].Mount != "" {
		t.Fatalf("record adopted before any request named its binding: %+v", records)
	}
	lease, err := m.Mint(context.Background(), AgentScope{VaultID: "vault"}, drainService)
	if err != nil {
		t.Fatal("an older build's record closed its database:", err)
	}
	if err := m.Revoke(context.Background(), lease.ID); err != nil {
		t.Fatal(err)
	}
	if records := unresolved(t, st); len(records) != 1 || records[0].Mount != "database" || records[0].Role != "reader" || records[0].Quarantined {
		t.Fatalf("record not adopted, or still closing its database: %+v", records)
	}
	waitWithin(t, 5*time.Second, "automatic reconciliation of the adopted record", func() bool { return len(unresolved(t, st)) == 0 })
}

// lostWithLiveLease loses a credential response whose child token cannot
// revoke itself, so the lost lease stays live in Vault, issued an orphan's
// age ago.
func lostWithLiveLease(t *testing.T, m *DurableLeaseMinter, f *durableVaultFixture) {
	t.Helper()
	f.mu.Lock()
	f.loseResponse, f.failSelfRevoke, f.leaseAge = true, true, 10*time.Minute
	f.mu.Unlock()
	if _, err := m.Mint(context.Background(), AgentScope{VaultID: "vault"}, drainService); err == nil {
		t.Fatal("interrupted response accepted")
	}
	f.mu.Lock()
	f.loseResponse, f.failSelfRevoke, f.leaseAge = false, false, 0
	if len(f.live) != 1 {
		t.Fatalf("live leases %v, want the lost one", f.live)
	}
	f.mu.Unlock()
}

// Once the child token is dead, an unaccounted lease older than any issuance
// still under way is an orphan: the broker revokes it by path and clears the
// record, without waiting for Vault.
func TestTheBrokerRevokesAnOrphanLease(t *testing.T) {
	client, st, f := durableFixture(t)
	m, err := NewDurableLeaseMinter(context.Background(), client, st, DurableLeaseOptions{
		TokenTTL: time.Second, RetryInterval: 20 * time.Millisecond, UnknownSettle: 100 * time.Millisecond, UnknownRecheck: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close(context.Background())
	lostWithLiveLease(t, m, f)
	waitWithin(t, 5*time.Second, "the orphan revoked and the record cleared", func() bool { return len(unresolved(t, st)) == 0 })
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.live) != 0 {
		t.Fatalf("orphan lease still live: %v", f.live)
	}
}

// The one case that closes a database: Vault cannot revoke the orphan lease
// (the database refuses to drop the role). Only that database closes; others
// keep issuing; it reopens on its own once the revocation succeeds.
func TestAnUnrevocableOrphanClosesOnlyItsOwnDatabase(t *testing.T) {
	client, st, f := durableFixture(t)
	m, err := NewDurableLeaseMinter(context.Background(), client, st, DurableLeaseOptions{
		TokenTTL: time.Second, RetryInterval: 20 * time.Millisecond, UnknownSettle: 100 * time.Millisecond, UnknownRecheck: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close(context.Background())
	lostWithLiveLease(t, m, f)
	f.mu.Lock()
	f.failRevoke = true
	f.mu.Unlock()
	waitWithin(t, 5*time.Second, "the unrevocable orphan to close its database", func() bool {
		records := unresolved(t, st)
		return len(records) == 1 && records[0].Quarantined
	})
	if _, err := m.Mint(context.Background(), AgentScope{VaultID: "vault"}, drainService); err == nil {
		t.Fatal("database issued while Vault could not revoke an orphan lease under its role")
	}
	f.mu.Lock()
	f.failRevoke = false
	f.mu.Unlock()
	other := &DatabaseService{Name: "other", Mount: "database", Role: "writer"}
	lease, err := m.Mint(context.Background(), AgentScope{VaultID: "vault"}, other)
	if err != nil {
		t.Fatal("a closed database closed another:", err)
	}
	if err := m.Revoke(context.Background(), lease.ID); err != nil {
		t.Fatal(err)
	}
	waitWithin(t, 5*time.Second, "the database reopened after revocation succeeded", func() bool { return len(unresolved(t, st)) == 0 })
	lease, err = m.Mint(context.Background(), AgentScope{VaultID: "vault"}, drainService)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Revoke(context.Background(), lease.ID); err != nil {
		t.Fatal(err)
	}
}

// The server starts the drain when SIGTERM arrives, before its listeners
// drain: readiness turns false at once and no new issuance starts.
func TestBeginDrainStopsReadinessAndNewIssuance(t *testing.T) {
	client, st, _ := durableFixture(t)
	m := newDurableForTest(t, client, st)
	if !m.Ready() {
		t.Fatal("a fresh minter is not ready")
	}
	m.BeginDrain()
	if m.Ready() {
		t.Fatal("ready while draining")
	}
	if _, err := m.Mint(context.Background(), AgentScope{VaultID: "vault"}, drainService); !errors.Is(err, errDraining) {
		t.Fatalf("issuance while draining: %v", err)
	}
}
