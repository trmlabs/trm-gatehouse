//go:build realpg

package pgproxy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Infisical/agent-vault/internal/store"
)

// storeLedger is the server's session ledger over a real store, for one owner.
type storeLedger struct {
	st    *store.SQLStore
	owner string
}

func (l storeLedger) Add(ctx context.Context, id, key string, limit int) error {
	err := l.st.AddBrokerSession(ctx, l.owner, id, key, limit)
	if errors.Is(err, store.ErrPodSessionLimit) {
		return ErrSessionLimit
	}
	return err
}

func (l storeLedger) Remove(ctx context.Context, id string) error {
	return l.st.RemoveBrokerSession(ctx, id)
}

// Two broker replicas on one PostgreSQL store hold a database's maxConns
// across the fleet: counted on the real database, together they hold no more
// connections than it, however the load is spread between them.
func TestRealPostgres_DatabaseBudgetHoldsAcrossReplicas(t *testing.T) {
	upstream, adminDSN, database, storeDSN := os.Getenv("AV_TEST_PG_UPSTREAM"), os.Getenv("AV_TEST_PG_ADMIN"), os.Getenv("AV_TEST_PG_DB"), os.Getenv("AV_TEST_STORE_PG_URL")
	if upstream == "" || adminDSN == "" || database == "" || storeDSN == "" {
		t.Skip("set AV_TEST_PG_UPSTREAM, AV_TEST_PG_ADMIN, AV_TEST_PG_DB, AV_TEST_STORE_PG_URL to run the real-PostgreSQL integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	opened, err := store.OpenStore(store.StoreConfig{DatabaseURL: storeDSN})
	if err != nil {
		t.Fatal(err)
	}
	st, ok := opened.(*store.SQLStore)
	if !ok {
		t.Fatalf("unexpected store type %T", opened)
	}
	t.Cleanup(func() { _ = st.Close() })
	admin, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close(context.Background()) }()
	role := fmt.Sprintf("av_budget_%d", time.Now().UnixNano())
	roleSQL := pgx.Identifier{role}.Sanitize()
	const password = "synthetic-budget-password"
	if _, err := admin.Exec(ctx, "CREATE ROLE "+roleSQL+" LOGIN PASSWORD '"+password+"'"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = admin.Exec(context.Background(), "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = $1", role)
		_, _ = admin.Exec(context.Background(), "DROP ROLE IF EXISTS "+roleSQL)
	}()
	connections := func() int {
		var n int
		if err := admin.QueryRow(ctx, "SELECT count(*) FROM pg_stat_activity WHERE usename = $1 AND datname = $2", role, database).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	const budget = 4
	lease := &Lease{ID: "it-budget", Username: role, Password: password, ExpiresAt: time.Now().Add(time.Hour)}
	svc := &DatabaseService{Name: "analytics", Addr: upstream, Database: database, Mount: "database", Role: "readonly", MaxConns: budget}
	var addrs []string
	for i := range 2 {
		owner := fmt.Sprintf("budget-it-%d/%d", i, time.Now().UnixNano())
		if err := st.ClaimDatabaseCleanupOwner(ctx, owner, 5*time.Minute); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = st.ReleaseDatabaseCleanupOwner(context.Background(), owner) })
		_, addr := startBroker(t, Options{
			Auth:      &fakeAuth{scope: &AgentScope{VaultID: "vault-it", ActorID: "agent-it"}},
			Databases: &fakeResolver{svc: svc},
			Leases:    &fakeMinter{lease: lease},
			Sessions:  storeLedger{st: st, owner: owner},
		})
		addrs = append(addrs, addr)
	}
	// Uneven load: three sessions on one replica, one on the other.
	for _, addr := range []string{addrs[0], addrs[0], addrs[0], addrs[1]} {
		s := openAgentSession(t, addr, "agent-vault-token", database)
		t.Cleanup(s.close)
	}
	for _, addr := range addrs {
		if code := connectExpectCode(t, addr, "agent-vault-token", database); code != "53300" {
			t.Fatalf("session past the fleet's budget: %q, want 53300", code)
		}
	}
	if n := connections(); n != budget {
		t.Fatalf("two replicas hold %d connections on the database, budget %d", n, budget)
	}
	t.Logf("two replicas held %d connections on %s against maxConns %d", budget, database, budget)
}
