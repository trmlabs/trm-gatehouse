//go:build realpg

package pgproxy

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// Two broker replicas that see each other split one database's maxConns in
// session mode: counted on the real database, they hold no more connections
// than the budget, and each refuses past its share.
func TestRealPostgres_SessionBudgetHoldsAcrossReplicas(t *testing.T) {
	upstream, adminDSN, database := os.Getenv("AV_TEST_PG_UPSTREAM"), os.Getenv("AV_TEST_PG_ADMIN"), os.Getenv("AV_TEST_PG_DB")
	if upstream == "" || adminDSN == "" || database == "" {
		t.Skip("set AV_TEST_PG_UPSTREAM, AV_TEST_PG_ADMIN, AV_TEST_PG_DB to run the real-PostgreSQL integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
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
	for range 2 {
		_, addr := startBroker(t, Options{
			Auth:      &fakeAuth{scope: &AgentScope{VaultID: "vault-it", ActorID: "agent-it"}},
			Databases: &fakeResolver{svc: svc},
			Leases:    newFleetMinter(lease, 2),
		})
		addrs = append(addrs, addr)
	}
	for _, addr := range addrs {
		for range budget / 2 {
			s := openAgentSession(t, addr, "agent-vault-token", database)
			t.Cleanup(s.close)
		}
		if code := connectExpectCode(t, addr, "agent-vault-token", database); code != "53300" {
			t.Fatalf("session past one replica's share: %q, want 53300", code)
		}
	}
	if n := connections(); n != budget {
		t.Fatalf("two replicas hold %d connections on the database, budget %d", n, budget)
	}
	t.Logf("two replicas held %d connections on %s against maxConns %d", budget, database, budget)
}
