//go:build realvault

// Real-Vault test for the database reader; run `go test -tags realvault ./internal/hashicorp/ -run RealVault`
// with VAULT_ADDR, a token or AppRole, and the AV_TEST_VAULT_* and AV_TEST_PG_* variables set.
package hashicorp

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestRealVault_DatabaseEngine_EndToEnd(t *testing.T) {
	if os.Getenv("VAULT_ADDR") == "" || os.Getenv("AV_TEST_PG_UPSTREAM") == "" || os.Getenv("AV_TEST_PG_ADMIN") == "" {
		t.Skip("set VAULT_ADDR (+token), AV_TEST_PG_UPSTREAM, AV_TEST_PG_DB, AV_TEST_PG_ADMIN to run the real-Vault integration test")
	}
	mount := envOr("AV_TEST_VAULT_MOUNT", "database")
	role := envOr("AV_TEST_VAULT_ROLE", "readonly")
	upstream := os.Getenv("AV_TEST_PG_UPSTREAM")
	database := envOr("AV_TEST_PG_DB", "appdb")
	adminDSN := os.Getenv("AV_TEST_PG_ADMIN")

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	client, err := NewClient(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewClient against real Vault: %v", err)
	}

	first, err := client.ReadDatabaseCredential(ctx, mount, role)
	if err != nil {
		t.Fatalf("first ReadDatabaseCredential: %v", err)
	}
	second, err := client.ReadDatabaseCredential(ctx, mount, role)
	if err != nil {
		t.Fatalf("second ReadDatabaseCredential: %v", err)
	}
	defer func() { _ = client.RevokeLease(context.Background(), second.LeaseID) }()

	if first.Username == second.Username {
		t.Fatalf("expected distinct dynamic users, both were %q", first.Username)
	}
	if first.LeaseID == "" || first.Password == "" || first.LeaseDuration <= 0 {
		t.Fatalf("malformed credential: %+v", first)
	}

	userDSN := fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable", first.Username, first.Password, upstream, database)
	conn, err := pgx.Connect(ctx, userDSN)
	if err != nil {
		t.Fatalf("connect to Postgres as the Vault-minted user: %v", err)
	}
	var whoami string
	if err := conn.QueryRow(ctx, "SELECT current_user").Scan(&whoami); err != nil {
		t.Fatalf("query as minted user: %v", err)
	}
	if whoami != first.Username {
		t.Fatalf("connected as %q, want %q", whoami, first.Username)
	}
	_ = conn.Close(ctx)

	if first.Renewable {
		if _, err := client.RenewLease(ctx, first.LeaseID, time.Minute); err != nil {
			t.Fatalf("RenewLease: %v", err)
		}
	}

	if err := client.RevokeLease(ctx, first.LeaseID); err != nil {
		t.Fatalf("RevokeLease: %v", err)
	}
	admin, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("connect as admin: %v", err)
	}
	defer func() { _ = admin.Close(ctx) }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var count int
		if err := admin.QueryRow(ctx, "SELECT count(*) FROM pg_roles WHERE rolname = $1", first.Username).Scan(&count); err != nil {
			t.Fatalf("check role dropped: %v", err)
		}
		if count == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Vault-minted role %q was not dropped after revoke", first.Username)
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Logf("real Vault minted distinct users %q and %q; first connected to Postgres and was dropped on revoke", first.Username, second.Username)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
