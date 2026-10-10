//go:build realpg

package store

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// migrate-db carries the broker's tables to PostgreSQL. A pending cleanup
// record arrives without an owner, so the first live broker claims it, and the
// audit boot counter continues instead of restarting at 1.
func TestRealPostgres_MigrateCarriesBrokerTables(t *testing.T) {
	dsn := os.Getenv("AV_TEST_STORE_PG_URL")
	if dsn == "" {
		t.Skip("set AV_TEST_STORE_PG_URL")
	}
	ctx := context.Background()
	admin, err := openPostgres(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	name := fmt.Sprintf("migrate_%d", time.Now().UnixNano())
	if _, err := admin.db.Exec("CREATE DATABASE " + name); err != nil { // #nosec G202 -- generated name
		t.Fatal(err)
	}
	defer func() { _, _ = admin.db.Exec("DROP DATABASE " + name + " WITH (FORCE)") }() // #nosec G202 -- generated name
	target, _ := url.Parse(dsn)
	target.Path = "/" + name

	src, err := Open(filepath.Join(t.TempDir(), "source.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	if err := src.ClaimDatabaseCleanupOwner(ctx, "sqlite-broker", time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := src.AddDatabaseCleanup(ctx, "sqlite-broker", DatabaseCleanup{Accessor: "pending", Binding: "vault/db"}); err != nil {
		t.Fatal(err)
	}
	if err := src.SetDatabaseCleanupLease(ctx, "sqlite-broker", "pending", "database/creds/readonly/abc"); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, _, err := src.BeginAuditBoot(ctx, "broker-0"); err != nil {
			t.Fatal(err)
		}
	}
	if err := src.InsertProxyAudit(ctx, ProxyAudit{RequestID: "r1", VaultID: "v", ActorType: "agent", ActorID: "a", WorkloadID: "w",
		Destination: "api.example.test", Service: "s", Method: "GET", Decision: "allow", StartedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	dst, err := openPostgres(target.String())
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()
	if err := MigrateData(ctx, src, dst, nil); err != nil {
		t.Fatal(err)
	}
	records, err := dst.ListDatabaseCleanup(ctx)
	if err != nil || len(records) != 1 || records[0].LeaseID != "database/creds/readonly/abc" {
		t.Fatalf("pending cleanup not carried: %+v %v", records, err)
	}
	if err := dst.ClaimDatabaseCleanupOwner(ctx, "fleet-0", time.Minute); err != nil {
		t.Fatal(err)
	}
	if n, err := dst.ClaimOrphanedDatabaseCleanup(ctx, "fleet-0"); err != nil || n != 1 {
		t.Fatalf("migrated record not claimable: %d %v", n, err)
	}
	boot, _, err := dst.BeginAuditBoot(ctx, "broker-0")
	if err != nil || boot != 4 {
		t.Fatalf("audit boot after migration = %d, want 4: %v", boot, err)
	}
	var audits int
	if err := dst.db.QueryRow("SELECT COUNT(*) FROM credential_proxy_audit").Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("proxy audit not carried: %d %v", audits, err)
	}
}

// A CA on disk that cannot be read leaves the destination untouched, so the
// rerun after fixing it starts clean instead of refusing a half-filled
// database; the rerun moves the data and the CA together.
func TestRealPostgres_MigrateWithCAIsAllOrNothing(t *testing.T) {
	dsn := os.Getenv("AV_TEST_STORE_PG_URL")
	if dsn == "" {
		t.Skip("set AV_TEST_STORE_PG_URL")
	}
	ctx := context.Background()
	admin, err := openPostgres(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	name := fmt.Sprintf("migrate_ca_%d", time.Now().UnixNano())
	if _, err := admin.db.Exec("CREATE DATABASE " + name); err != nil { // #nosec G202 -- generated name
		t.Fatal(err)
	}
	defer func() { _, _ = admin.db.Exec("DROP DATABASE " + name + " WITH (FORCE)") }() // #nosec G202 -- generated name
	target, _ := url.Parse(dsn)
	target.Path = "/" + name
	dir := t.TempDir()
	src, err := Open(filepath.Join(dir, "source.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	if _, err := src.CreateVault(ctx, "carried"); err != nil {
		t.Fatal(err)
	}
	caDir := filepath.Join(dir, "ca")
	if err := os.MkdirAll(caDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(caDir, "ca.crt.pem"), []byte("-----BEGIN CERTIFICATE-----\nsynthetic\n-----END CERTIFICATE-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(caDir, "ca.key.enc"), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	dst, err := openPostgres(target.String())
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()
	if _, err := MigrateDataWithCA(ctx, src, dst, caDir, nil); err == nil {
		t.Fatal("an unreadable CA key was accepted")
	}
	if found, err := CountDestinationData(dst); err != nil || found != "" {
		t.Fatalf("a failed migration left data behind (%q, %v); a rerun would refuse", found, err)
	}
	if err := os.WriteFile(filepath.Join(caDir, "ca.key.enc"), []byte(`{"nonce":"bm9uY2U=","ciphertext":"Y2lwaGVydGV4dA=="}`), 0o600); err != nil {
		t.Fatal(err)
	}
	moved, err := MigrateDataWithCA(ctx, src, dst, caDir, nil)
	if err != nil || !moved {
		t.Fatalf("rerun: moved %v, %v", moved, err)
	}
	if found, err := CountDestinationData(dst); err != nil || found == "" {
		t.Fatalf("rerun did not carry the data: %q %v", found, err)
	}
	state, err := dst.GetCAState(ctx)
	if err != nil || state == nil || state.Source != "migrated-from-disk" {
		t.Fatalf("CA not moved with the data: %+v %v", state, err)
	}
}
