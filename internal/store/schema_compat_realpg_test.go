//go:build realpg

package store

import (
	"os"
	"testing"
)

// Applies this build's migrations only; the schema-compat CI job then runs the previous build's tests on the result.
func TestSchemaCompat_ApplyMigrations(t *testing.T) {
	if os.Getenv("AV_SCHEMA_COMPAT_APPLY") != "1" {
		t.Skip("run by the schema-compat CI job")
	}
	dsn := os.Getenv("AV_TEST_STORE_PG_URL")
	if dsn == "" {
		t.Fatal("AV_TEST_STORE_PG_URL is required when AV_SCHEMA_COMPAT_APPLY=1")
	}
	s, err := openPostgres(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { s.Close() }()
	applied, err := loadAppliedMigrations(s.db)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range gormMigrations {
		if !applied[m.Name] {
			t.Fatalf("migration %s was not applied", m.Name)
		}
	}
}
