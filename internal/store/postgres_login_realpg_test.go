//go:build realpg

package store

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The store's password is rotated in the mounted file while the broker runs:
// the old password is refused, and the next connection re-reads the file and
// logs in with the new one, without a restart.
func TestRealPostgres_StoreRereadsRotatedLogin(t *testing.T) {
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
	name := fmt.Sprintf("rotate_%d", time.Now().UnixNano())
	exec := func(statement string) {
		t.Helper()
		if _, err := admin.db.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	exec("CREATE ROLE " + name + " LOGIN PASSWORD 'first-synthetic-password'")
	exec("CREATE DATABASE " + name + " OWNER " + name)
	defer func() {
		_, _ = admin.db.Exec("DROP DATABASE " + name + " WITH (FORCE)") // #nosec G202 -- generated name
		_, _ = admin.db.Exec("DROP ROLE " + name)                       // #nosec G202 -- generated name
	}()
	login := func(password string) string {
		u, _ := url.Parse(dsn)
		u.User = url.UserPassword(name, password)
		u.Path = "/" + name
		return u.String()
	}
	file := filepath.Join(t.TempDir(), "database-url")
	if err := os.WriteFile(file, []byte(login("first-synthetic-password")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	reads := 0
	reload := func() (string, error) {
		reads++
		data, err := os.ReadFile(file)
		return strings.TrimSpace(string(data)), err
	}
	initial, _ := reload()
	reads = 0
	s, err := openPostgresReloading(initial, reload)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// Every query takes a new connection, as one does after the pool recycles.
	s.db.SetMaxIdleConns(0)
	if _, err := s.CountUsers(ctx); err != nil {
		t.Fatal(err)
	}

	exec("ALTER ROLE " + name + " PASSWORD 'second-synthetic-password'")
	if old, err := openPostgres(login("first-synthetic-password")); err == nil {
		_ = old.Close()
		t.Fatal("the old password still logs in")
	} else if !loginRefused(err) {
		t.Fatalf("the old password failed for another reason: %v", err)
	}
	if err := os.WriteFile(file, []byte(login("second-synthetic-password")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		if _, err := s.CountUsers(ctx); err != nil {
			t.Fatalf("query %d after the rotation: %v", i, err)
		}
	}
	if reads != 1 {
		t.Fatalf("the file was read %d times after the rotation, want once", reads)
	}
}
