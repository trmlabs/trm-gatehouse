//go:build realpg

package store

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// rotatingLogin is a throwaway role and database whose password the test rotates, and the URL file a mounted Secret would hold.
type rotatingLogin struct {
	name  string
	dsn   string
	file  string
	admin *SQLStore
	reads atomic.Int32
}

func newRotatingLogin(t *testing.T) *rotatingLogin {
	t.Helper()
	dsn := os.Getenv("AV_TEST_STORE_PG_URL")
	if dsn == "" {
		t.Skip("set AV_TEST_STORE_PG_URL")
	}
	admin, err := openPostgres(dsn)
	if err != nil {
		t.Fatal(err)
	}
	r := &rotatingLogin{name: fmt.Sprintf("rotate_%d", time.Now().UnixNano()), dsn: dsn, file: filepath.Join(t.TempDir(), "database-url"), admin: admin}
	t.Cleanup(func() {
		_, _ = admin.db.Exec("DROP DATABASE " + r.name + " WITH (FORCE)") // #nosec G202 -- generated name
		_, _ = admin.db.Exec("DROP ROLE " + r.name)                       // #nosec G202 -- generated name
		_ = admin.Close()
	})
	r.exec(t, "CREATE ROLE "+r.name+" LOGIN PASSWORD 'first-synthetic-password'")
	r.exec(t, "CREATE DATABASE "+r.name+" OWNER "+r.name)
	r.write(t, "first-synthetic-password")
	return r
}

func (r *rotatingLogin) exec(t *testing.T, statement string) {
	t.Helper()
	if _, err := r.admin.db.ExecContext(context.Background(), statement); err != nil {
		t.Fatal(err)
	}
}

func (r *rotatingLogin) login(password string) string {
	u, _ := url.Parse(r.dsn)
	u.User = url.UserPassword(r.name, password)
	u.Path = "/" + r.name
	return u.String()
}

func (r *rotatingLogin) write(t *testing.T, password string) {
	t.Helper()
	if err := os.WriteFile(r.file, []byte(r.login(password)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (r *rotatingLogin) reload() (string, error) {
	r.reads.Add(1)
	data, err := os.ReadFile(r.file)
	return strings.TrimSpace(string(data)), err
}

// rotate changes the password in the database only, as a static role rotation does before the mounted file catches up.
func (r *rotatingLogin) rotate(t *testing.T) {
	t.Helper()
	r.exec(t, "ALTER ROLE "+r.name+" PASSWORD 'second-synthetic-password'")
	if old, err := openPostgres(r.login("first-synthetic-password")); err == nil {
		_ = old.Close()
		t.Fatal("the old password still logs in")
	} else if !loginRefused(err) {
		t.Fatalf("the old password failed for another reason: %v", err)
	}
}

func (r *rotatingLogin) open(t *testing.T) *SQLStore {
	t.Helper()
	initial, _ := r.reload()
	r.reads.Store(0)
	s, err := openPostgresReloading(initial, r.reload, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestRealPostgres_StoreRereadsRotatedLogin(t *testing.T) {
	ctx := context.Background()
	r := newRotatingLogin(t)
	s := r.open(t)
	// Every query takes a new connection, as one does after the pool recycles.
	s.db.SetMaxIdleConns(0)
	if _, err := s.CountUsers(ctx); err != nil {
		t.Fatal(err)
	}

	r.rotate(t)
	r.write(t, "second-synthetic-password")
	for i := range 3 {
		if _, err := s.CountUsers(ctx); err != nil {
			t.Fatalf("query %d after the rotation: %v", i, err)
		}
	}
	if n := r.reads.Load(); n != 1 {
		t.Fatalf("the file was read %d times after the rotation, want once", n)
	}
}

// While the file still holds the revoked password, an open connection keeps working and a new one waits for the file instead of failing.
func TestRealPostgres_StoreWaitsForALaggingURLFile(t *testing.T) {
	ctx := context.Background()
	r := newRotatingLogin(t)
	s := r.open(t)
	open, err := s.db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer open.Close()
	// Every other query takes a new connection, as one does after the pool recycles.
	s.db.SetMaxIdleConns(0)

	r.rotate(t)
	if _, err := open.ExecContext(ctx, "SELECT 1"); err != nil {
		t.Fatalf("an open connection stopped working at the rotation: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := s.CountUsers(ctx)
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("a new connection did not wait for the file: %v", err)
	case <-time.After(3 * rotationPoll):
	}
	r.write(t, "second-synthetic-password")
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("query after the file caught up: %v", err)
		}
	case <-time.After(time.Minute):
		t.Fatal("the query did not finish after the file caught up")
	}
}

// A wrong password at start fails the start at once; the wait for a rotated URL applies only once the store is running.
func TestRealPostgres_StartFailsAtOnceOnAWrongPassword(t *testing.T) {
	r := newRotatingLogin(t)
	r.write(t, "wrong-synthetic-password")
	initial, _ := r.reload()
	start := time.Now()
	s, err := openPostgresReloading(initial, r.reload, nil)
	if err == nil {
		_ = s.Close()
		t.Fatal("a wrong password started the store")
	}
	if took := time.Since(start); took > 30*time.Second {
		t.Fatalf("the start took %v to fail", took)
	}
}
