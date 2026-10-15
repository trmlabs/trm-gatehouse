package store

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A store copied to the shared store leaves <name>.migrated. Starting on
// SQLite again must refuse, not create a new, empty store beside it.
func TestOpenStoreRefusesAMigratedSQLiteStore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent-vault.db")
	if err := os.WriteFile(path+".migrated", []byte("copied"), 0o600); err != nil {
		t.Fatal(err)
	}
	if db, err := OpenStore(StoreConfig{SQLitePath: path}); !errors.Is(err, ErrSQLiteMovedToSharedStore) {
		if db != nil {
			_ = db.Close()
		}
		t.Fatalf("OpenStore = %v, want ErrSQLiteMovedToSharedStore", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("an empty store was created: stat = %v", err)
	}
}

func TestOpenStoreOpensSQLiteWithoutTheMarker(t *testing.T) {
	db, err := OpenStore(StoreConfig{SQLitePath: filepath.Join(t.TempDir(), "agent-vault.db")})
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
}

// A marker that cannot be checked refuses too.
func TestOpenStoreRefusesWhenTheMarkerCannotBeChecked(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a non-root POSIX user")
	}
	dir := filepath.Join(t.TempDir(), "locked")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) // #nosec G302 -- a test directory, restored so TempDir can remove it
	db, err := OpenStore(StoreConfig{SQLitePath: filepath.Join(dir, "agent-vault.db")})
	if err == nil {
		_ = db.Close()
		t.Fatal("OpenStore opened a store whose marker could not be checked")
	}
	if errors.Is(err, ErrSQLiteMovedToSharedStore) || !strings.Contains(err.Error(), "checking for") {
		t.Fatalf("an unreadable directory did not fail the marker check: %v", err)
	}
}
