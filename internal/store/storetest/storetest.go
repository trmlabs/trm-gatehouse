// Package storetest gives tests a fully migrated SQLite store without paying
// for every migration in every test.
//
// Running the migrations takes over a second per store under -race, and most
// broker tests open a fresh store. Seed builds one migrated database per test
// binary and copies it into place, so store.Open on the copy finds nothing
// pending and the tests that open stores keep exercising store.Open itself.
package storetest

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/Infisical/agent-vault/internal/store"
)

var template = sync.OnceValues(func() ([]byte, error) {
	dir, err := os.MkdirTemp("", "storetest")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	path := filepath.Join(dir, "template.db")
	s, err := store.Open(path)
	if err != nil {
		return nil, err
	}
	// Closing the last connection checkpoints the write-ahead log into the
	// main file, so the file alone holds the whole schema.
	if err := s.Close(); err != nil {
		return nil, err
	}
	if _, err := os.Stat(path + "-wal"); !os.IsNotExist(err) {
		return nil, fmt.Errorf("template write-ahead log was not checkpointed: %v", err)
	}
	return os.ReadFile(path)
})

// Seed writes a fully migrated, empty SQLite database at path. Open it with
// store.Open as usual. path must not exist yet.
func Seed(t testing.TB, path string) {
	t.Helper()
	data, err := template()
	if err != nil {
		t.Fatalf("building migrated store template: %v", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatalf("seeding store: %v", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		t.Fatalf("seeding store: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("seeding store: %v", err)
	}
}

// Open seeds a migrated store in a fresh temporary directory, opens it and
// closes it when the test ends.
func Open(t testing.TB) *store.SQLStore {
	t.Helper()
	path := filepath.Join(t.TempDir(), "store.db")
	Seed(t, path)
	s, err := store.Open(path)
	if err != nil {
		t.Fatalf("opening seeded store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}
