// Package storetest gives tests a migrated SQLite store without running every migration per test.
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
	// Closing the last connection checkpoints the WAL, so the file alone holds the schema.
	if err := s.Close(); err != nil {
		return nil, err
	}
	if _, err := os.Stat(path + "-wal"); !os.IsNotExist(err) {
		return nil, fmt.Errorf("template write-ahead log was not checkpointed: %v", err)
	}
	return os.ReadFile(path)
})

// Seed copies one per-binary migrated database to path, which must not exist, so store.Open finds nothing pending.
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

// Open seeds a migrated store in a temporary directory and closes it when the test ends.
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
