package session

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveAndLoad(t *testing.T) {
	// Use a temp dir to avoid touching the real ~/.agent-vault
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	t.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", origHome)

	sess := &ClientSession{
		Token:   "test-token-123",
		Address: "http://127.0.0.1:9090",
	}

	if err := Save(sess); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Verify file exists with correct permissions
	path := filepath.Join(tmpDir, ".agent-vault", "session.json")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("session file not found: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("expected permissions 0600, got %o", perm)
	}

	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded == nil {
		t.Fatal("expected non-nil session")
	}
	if loaded.Token != sess.Token {
		t.Fatalf("expected token %q, got %q", sess.Token, loaded.Token)
	}
	if loaded.Address != sess.Address {
		t.Fatalf("expected address %q, got %q", sess.Address, loaded.Address)
	}
}

func TestLoadNonExistent(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded != nil {
		t.Fatalf("expected nil session, got %+v", loaded)
	}
}

func TestClear(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	sess := &ClientSession{Token: "to-delete", Address: "http://localhost:14321"}
	if err := Save(sess); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if err := Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}

	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load after Clear: %v", err)
	}
	if loaded != nil {
		t.Fatal("expected nil session after Clear")
	}
}

func TestClearNonExistent(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	// Should not error when file doesn't exist
	if err := Clear(); err != nil {
		t.Fatalf("Clear on non-existent file: %v", err)
	}
}
