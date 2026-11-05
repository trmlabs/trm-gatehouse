package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The store URL can come from a file; the value never appears in an error.
func TestDatabaseURLFromFile(t *testing.T) {
	dir := t.TempDir()
	// Built in pieces so the synthetic URL does not read as a credential.
	secret := "postgres://broker:" + "synthetic-store-password" + "@db.internal:5432/brokerstore"
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	good := write("url", secret+"\n")

	t.Setenv("DATABASE_URL", "")
	t.Setenv("DATABASE_URL_FILE", good)
	if url, err := databaseURL(); err != nil || url != secret {
		t.Fatalf("from file: %q %v", url, err)
	}
	if !sharedStoreConfigured() {
		t.Fatal("a store URL file does not count as a shared store")
	}

	link := filepath.Join(dir, "link")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DATABASE_URL_FILE", link) // a Kubernetes Secret mount is a symlink to a regular file
	if url, err := databaseURL(); err != nil || url != secret {
		t.Fatalf("through a symlink: %q %v", url, err)
	}

	for name, setup := range map[string]func(){
		"both set":  func() { t.Setenv("DATABASE_URL", secret); t.Setenv("DATABASE_URL_FILE", good) },
		"directory": func() { t.Setenv("DATABASE_URL", ""); t.Setenv("DATABASE_URL_FILE", dir) },
		"empty":     func() { t.Setenv("DATABASE_URL", ""); t.Setenv("DATABASE_URL_FILE", write("empty", " \n")) },
		"too large": func() {
			t.Setenv("DATABASE_URL", "")
			t.Setenv("DATABASE_URL_FILE", write("big", strings.Repeat("x", 5000)))
		},
		"missing": func() { t.Setenv("DATABASE_URL", ""); t.Setenv("DATABASE_URL_FILE", filepath.Join(dir, "absent")) },
	} {
		setup()
		url, err := databaseURL()
		if err == nil || url != "" {
			t.Errorf("%s: accepted (%v)", name, err)
			continue
		}
		if strings.Contains(err.Error(), "synthetic-store-password") {
			t.Errorf("%s: the error carries the URL", name)
		}
	}

	t.Setenv("DATABASE_URL_FILE", "")
	t.Setenv("DATABASE_URL", secret)
	if url, err := databaseURL(); err != nil || url != secret {
		t.Fatalf("plain DATABASE_URL: %q %v", url, err)
	}
	t.Setenv("DATABASE_URL", "")
	if url, err := databaseURL(); err != nil || url != "" || sharedStoreConfigured() {
		t.Fatalf("no store set: %q %v", url, err)
	}
}

// A Secret volume rotates by repointing a symlink; the change check must see that even when size and mtime match.
func TestDatabaseURLChangedSeesASymlinkSwap(t *testing.T) {
	dir := t.TempDir()
	stamp := time.Unix(1_700_000_000, 0)
	versions := map[string]string{"v1": "postgres://broker:" + "synthetic-one" + "@db.internal/s", "v2": "postgres://broker:" + "synthetic-two" + "@db.internal/s"}
	for name, body := range versions {
		sub := filepath.Join(dir, name)
		if err := os.Mkdir(sub, 0o700); err != nil {
			t.Fatal(err)
		}
		file := filepath.Join(sub, "url")
		if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(file, stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
	point := func(version string) {
		tmp := filepath.Join(dir, "..data_tmp")
		_ = os.Remove(tmp)
		if err := os.Symlink(version, tmp); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmp, filepath.Join(dir, "..data")); err != nil {
			t.Fatal(err)
		}
	}
	point("v1")
	if err := os.Symlink(filepath.Join("..data", "url"), filepath.Join(dir, "url")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DATABASE_URL", "")
	t.Setenv("DATABASE_URL_FILE", filepath.Join(dir, "url"))

	changed := databaseURLChanged()
	if changed() {
		t.Fatal("reported a change before any")
	}
	point("v2")
	if !changed() {
		t.Fatal("missed the symlink swap")
	}
	if changed() {
		t.Fatal("reported the same swap twice")
	}
	if url, err := databaseURL(); err != nil || !strings.Contains(url, "synthetic-two") {
		t.Fatalf("the swapped file was not read: %v", err)
	}

	t.Setenv("DATABASE_URL_FILE", "")
	if databaseURLChanged() != nil {
		t.Fatal("a check with no file")
	}
}

// A rotation between the baseline stamp and the read is reported as a change, not swallowed into the baseline.
func TestDatabaseURLWithChangeSeesARotationDuringTheRead(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "url")
	write := func(v string) {
		t.Helper()
		if err := os.WriteFile(file, []byte("postgres://u:"+v+"@h/db\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("synthetic-one")
	t.Setenv("DATABASE_URL", "")
	t.Setenv("DATABASE_URL_FILE", file)
	afterURLStamp = func() { write("synthetic-two-longer") }
	t.Cleanup(func() { afterURLStamp = func() {} })

	url, changed, err := databaseURLWithChange()
	if err != nil || !strings.Contains(url, "synthetic-two") {
		t.Fatalf("read %v", err)
	}
	if !changed() {
		t.Fatal("a rotation between the stamp and the read became the baseline")
	}
}
