package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// maxDatabaseURLFile bounds DATABASE_URL_FILE; a connection URL is far shorter.
const maxDatabaseURLFile = 4096

// databaseURL returns the shared store's URL from DATABASE_URL or the file DATABASE_URL_FILE names;
// setting both is refused. The value is never logged. An empty result means local SQLite.
func databaseURL() (string, error) {
	inline, path := os.Getenv("DATABASE_URL"), os.Getenv("DATABASE_URL_FILE")
	switch {
	case path == "":
		return inline, nil
	case inline != "":
		return "", fmt.Errorf("set DATABASE_URL or DATABASE_URL_FILE, not both")
	}
	info, err := os.Stat(path) //nolint:gosec // G703: the operator names this file; reading it is the feature
	if err != nil {
		return "", fmt.Errorf("DATABASE_URL_FILE: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("DATABASE_URL_FILE must name a regular file")
	}
	if info.Size() > maxDatabaseURLFile {
		return "", fmt.Errorf("DATABASE_URL_FILE is larger than %d bytes", maxDatabaseURLFile)
	}
	data, err := os.ReadFile(path) //nolint:gosec // G703: the operator names this file; reading it is the feature
	if err != nil {
		return "", fmt.Errorf("DATABASE_URL_FILE: cannot read the file")
	}
	url := strings.TrimSpace(string(data))
	if url == "" || len(data) > maxDatabaseURLFile {
		return "", fmt.Errorf("DATABASE_URL_FILE is empty or too large")
	}
	return url, nil
}

// afterURLStamp is a test hook run between the baseline stamp and the read.
var afterURLStamp = func() {}

// databaseURLWithChange stamps the file before reading it, so a rotation in between shows as a change instead of becoming the baseline.
func databaseURLWithChange() (string, func() bool, error) {
	changed := databaseURLChanged()
	afterURLStamp()
	url, err := databaseURL()
	return url, changed, err
}

// databaseURLReload re-reads the file after a refused login so a rotated password needs no restart.
func databaseURLReload() func() (string, error) {
	if os.Getenv("DATABASE_URL_FILE") == "" {
		return nil
	}
	return databaseURL
}

// databaseURLChanged reports, per call, whether the URL file changed since the last call. It stats the resolved target, because a Secret mount swaps a symlink.
func databaseURLChanged() func() bool {
	path := os.Getenv("DATABASE_URL_FILE")
	if path == "" {
		return nil
	}
	var mu sync.Mutex
	last := urlFileStamp(path)
	return func() bool {
		now := urlFileStamp(path)
		mu.Lock()
		defer mu.Unlock()
		if now == last {
			return false
		}
		last = now
		return true
	}
}

type fileStamp struct {
	target  string
	size    int64
	modTime time.Time
}

// urlFileStamp is the zero value when the file cannot be read, so a missing file reads as a change once it returns.
func urlFileStamp(path string) fileStamp {
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fileStamp{}
	}
	info, err := os.Stat(target) //nolint:gosec // G703: the operator names this file; reading it is the feature
	if err != nil {
		return fileStamp{}
	}
	return fileStamp{target, info.Size(), info.ModTime()}
}

// sharedStoreConfigured reports whether either variable names a shared store, without reading the file.
func sharedStoreConfigured() bool {
	return os.Getenv("DATABASE_URL") != "" || os.Getenv("DATABASE_URL_FILE") != ""
}
