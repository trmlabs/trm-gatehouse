package isolation

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	// isolationDirName lives under ~/.agent-vault so ungraceful exits can
	// be cleaned up by PruneHostCAFiles on the next run.
	isolationDirName = "isolation"
	caPrefix         = "ca-"
	caSuffix         = ".pem"
	caStaleTTL       = 24 * time.Hour
)

// sessionIDRE matches the output of NewSessionID — hex-only, so a
// sessionID value can't contain path separators or "..".
var sessionIDRE = regexp.MustCompile(`^[0-9a-f]+$`)

// WriteHostCAFile writes the MITM CA cert to the isolation dir (mode 0o644 so the container user can read it) and returns the host path.
func WriteHostCAFile(pem []byte, sessionID string) (string, error) {
	if !sessionIDRE.MatchString(sessionID) {
		return "", fmt.Errorf("WriteHostCAFile: sessionID must be hex, got %q", sessionID)
	}
	dir, err := hostIsolationDir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create isolation dir: %w", err)
	}
	path := filepath.Join(dir, caPrefix+sessionID+caSuffix)
	if err := os.WriteFile(path, pem, 0o600); err != nil {
		return "", fmt.Errorf("write CA file: %w", err)
	}
	// Chmod to 0o644 so the container can read its bind mount; the 0o700 parent dir keeps host exposure unchanged.
	if err := os.Chmod(path, 0o644); err != nil { // #nosec G302 -- container user (UID != host) must read bind-mounted CA; parent dir is 0o700
		return "", fmt.Errorf("chmod CA file: %w", err)
	}
	return path, nil
}

// PruneHostCAFiles removes stale ca-*.pem files; best-effort, errors ignored.
func PruneHostCAFiles() {
	dir, err := hostIsolationDir()
	if err != nil {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-caStaleTTL)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, caPrefix) || !strings.HasSuffix(name, caSuffix) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().After(cutoff) {
			continue
		}
		_ = os.Remove(filepath.Join(dir, name))
	}
}

func hostIsolationDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".agent-vault", isolationDirName), nil
}
