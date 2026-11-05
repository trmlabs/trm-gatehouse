package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// keychainItemName is the macOS Keychain service name Claude Code stores its OAuth credential under.
const keychainItemName = "Claude Code-credentials"

// populateClaudeCredentialsFromKeychain copies the macOS Keychain credential to ~/.claude/.credentials.json without overwriting an existing, possibly newer file.
// Best-effort: failures are swallowed so the container still starts.
func populateClaudeCredentialsFromKeychain(hostAgentDir string) {
	if runtime.GOOS != "darwin" {
		return
	}
	credPath := filepath.Join(hostAgentDir, ".credentials.json")
	if _, err := os.Stat(credPath); err == nil {
		return
	}
	out, err := exec.Command("security", "find-generic-password", "-s", keychainItemName, "-w").Output()
	if err != nil {
		return
	}
	token := strings.TrimSpace(string(out))
	if token == "" {
		return
	}
	_ = os.WriteFile(credPath, []byte(token), 0o600)
}
