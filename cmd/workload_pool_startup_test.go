package cmd

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/server"
	"github.com/Infisical/agent-vault/internal/store/storetest"
)

// A pool binding with no agentID or vaultID starts the broker, which makes
// the pool's agent and vault and grants the agent proxy on it.
func TestStartupProvisionsPoolBindings(t *testing.T) {
	dir, db := t.TempDir(), storetest.Open(t)
	tls := httptest.NewTLSServer(http.NotFoundHandler())
	tls.Close()
	ca := filepath.Join(dir, "ca.crt")
	identity := filepath.Join(dir, "identity.json")
	policy, _ := json.Marshal(map[string]any{"apiServer": "https://kubernetes.example.test", "caFile": ca,
		"reviewerTokenFile": filepath.Join(dir, "token"), "issuer": "https://issuer.example.test", "audience": "workers",
		"bindings": []map[string]any{{"namespace": "workers", "serviceAccount": "example-pool", "serviceAccountUID": "account-uid",
			"pool": "example-pool", "ownerUIDs": []string{"account-uid"}, "maxPodSeconds": 3600,
			"imageDigests": []string{"sha256:" + strings.Repeat("a", 64)}}}})
	if os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tls.Certificate().Raw}), 0o600) != nil ||
		os.WriteFile(identity, policy, 0o600) != nil {
		t.Fatal("writing fixtures")
	}
	t.Setenv("AGENT_VAULT_WORKLOAD_IDENTITY_FILE", identity)
	t.Setenv("AGENT_VAULT_CREDENTIAL_PROXY", "")
	t.Setenv("VAULT_ADDR", "")
	logger := slog.New(slog.DiscardHandler)
	s := server.New("127.0.0.1:0", db, make([]byte, 32), nil, false, "", logger)
	for range 2 { // the second start finds what the first made
		if err := attachServerExtensions(s, "127.0.0.1", 0, 0, make([]byte, 32), db, logger, 0, 0); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()
	agent, err := db.GetAgentByName(ctx, "example-pool")
	if err != nil {
		t.Fatal(err)
	}
	vault, err := db.GetVault(ctx, "example-pool")
	if err != nil {
		t.Fatal(err)
	}
	if role, err := db.GetVaultRole(ctx, agent.ID, vault.ID); err != nil || role != "proxy" {
		t.Fatalf("role %q %v", role, err)
	}
}
