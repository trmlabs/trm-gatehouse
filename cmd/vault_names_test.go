package cmd

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/githubapp"
	"github.com/Infisical/agent-vault/internal/hashicorp"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
)

// The broker's own documents default to the gatehouse KV mount;
// AGENT_VAULT_KV_MOUNT moves them, and the GitHub App key fallback follows.
func TestKVMountSetting(t *testing.T) {
	vault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"id":"synthetic","ttl":0}}`))
	}))
	defer vault.Close()
	t.Setenv("VAULT_ADDR", vault.URL)
	t.Setenv("VAULT_TOKEN", "synthetic-test-token")
	t.Setenv("VAULT_ROLE_ID", "")
	t.Setenv("VAULT_SECRET_ID", "")
	t.Setenv("VAULT_JWT_ROLE", "")
	client, err := hashicorp.NewClient(context.Background(), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"AGENT_VAULT_GITHUB_APP_KV_PATH": "github-app"}
	getenv := func(k string) string { return env[k] }
	for value, want := range map[string]string{"": "gatehouse", "agents/kv": "agents/kv"} {
		env[kvMountEnv] = value
		signer, err := githubAppSigner(client, getenv)
		if err != nil {
			t.Fatalf("%q: %v", value, err)
		}
		if kv, ok := signer.(githubapp.KVSigner); !ok || kv.Mount != want || kv.Path != "github-app" {
			t.Errorf("%q: signer %+v, want KV mount %s", value, signer, want)
		}
	}
	env[kvMountEnv] = "Agents KV"
	if _, err := githubAppSigner(client, getenv); err == nil || !strings.Contains(err.Error(), kvMountEnv) {
		t.Errorf("invalid mount: %v", err)
	}
}

// broker-catalog validate applies the same naming settings as the broker,
// from its flags.
func TestBrokerCatalogValidateNamingFlags(t *testing.T) {
	t.Cleanup(func() {
		httpcatalog.Environment.Store("")
		_ = httpcatalog.SetKeyPrefix("")
		_ = httpcatalog.SetRolePattern("")
		for _, name := range []string{"environment", "key-prefix", "role-pattern"} {
			_ = brokerCatalogValidateCmd.Flags().Set(name, "")
		}
	})
	flags := brokerCatalogValidateCmd.Flags()
	for name, value := range map[string]string{"environment": "staging", "key-prefix": "agents/keys", "role-pattern": `{environment}-[a-z]+`} {
		if err := flags.Set(name, value); err != nil {
			t.Fatal(err)
		}
	}
	if err := catalogSettings(validateSettings(brokerCatalogValidateCmd)); err != nil {
		t.Fatal(err)
	}
	doc := []byte(`{"entries":[{"name":"app","kind":"postgres","host":"p.abc.db.postgresbridge.com","pools":["pool-a"],"postgres":{"database":"app","mount":"database","role":"staging-app-readonly"}},
		{"name":"serpapi","host":"serpapi.com","pathPrefixes":["/search"],"methods":["GET"],"header":"X-Api-Key","placeholder":"__vault_SERPAPI_KEY__","key":{"mount":"gatehouse","path":"agents/keys/serpapi","field":"key"},"pools":["pool-a"]}]}`)
	if err := validateBrokerCatalog(doc, nil, false, &strings.Builder{}); err != nil {
		t.Fatalf("catalog under the flags' rules: %v", err)
	}
	if err := flags.Set("role-pattern", "staging-[a-z]+"); err != nil {
		t.Fatal(err)
	}
	if err := catalogSettings(validateSettings(brokerCatalogValidateCmd)); err == nil || !strings.Contains(err.Error(), "{environment}") {
		t.Fatalf("a role pattern without {environment}: %v", err)
	}
}

// validate applies the broker's size limit for an Automation's settings from
// its flag, and refuses a limit out of bounds.
func TestBrokerCatalogValidateSettingsLimitFlag(t *testing.T) {
	t.Cleanup(func() {
		_ = httpcatalog.SetSettingsMaxBytes("")
		_ = brokerCatalogValidateCmd.Flags().Set("settings-max-bytes", "")
	})
	flags := brokerCatalogValidateCmd.Flags()
	if err := flags.Set("settings-max-bytes", "2048"); err != nil {
		t.Fatal(err)
	}
	if err := catalogSettings(validateSettings(brokerCatalogValidateCmd)); err != nil || httpcatalog.SettingsMaxBytes() != 2048 {
		t.Fatalf("%v, limit %d", err, httpcatalog.SettingsMaxBytes())
	}
	if err := flags.Set("settings-max-bytes", "64KiB"); err != nil {
		t.Fatal(err)
	}
	if err := catalogSettings(validateSettings(brokerCatalogValidateCmd)); err == nil || !strings.Contains(err.Error(), httpcatalog.SettingsMaxBytesEnv) {
		t.Fatalf("an unparseable limit: %v", err)
	}
}
