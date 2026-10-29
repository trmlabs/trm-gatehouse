package cmd

import (
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/pgproxy"
	"github.com/Infisical/agent-vault/internal/server"
)

// A database broker that was asked for but has no Vault login fails startup,
// so the replica never reports ready without a way to mint credentials.
func TestPostgresBrokerWithoutVaultFailsStartup(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	s := server.New("127.0.0.1:0", nil, make([]byte, 32), nil, false, "", logger)
	t.Setenv("AGENT_VAULT_DB_SERVICES", "")
	t.Setenv("AGENT_VAULT_DB_SERVICES_FILE", "")
	t.Setenv("AGENT_VAULT_DB_BROKER", "")
	if err := attachPostgresBrokerIfEnabled(s, "127.0.0.1", 15432, logger); err != nil {
		t.Fatalf("broker not asked for: %v", err)
	}
	t.Setenv("AGENT_VAULT_DB_BROKER", "1")
	err := attachPostgresBrokerIfEnabled(s, "127.0.0.1", 15432, logger)
	if err == nil || !strings.Contains(err.Error(), "requires a working HashiCorp Vault client") {
		t.Fatalf("broker without Vault: %v", err)
	}
}

// Admission settings are parsed strictly: a malformed value fails startup
// instead of being ignored.
func TestAdmissionSettings(t *testing.T) {
	env := func(values map[string]string) func(string) string { return func(k string) string { return values[k] } }
	var opts pgproxy.Options
	if err := applyAdmissionSettings(&opts, env(map[string]string{"AGENT_VAULT_DB_ADMISSION_CONCURRENCY": "512",
		"AGENT_VAULT_DB_ADMISSION_TIMEOUT": "3s", "AGENT_VAULT_DB_LEDGER_TIMEOUT": "6s"})); err != nil {
		t.Fatal(err)
	}
	if opts.AdmissionConcurrency != 512 || opts.AdmissionTimeout != 3*time.Second || opts.LedgerTimeout != 6*time.Second {
		t.Fatalf("settings %+v", opts)
	}
	for name, value := range map[string]string{
		"AGENT_VAULT_DB_ADMISSION_CONCURRENCY": "lots", "AGENT_VAULT_DB_ADMISSION_TIMEOUT": "2", "AGENT_VAULT_DB_LEDGER_TIMEOUT": "-1s",
	} {
		if err := applyAdmissionSettings(&pgproxy.Options{}, env(map[string]string{name: value})); err == nil {
			t.Errorf("%s=%s accepted", name, value)
		}
	}
	if err := applyAdmissionSettings(&pgproxy.Options{}, env(map[string]string{"AGENT_VAULT_DB_ADMISSION_CONCURRENCY": "0"})); err == nil {
		t.Error("a concurrency of 0 accepted")
	}
}

// The broker's own PostgreSQL TLS listener needs a port and both files, keeps
// the plain listener on loopback, and cannot be combined with the PROXY
// header it replaces.
func TestPostgresTLSSettings(t *testing.T) {
	env := func(values map[string]string) func(string) string { return func(k string) string { return values[k] } }
	files := map[string]string{"AGENT_VAULT_DB_TLS_PORT": "15443", "AGENT_VAULT_DB_TLS_CERT_FILE": "/etc/gatehouse/tls/tls.crt",
		"AGENT_VAULT_DB_TLS_KEY_FILE": "/etc/gatehouse/tls/tls.key"}
	with := func(extra map[string]string) map[string]string {
		out := map[string]string{}
		for k, v := range files {
			out[k] = v
		}
		for k, v := range extra {
			if v == "" {
				delete(out, k)
			} else {
				out[k] = v
			}
		}
		return out
	}
	addr, certFile, keyFile, err := postgresTLSSettings(env(files), "127.0.0.1")
	if err != nil || addr != "0.0.0.0:15443" || certFile != files["AGENT_VAULT_DB_TLS_CERT_FILE"] || keyFile != files["AGENT_VAULT_DB_TLS_KEY_FILE"] {
		t.Fatalf("settings %q %q %q %v", addr, certFile, keyFile, err)
	}
	if addr, _, _, err := postgresTLSSettings(env(nil), "127.0.0.1"); addr != "" || err != nil {
		t.Fatalf("unset: %q %v", addr, err)
	}
	for name, values := range map[string]map[string]string{
		"files without a port":   with(map[string]string{"AGENT_VAULT_DB_TLS_PORT": ""}),
		"a port without a key":   with(map[string]string{"AGENT_VAULT_DB_TLS_KEY_FILE": ""}),
		"a port without a cert":  with(map[string]string{"AGENT_VAULT_DB_TLS_CERT_FILE": ""}),
		"port 0":                 with(map[string]string{"AGENT_VAULT_DB_TLS_PORT": "0"}),
		"port past 65535":        with(map[string]string{"AGENT_VAULT_DB_TLS_PORT": "65536"}),
		"a padded port":          with(map[string]string{"AGENT_VAULT_DB_TLS_PORT": "015443"}),
		"the PROXY header":       with(map[string]string{"AGENT_VAULT_DB_PROXY_PROTOCOL": "true"}),
		"the cross-cluster port": with(map[string]string{"AGENT_VAULT_CROSS_CLUSTER_PORT": "16443"}),
	} {
		if _, _, _, err := postgresTLSSettings(env(values), "127.0.0.1"); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, _, _, err := postgresTLSSettings(env(files), "0.0.0.0"); err == nil {
		t.Error("a non-loopback plain listener accepted")
	}
}
