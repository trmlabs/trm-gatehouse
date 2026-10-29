package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/auditchain"
	"github.com/Infisical/agent-vault/internal/hashicorp"
	"github.com/Infisical/agent-vault/internal/server"
	"github.com/Infisical/agent-vault/internal/store"
)

func shortStartupRetry(t *testing.T, window time.Duration) {
	t.Helper()
	oldWindow, oldBackoff := startupRetry, startupBackoff
	startupRetry, startupBackoff = window, 5*time.Millisecond
	t.Cleanup(func() { startupRetry, startupBackoff = oldWindow, oldBackoff })
}

func TestStartupRetryWindowSetting(t *testing.T) {
	for raw, want := range map[string]time.Duration{"": 120 * time.Second, "0": 0, "45": 45 * time.Second} {
		got, err := startupRetryWindow(func(string) string { return raw })
		if err != nil || got != want {
			t.Errorf("%q: %v %v", raw, got, err)
		}
	}
	for _, raw := range []string{"-1", "soon", "3601"} {
		if _, err := startupRetryWindow(func(string) string { return raw }); err == nil {
			t.Errorf("%q accepted", raw)
		}
	}
}

// A Vault blip at startup: Vault refuses the first logins, answers a later
// one, and the broker attaches its client instead of starting without one.
func TestVaultLoginIsRetriedAtStartup(t *testing.T) {
	shortStartupRetry(t, 5*time.Second)
	var attempts atomic.Int32
	vault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/token/lookup-self" {
			http.NotFound(w, r)
			return
		}
		if attempts.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"errors":["Vault is sealed"]}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":{"id":"synthetic","ttl":0}}`))
	}))
	defer vault.Close()
	t.Setenv("VAULT_ADDR", vault.URL)
	t.Setenv("VAULT_TOKEN", "synthetic-test-token")
	t.Setenv("VAULT_MAX_RETRIES", "0") // count startup attempts, not the client's own retries
	t.Setenv("VAULT_ROLE_ID", "")
	t.Setenv("VAULT_SECRET_ID", "")
	t.Setenv("VAULT_JWT_ROLE", "")
	logger := slog.New(slog.DiscardHandler)
	s := server.New("127.0.0.1:0", nil, make([]byte, 32), nil, false, "", logger)
	attachHashicorpIfConfigured(s, logger)
	if s.HashicorpClient() == nil || attempts.Load() != 3 {
		t.Fatalf("client attached %v after %d attempts, want after 3", s.HashicorpClient() != nil, attempts.Load())
	}
}

// A missing or invalid auth setting is not retried: no Vault answer fixes it.
func TestVaultLoginMisconfigurationIsNotRetried(t *testing.T) {
	shortStartupRetry(t, 5*time.Second)
	t.Setenv("VAULT_ADDR", "http://127.0.0.1:1")
	var attempts atomic.Int32
	old := newHashicorpClient
	t.Cleanup(func() { newHashicorpClient = old })
	newHashicorpClient = func(context.Context, *slog.Logger) (*hashicorp.Client, error) {
		attempts.Add(1)
		return nil, fmt.Errorf("%w: VAULT_JWT_ROLE is malformed", hashicorp.ErrInvalidAuthConfig)
	}
	logger := slog.New(slog.DiscardHandler)
	s := server.New("127.0.0.1:0", nil, make([]byte, 32), nil, false, "", logger)
	started := time.Now()
	attachHashicorpIfConfigured(s, logger)
	if s.HashicorpClient() != nil || attempts.Load() != 1 || time.Since(started) > time.Second {
		t.Fatalf("attempts %d in %s", attempts.Load(), time.Since(started))
	}
}

// The window bounds the retries: past it, the last error is returned.
func TestRetryAtStartupGivesUpAfterTheWindow(t *testing.T) {
	shortStartupRetry(t, 60*time.Millisecond)
	var attempts int
	started := time.Now()
	err := retryAtStartup(slog.New(slog.DiscardHandler), "test step", func() error {
		attempts++
		return errors.New("vault sealed")
	})
	if err == nil || !strings.Contains(err.Error(), "sealed") || attempts < 2 || time.Since(started) > 2*time.Second {
		t.Fatalf("err %v after %d attempts in %s", err, attempts, time.Since(started))
	}
	shortStartupRetry(t, 0)
	attempts = 0
	_ = retryAtStartup(slog.New(slog.DiscardHandler), "test step", func() error { attempts++; return errors.New("x") })
	if attempts != 1 {
		t.Fatalf("a zero window made %d attempts", attempts)
	}
}

// An attempt that ignores its deadline is abandoned, and what it builds late
// is handed to late so it can be closed.
func TestBoundedAttemptClosesLateResults(t *testing.T) {
	release := make(chan struct{})
	closed := make(chan string, 1)
	_, err := boundedAttempt(20*time.Millisecond, func(context.Context) (string, error) {
		<-release
		return "late client", nil
	}, func(v string) { closed <- v })
	if err == nil {
		t.Fatal("a stuck attempt returned success")
	}
	close(release)
	select {
	case v := <-closed:
		if v != "late client" {
			t.Fatal(v)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("late result was not handed back")
	}
}

// The audit key read is retried for the startup window: a blip no longer
// exits with "proxy certificates need the signed audit trail".
func TestAuditTrailStartIsRetried(t *testing.T) {
	shortStartupRetry(t, 80*time.Millisecond)
	vault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"id":"synthetic","ttl":0}}`))
	}))
	defer vault.Close()
	t.Setenv("VAULT_ADDR", vault.URL)
	t.Setenv("VAULT_TOKEN", "synthetic-test-token")
	t.Setenv("VAULT_ROLE_ID", "")
	t.Setenv("VAULT_SECRET_ID", "")
	t.Setenv("VAULT_JWT_ROLE", "")
	t.Setenv("AGENT_VAULT_AUDIT_CHAIN", "true")
	client, err := hashicorp.NewClient(context.Background(), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var attempts atomic.Int32
	old := newAuditChain
	t.Cleanup(func() { newAuditChain = old })
	newAuditChain = func(context.Context, auditchain.Options) (*auditchain.Chain, error) {
		attempts.Add(1)
		return nil, errors.New("audit HMAC key unavailable: vault sealed")
	}
	env := map[string]string{"AGENT_VAULT_AUDIT_REPLICA": "broker-0", "AGENT_VAULT_AUDIT_HMAC_PATH": "audit/hmac", "AGENT_VAULT_AUDIT_TRANSIT_KEY": "audit"}
	_, err = brokerAuditChain(context.Background(), client, st, func(k string) string { return env[k] }, slog.New(slog.DiscardHandler))
	if err == nil || attempts.Load() < 2 {
		t.Fatalf("audit start: err %v after %d attempts, want retries then the error", err, attempts.Load())
	}
	// Missing settings still fail at once, with no attempt.
	attempts.Store(0)
	if _, err = brokerAuditChain(context.Background(), client, st, func(string) string { return "" }, slog.New(slog.DiscardHandler)); err == nil || attempts.Load() != 0 {
		t.Fatalf("missing settings: err %v attempts %d", err, attempts.Load())
	}
}

// A broker restarting while Vault cannot serve the catalog starts from the
// copy its store kept, ready; with no copy it starts empty and not ready,
// instead of exiting.
func TestBrokerCatalogStartsFromTheStoredCopyWhenVaultIsDown(t *testing.T) {
	sharedCatalog.Lock()
	sharedCatalog.source, sharedCatalog.started = nil, false
	sharedCatalog.Unlock()
	t.Cleanup(func() {
		sharedCatalog.Lock()
		sharedCatalog.source, sharedCatalog.started = nil, false
		sharedCatalog.Unlock()
	})
	vault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/token/lookup-self" {
			_, _ = w.Write([]byte(`{"data":{"id":"synthetic","ttl":0}}`))
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"errors":["Vault is sealed"]}`))
	}))
	defer vault.Close()
	t.Setenv("VAULT_ADDR", vault.URL)
	t.Setenv("VAULT_TOKEN", "synthetic-test-token")
	t.Setenv("VAULT_MAX_RETRIES", "0")
	t.Setenv("VAULT_ROLE_ID", "")
	t.Setenv("VAULT_SECRET_ID", "")
	t.Setenv("VAULT_JWT_ROLE", "")
	client, err := hashicorp.NewClient(context.Background(), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "catalog.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	doc := `{"entries":[{"name":"serpapi","host":"serpapi.com","pathPrefixes":["/search"],"methods":["GET"],"header":"X-Api-Key",
		"placeholder":"__vault_SERPAPI_KEY__","key":{"mount":"gatehouse","path":"vendors/serpapi","field":"key"},"pools":["pool-a"]}]}`
	if err := st.SaveBrokerCatalog(context.Background(), "gatehouse/catalog", 9, []byte(doc)); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"AGENT_VAULT_CATALOG_VAULT_PATH": "gatehouse/catalog"}
	checks := map[string]func() bool{}
	ready := func(name string, check func() bool) { checks[name] = check }
	source, err := brokerCatalog(context.Background(), client, st, ready, func(k string) string { return env[k] }, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal("broker exits when Vault is down:", err)
	}
	if !source.Current().HasHost("serpapi.com", 443) || checks["catalog"] == nil || !checks["catalog"]() {
		t.Fatal("the stored catalog is not in force")
	}
	// No stored copy: empty, not ready, still running.
	sharedCatalog.Lock()
	sharedCatalog.source, sharedCatalog.started = nil, false
	sharedCatalog.Unlock()
	env["AGENT_VAULT_CATALOG_VAULT_PATH"] = "gatehouse/never-stored"
	source, err = brokerCatalog(context.Background(), client, st, ready, func(k string) string { return env[k] }, slog.New(slog.DiscardHandler))
	if err != nil || len(source.Current().Entries()) != 0 || checks["catalog"]() {
		t.Fatalf("empty start: err %v entries %d ready %v", err, len(source.Current().Entries()), checks["catalog"]())
	}
}
