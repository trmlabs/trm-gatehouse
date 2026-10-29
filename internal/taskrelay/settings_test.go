package taskrelay

import (
	"bytes"
	"context"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/httpcatalog"
)

func settingsConfig() FixedConfig {
	up := UpstreamConfig{Address: "gatehouse.gatehouse.svc:15443", ServerName: "gatehouse.gatehouse.svc", CAFile: "/ca", ProofFile: "/proof", Audience: "gatehouse",
		SessionSocketDir: "/var/run/cursor-identity", SessionAudience: "gatehouse"}
	return FixedConfig{TaskID: "pool-worker", Deadline: time.Now().Add(time.Hour), AuditFile: "/data/audit.jsonl", Self: true,
		Connect:            &ConnectConfig{Listen: "127.0.0.1:14443", Upstream: up, AllowedTargets: []string{"api.example.com:443"}},
		AutomationSettings: &AutomationSettingsConfig{File: "/var/run/gatehouse-settings/settings.sh"}}
}

// Settings are a Cursor worker's sidecar's alone: a sidecar relaying a run's
// token, writing to an absolute file in a directory of its own, within
// bounded waits.
func TestSettingsConfig(t *testing.T) {
	if err := settingsConfig().Validate(time.Now()); err != nil {
		t.Fatalf("valid settings config refused: %v", err)
	}
	for name, mutate := range map[string]func(*FixedConfig){
		"no run token": func(c *FixedConfig) { c.Connect.Upstream.SessionSocketDir, c.Connect.Upstream.SessionAudience = "", "" },
		"a Claude session": func(c *FixedConfig) {
			c.Connect.Upstream.SessionSocketDir, c.Connect.Upstream.SessionAudience, c.Connect.Upstream.SessionFile = "", "", "/token"
		},
		"no connect":         func(c *FixedConfig) { c.Connect = nil },
		"relative file":      func(c *FixedConfig) { c.AutomationSettings.File = "settings.sh" },
		"unclean file":       func(c *FixedConfig) { c.AutomationSettings.File = "/var/run/../settings.sh" },
		"file at the root":   func(c *FixedConfig) { c.AutomationSettings.File = "/settings.sh" },
		"wait over an hour":  func(c *FixedConfig) { c.AutomationSettings.WaitSeconds = 3601 },
		"negative wait":      func(c *FixedConfig) { c.AutomationSettings.WaitSeconds = -1 },
		"refresh too often":  func(c *FixedConfig) { c.AutomationSettings.RefreshSeconds = 5 },
		"refresh over a day": func(c *FixedConfig) { c.AutomationSettings.RefreshSeconds = 86401 },
		"not a sidecar":      func(c *FixedConfig) { c.Self = false },
	} {
		c := settingsConfig()
		connect, settings := *c.Connect, *c.AutomationSettings
		c.Connect, c.AutomationSettings = &connect, &settings
		mutate(&c)
		if c.Validate(time.Now()) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Each value reaches a shell exactly as the catalog holds it, whatever
// quotes or shell characters it has, and the notice sets nothing and says
// why on stderr.
func TestSettingsScriptIsLiteralInBash(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	settings := map[string]string{"API_BASE": "https://api.example.com/v1", "QUOTED": `it's "x" $HOME $(id) ` + "`id`" + ` \ ;`, "EMPTY": ""}
	file := filepath.Join(t.TempDir(), "settings.sh")
	if err := writeSettingsFile(file, settingsScript(settings)); err != nil {
		t.Fatal(err)
	}
	for name, want := range settings {
		out, err := exec.Command(bash, "-c", `. "$1"; printf '%s' "${!2}"`, "bash", file, name).Output()
		if err != nil || string(out) != want {
			t.Errorf("%s: %q, %v", name, out, err)
		}
	}
	if err := writeSettingsFile(file, noticeScript("refused by the broker")); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bash, "-c", `. "$1"; printf '%s' "${API_BASE-unset}"`, "bash", file)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil || string(out) != "unset" || !strings.Contains(stderr.String(), "unavailable (refused by the broker)") {
		t.Fatalf("notice: %q %q %v", out, stderr.String(), err)
	}
}

// A reader never sees part of a file: while one file replaces another again
// and again, every read is one of the two whole, and no temporary file is
// left behind.
func TestSettingsFileIsReplacedWhole(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "settings.sh")
	a := settingsScript(map[string]string{"A": strings.Repeat("a", 200<<10)})
	b := noticeScript("no answer from the broker yet")
	if err := writeSettingsFile(file, a); err != nil {
		t.Fatal(err)
	}
	var stop atomic.Bool
	var torn atomic.Int32
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !stop.Load() {
			got, err := os.ReadFile(file)
			if err != nil || (!bytes.Equal(got, a) && !bytes.Equal(got, b)) {
				torn.Add(1)
			}
		}
	}()
	for i := range 200 {
		content := a
		if i%2 == 0 {
			content = b
		}
		if err := writeSettingsFile(file, content); err != nil {
			t.Fatal(err)
		}
	}
	stop.Store(true)
	wg.Wait()
	if torn.Load() != 0 {
		t.Fatalf("%d reads saw a partial or missing file", torn.Load())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("left behind: %v", entries)
	}
	if info, _ := os.Stat(file); info.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v", info.Mode())
	}
}

// fakeRun stands in for the run's token and the broker's answers.
type fakeRun struct {
	mu     sync.Mutex
	token  string
	status int
	answer map[string]string
	asked  int
	tokens []string
}

func (f *fakeRun) set(token string, status int, answer map[string]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.token, f.status, f.answer = token, status, answer
}

func (f *fakeRun) writer(file string, wait time.Duration) *settingsWriter {
	return &settingsWriter{config: AutomationSettingsConfig{File: file, WaitSeconds: int(wait / time.Second), RefreshSeconds: 30},
		log: slog.New(slog.DiscardHandler), tick: 10 * time.Millisecond,
		token: func() string { f.mu.Lock(); defer f.mu.Unlock(); return f.token },
		fetch: func(_ context.Context, token string) (int, map[string]string, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.asked++
			f.tokens = append(f.tokens, token)
			return f.status, f.answer, nil
		}}
}

func waitForFile(t *testing.T, file string, want func(string) bool, within time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		b, _ := os.ReadFile(file)
		if want(string(b)) {
			return string(b)
		}
		if time.Now().After(deadline) {
			t.Fatalf("file never became what was wanted; last %q", b)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Before the claim nothing is asked or written; once the run's token exists
// the broker's answer is written, with the run's own token sent.
func TestSettingsWrittenOnceTheRunHasAToken(t *testing.T) {
	file := filepath.Join(t.TempDir(), "settings.sh")
	run := &fakeRun{}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); run.writer(file, time.Hour).run(ctx) }()
	time.Sleep(100 * time.Millisecond)
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatalf("written before the claim: %v", err)
	}
	run.mu.Lock()
	asked := run.asked
	run.mu.Unlock()
	if asked != 0 {
		t.Fatalf("asked the broker %d times before the claim", asked)
	}
	run.set("run-token", http.StatusOK, map[string]string{"API_BASE": "https://api.example.com/v1"})
	waitForFile(t, file, func(s string) bool { return strings.Contains(s, "export API_BASE='https://api.example.com/v1'") }, 2*time.Second)
	cancel()
	<-done
	if run.tokens[0] != "run-token" {
		t.Fatalf("sent %q", run.tokens[0])
	}
}

// Without an answer by the wait, the file is still written, so a shell never
// waits longer: it says the settings are unavailable. A later answer replaces
// it. A refusal is written at once, and asked again only at the refresh.
func TestSettingsNoticeAtTheWaitThenAnswer(t *testing.T) {
	file := filepath.Join(t.TempDir(), "settings.sh")
	run := &fakeRun{}
	run.set("run-token", http.StatusServiceUnavailable, nil)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	w := run.writer(file, time.Second)
	started := time.Now()
	go func() { defer close(done); w.run(ctx) }()
	waitForFile(t, file, func(s string) bool { return strings.Contains(s, "no answer from the broker yet") }, 3*time.Second)
	if waited := time.Since(started); waited < 900*time.Millisecond || waited > 2*time.Second {
		t.Fatalf("notice after %v, want about the 1 s wait", waited)
	}
	run.set("run-token", http.StatusOK, map[string]string{"MODE": "staging"})
	waitForFile(t, file, func(s string) bool { return strings.Contains(s, "export MODE='staging'") }, 3*time.Second)
	cancel()
	<-done
	// A refusal on a fresh sidecar is written at once.
	refused := &fakeRun{}
	refused.set("run-token", http.StatusForbidden, nil)
	ctx, cancel = context.WithCancel(t.Context())
	defer cancel()
	done = make(chan struct{})
	go func() { defer close(done); refused.writer(file, time.Hour).run(ctx) }()
	waitForFile(t, file, func(s string) bool {
		return strings.Contains(s, "refused by the broker") && !strings.Contains(s, "export")
	}, 2*time.Second)
	time.Sleep(200 * time.Millisecond)
	cancel()
	<-done
	if refused.asked != 1 {
		t.Fatalf("asked %d times after a refusal, want once before the 30 s refresh", refused.asked)
	}
}

// The sidecar proves its Pod and relays the run's token on a plain GET of
// the settings route, and accepts only a well-formed answer that passes the
// catalog's checks.
func TestFetchSettingsAsksTheBrokerAsTheRun(t *testing.T) {
	var gotProof, gotSession, gotLine atomic.Value
	var answer atomic.Value
	answer.Store(`{"settings":{"API_BASE":"https://api.example.com/v1"}}`)
	var status atomic.Int32
	status.Store(http.StatusOK)
	broker := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotProof.Store(r.Header.Get("Proxy-Authorization"))
		gotSession.Store(r.Header.Get(sessionHeader))
		gotLine.Store(r.Method + " " + r.RequestURI)
		w.WriteHeader(int(status.Load()))
		if status.Load() == http.StatusOK {
			_, _ = io.WriteString(w, answer.Load().(string))
		}
	}))
	defer broker.Close()
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	writeTestFile(t, ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: broker.TLS.Certificates[0].Certificate[0]}))
	proof := testProof(time.Now().Add(time.Hour), "gatehouse")
	proofFile := filepath.Join(dir, "proof")
	writeTestFile(t, proofFile, []byte(proof))
	up := UpstreamConfig{Address: broker.Listener.Addr().String(), ServerName: "127.0.0.1", CAFile: ca, ProofFile: proofFile, Audience: "gatehouse"}
	deadline := time.Now().Add(time.Hour)

	code, settings, err := fetchSettings(t.Context(), up, deadline, "run-token")
	if err != nil || code != http.StatusOK || settings["API_BASE"] != "https://api.example.com/v1" {
		t.Fatalf("%d %v %v", code, settings, err)
	}
	if gotProof.Load() != "Bearer "+proof || gotSession.Load() != "run-token" || gotLine.Load() != "GET "+httpcatalog.SettingsPath {
		t.Fatalf("sent %v %v %v", gotProof.Load(), gotSession.Load(), gotLine.Load())
	}
	for name, bad := range map[string]string{
		"secret-shaped name": `{"settings":{"API_TOKEN":"x"}}`,
		"placeholder value":  `{"settings":{"API_BASE":"__vault_KEY__"}}`,
		"newline in a value": `{"settings":{"API_BASE":"a\nb"}}`,
		"unknown field":      `{"settings":{},"automation":"auto-1"}`,
		"no settings":        `{}`,
		"not json":           `settings`,
		"trailing data":      `{"settings":{}}{}`,
	} {
		answer.Store(bad)
		if _, settings, err := fetchSettings(t.Context(), up, deadline, "run-token"); err == nil {
			t.Errorf("%s: accepted %v", name, settings)
		}
	}
	status.Store(http.StatusForbidden)
	if code, settings, err := fetchSettings(t.Context(), up, deadline, "run-token"); code != http.StatusForbidden || settings != nil || err != nil {
		t.Fatalf("refusal: %d %v %v", code, settings, err)
	}
}
