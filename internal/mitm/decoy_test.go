package mitm

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/auditchain"
	"github.com/Infisical/agent-vault/internal/decoy"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
)

// Synthetic decoys; never real credentials.
const (
	decoyGitHub = "synthetic-decoy-github-token-8e41b0c2"
	decoyLLM    = "synthetic_decoy_llm_key_5d29f7a1e3"
)

// plantDecoys puts a set in force on a running proxy's source.
func plantDecoys(t *testing.T, s *decoy.Source) {
	t.Helper()
	values := map[string]string{"pool-a/github_token": decoyGitHub, "pool-a/llm_master_key": decoyLLM}
	load := func(context.Context, int) (map[string]string, int, error) { return values, 1, nil }
	if rejected, err := s.Load(context.Background(), load, true); err != nil || len(rejected) > 0 || s.Current().Len() != 2 {
		t.Fatalf("plant: %v %+v", err, rejected)
	}
}

func withDecoys(s *decoy.Source) func(*Options) {
	return func(o *Options) { o.HeaderAdapter.Decoys = s }
}

// asTranscript marks the fixture's entry as a model API.
func asTranscript(t *testing.T) func(*Options) {
	return func(o *Options) {
		entries := o.HeaderAdapter.Catalog.Current().Entries()
		entries[0].Transcript = true
		data, err := json.Marshal(map[string]any{"entries": entries})
		if err != nil {
			t.Fatal(err)
		}
		catalog, err := httpcatalog.Parse(data)
		if err != nil {
			t.Fatal(err)
		}
		o.HeaderAdapter.Catalog = catalog
	}
}

func checkDecoyRow(t *testing.T, e auditchain.Event, label, surface, pool, target string) {
	t.Helper()
	if e.Event != auditchain.EventDenied || e.Outcome != "decoy_credential" || e.Binding != "decoy/"+label || e.Decision != surface || e.Pool != pool || e.Target != target {
		t.Fatalf("decoy row %+v, want %s on %s from pool %q at %s", e, label, surface, pool, target)
	}
	if pool != "" && (e.Agent != "agent-uuid-1" || e.PodUID != "pod-uid-1") {
		t.Fatalf("decoy row attribution: %+v", e)
	}
	row, _ := json.Marshal(e)
	if strings.Contains(string(row), decoyGitHub) || strings.Contains(string(row), decoyLLM) {
		t.Fatal("decoy value in the audit row")
	}
}

// A decoy wherever a request can carry a credential is refused before it
// reaches the vendor, and the row names the decoy, the surface and the
// session. The check runs before routing and before every other request
// check, so an unlisted path or a misplaced placeholder still records it.
func TestAdapterRefusesDecoyCredentials(t *testing.T) {
	src := decoy.NewSource(nil)
	f := newAdapterFixture(t, withDecoys(src))
	plantDecoys(t, src)
	target := "example.com:" + strconv.Itoa(f.port)
	for _, tc := range []struct {
		name, method, path, body string
		mutate                   func(*http.Request)
		label, surface           string
	}{
		{"bearer", "POST", "/v1/chat/completions", "{}", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+decoyLLM) }, "pool-a/llm_master_key", decoy.SurfaceHeader},
		{"other header", "POST", "/v1/chat/completions", "{}", func(r *http.Request) { r.Header.Set("X-Api-Key", decoyLLM) }, "pool-a/llm_master_key", decoy.SurfaceHeader},
		{"basic password", "GET", "/v1/chat/x", "", func(r *http.Request) { r.SetBasicAuth("x-access-token", decoyGitHub) }, "pool-a/github_token", decoy.SurfaceHeader},
		{"cookie", "GET", "/v1/chat/x", "", func(r *http.Request) { r.Header.Set("Cookie", "token="+decoyGitHub) }, "pool-a/github_token", decoy.SurfaceHeader},
		{"query", "GET", "/v1/chat/x?api_key=" + decoyLLM, "", nil, "pool-a/llm_master_key", decoy.SurfaceQuery},
		{"path", "GET", "/v1/chat/" + decoyGitHub, "", nil, "pool-a/github_token", decoy.SurfacePath},
		{"json body", "POST", "/v1/chat/completions", `{"note":"` + decoyGitHub + `"}`, nil, "pool-a/github_token", decoy.SurfaceBody},
		{"form body", "POST", "/v1/chat/completions", "a=1&client_secret=" + decoyLLM, func(r *http.Request) { r.Header.Set("Content-Type", "application/x-www-form-urlencoded") }, "pool-a/llm_master_key", decoy.SurfaceBody},
		{"unlisted path", "POST", "/v1/admin", "{}", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+decoyLLM) }, "pool-a/llm_master_key", decoy.SurfaceHeader},
		{"with a misplaced placeholder", "POST", "/v1/chat/completions", `{"k":"__vault_LLM_KEY__","t":"` + decoyGitHub + `"}`, nil, "pool-a/github_token", decoy.SurfaceBody},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := f.calls.Load()
			code, body, err := f.do(t, tc.method, tc.path, tc.body, tc.mutate)
			if err != nil || code != http.StatusForbidden || f.calls.Load() != before {
				t.Fatalf("code=%d vendor calls=%d err=%v", code, f.calls.Load()-before, err)
			}
			if strings.Contains(body, "decoy") {
				t.Fatalf("refusal names the decoy to the caller: %q", body)
			}
			checkDecoyRow(t, f.audit.last(), tc.label, tc.surface, "pool-agent", target)
		})
	}
}

// With decoys loaded, ordinary traffic and near misses pass untouched.
func TestAdapterAdmitsTrafficWithoutADecoy(t *testing.T) {
	src := decoy.NewSource(nil)
	f := newAdapterFixture(t, withDecoys(src))
	plantDecoys(t, src)
	for _, body := range []string{`{"model":"m"}`, `{"note":"` + decoyGitHub + `x"}`, `{"note":"` + decoyGitHub[:20] + `"}`} {
		if code, _, err := f.do(t, "POST", "/v1/chat/completions", body, nil); err != nil || code != 200 {
			t.Fatalf("%q: %d %v", body, code, err)
		}
	}
	for _, e := range f.audit.all() {
		if e.Outcome == "decoy_credential" {
			t.Fatalf("decoy row for ordinary traffic: %+v", e)
		}
	}
}

// A model API's body quotes whatever the agent read, so a decoy there passes;
// the same decoy in a header of that call is still refused.
func TestTranscriptEntryBodyMayQuoteADecoy(t *testing.T) {
	src := decoy.NewSource(nil)
	f := newAdapterFixture(t, withDecoys(src), asTranscript(t))
	plantDecoys(t, src)
	if code, _, err := f.do(t, "POST", "/v1/chat/completions", `{"messages":[{"content":"env: TOKEN=`+decoyGitHub+`"}]}`, nil); err != nil || code != 200 || f.calls.Load() != 1 {
		t.Fatalf("transcript body: %d %v", code, err)
	}
	code, _, err := f.do(t, "POST", "/v1/chat/completions", "{}", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+decoyLLM) })
	if err != nil || code != http.StatusForbidden || f.calls.Load() != 1 {
		t.Fatalf("transcript header: %d %v", code, err)
	}
	checkDecoyRow(t, f.audit.last(), "pool-a/llm_master_key", decoy.SurfaceHeader, "pool-agent", "example.com:"+strconv.Itoa(f.port))
}

// A decoy sent as the proxy credential is refused at CONNECT, before any
// identity exists, so the row names no pool. A decoy in an admitted CONNECT's
// own headers is refused with the session named.
func TestDecoyOnTheConnectIsRefused(t *testing.T) {
	src := decoy.NewSource(nil)
	f := newAdapterFixture(t, withDecoys(src))
	plantDecoys(t, src)
	target := "example.com:" + strconv.Itoa(f.port)

	asProxyPassword := newTrustingClient(f.proxyURL, url.UserPassword(decoyGitHub, "vault"), f.roots)
	t.Cleanup(asProxyPassword.CloseIdleConnections)
	if resp, err := asProxyPassword.Get(f.url("/v1/chat/x")); err == nil {
		_ = resp.Body.Close()
		t.Fatal("tunnel opened with a decoy proxy password")
	}
	checkDecoyRow(t, f.audit.last(), "pool-a/github_token", decoy.SurfaceHeader, "", target)

	connectHeader := newTrustingClient(f.proxyURL, url.User("workload-token"), f.roots)
	connectHeader.Transport.(*http.Transport).ProxyConnectHeader = http.Header{"X-Debug": {"Bearer " + decoyLLM}}
	t.Cleanup(connectHeader.CloseIdleConnections)
	if resp, err := connectHeader.Get(f.url("/v1/chat/x")); err == nil {
		_ = resp.Body.Close()
		t.Fatal("tunnel opened with a decoy in the CONNECT")
	}
	checkDecoyRow(t, f.audit.last(), "pool-a/llm_master_key", decoy.SurfaceHeader, "pool-agent", target)
	if f.calls.Load() != 0 {
		t.Fatal("vendor reached")
	}
}

// A plain-HTTP request carrying a decoy records the decoy, not just the
// plain-HTTP refusal.
func TestDecoyOnAPlainHTTPRequestIsRecorded(t *testing.T) {
	src := decoy.NewSource(nil)
	f := newAdapterFixture(t, withDecoys(src))
	plantDecoys(t, src)
	client := newTrustingClient(f.proxyURL, url.User("workload-token"), f.roots)
	t.Cleanup(client.CloseIdleConnections)
	r, _ := http.NewRequest("GET", "http://example.com:"+strconv.Itoa(f.port)+"/v1/chat/x", nil)
	r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(decoyGitHub+":")))
	resp, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d", resp.StatusCode)
	}
	checkDecoyRow(t, f.audit.last(), "pool-a/github_token", decoy.SurfaceHeader, "pool-agent", "example.com:"+strconv.Itoa(f.port))
}

// git sending a decoy token as its Basic password, as a credential helper
// would, is refused as a decoy rather than as a stray credential, and no
// token is minted.
func TestGitDecoyCredentialIsRefused(t *testing.T) {
	f := newGitFixture(t)
	plantDecoys(t, f.decoys)
	header := "http.extraHeader=Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+decoyGitHub))
	if out, err := f.git(t, f.work, "-c", header, "ls-remote", f.remote("trmlabs/trm-b2b")); err == nil {
		t.Fatalf("ls-remote with a decoy succeeded: %s", out)
	}
	checkDecoyRow(t, f.audit.last(), "pool-a/github_token", decoy.SurfaceHeader, "pool-agent", "example.com:"+strconv.Itoa(f.port))
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.requests) != 0 {
		t.Fatalf("token minted for a decoy request: %v", f.requests)
	}
}

// A decoy in a GitHub write body (a comment carrying it out) is refused before
// a token is minted or GitHub sees it.
func TestGitHubAPIBodyDecoyIsRefused(t *testing.T) {
	f := newAPIFixture(t)
	plantDecoys(t, f.decoys)
	code, _ := f.post(t, "POST", "/repos/trmlabs/example-app/issues/12/comments", "", `{"body":"found it: `+decoyGitHub+`"}`)
	if code != http.StatusForbidden {
		t.Fatalf("status %d", code)
	}
	checkDecoyRow(t, f.audit.last(), "pool-a/github_token", decoy.SurfaceBody, "pool-agent", "example.com:"+strconv.Itoa(f.port))
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.created != 0 || len(f.minted) != 0 {
		t.Fatalf("GitHub reached: created %d minted %d", f.created, len(f.minted))
	}
}
