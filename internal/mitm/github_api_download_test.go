package mitm

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/githubapp"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
)

// downloadToken is the installation token the fake GitHub mints.
const downloadToken = "ghs_syntheticdownloadtoken"

// downloadFixture fronts a fake api.github.com whose job log, size bytes
// long, is served from a signed download host as GitHub does. When plantAt is
// not negative, the log carries the installation token at that byte.
type downloadFixture struct {
	client *http.Client
	port   int
	audit  *adapterAudit
}

func newDownloadFixture(t *testing.T, limits string, size, plantAt int64) *downloadFixture {
	t.Helper()
	saved := githubDownloadHosts
	githubDownloadHosts = []string{"com"} // the fake serves every host as example.com
	t.Cleanup(func() { githubDownloadHosts = saved })
	f := &downloadFixture{audit: &adapterAudit{}}
	line := []byte(strings.Repeat("x", 1023) + "\n")
	github := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app/installations/42/access_tokens":
			var body struct {
				Repositories []string          `json:"repositories"`
				Permissions  map[string]string `json:"permissions"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"token": downloadToken, "expires_at": time.Now().Add(time.Hour).Format(time.RFC3339),
				"permissions": body.Permissions, "repositories": []map[string]string{{"full_name": "example-org/" + body.Repositories[0]}}})
		case "/repos/example-org/example-repo/actions/jobs/11/logs":
			w.Header().Set("Location", "https://example.com/signed/job.log?sig=abc")
			w.WriteHeader(http.StatusFound)
		case "/signed/job.log":
			w.Header().Set("Content-Type", "text/plain")
			for sent := int64(0); sent < size; sent += int64(len(line)) {
				chunk := line[:min(int64(len(line)), size-sent)]
				if plantAt >= sent && plantAt < sent+int64(len(chunk)) {
					chunk = append([]byte(nil), chunk...)
					copy(chunk[plantAt-sent:], downloadToken)
				}
				if _, err := w.Write(chunk); err != nil {
					return
				}
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(github.Close)
	_, portText, _ := net.SplitHostPort(strings.TrimPrefix(github.URL, "https://"))
	f.port, _ = strconv.Atoi(portText)
	catalog, err := httpcatalog.Parse([]byte(fmt.Sprintf(`{"entries":[{"name":"github-api","host":"api.example.com","port":%d,"kind":"github-api",%s
		"pools":["pool-agent"],"git":{"appID":7,"installationID":42,"repos":[{"repo":"example-org/example-repo","access":"write",
		"operations":["actions.read"]}]}}]}`, f.port, limits)))
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	minter := &githubapp.Minter{Signer: rsaSigner{key}, API: github.URL, Client: github.Client()}
	scope := &brokercore.ProxyScope{VaultID: "vault-1", AgentID: "agent-uuid-1", Pool: "pool-agent", WorkloadID: "pod-uid-1"}
	proxyURL, roots, p := setupProxy(t, validTokenResolver("workload-token", scope), &fakeCredProvider{}, func(o *Options) {
		o.StrictCredentialProxy = true
		o.HeaderAdapter = &HeaderAdapter{Catalog: catalog, Keys: &adapterKeys{}, Audit: f.audit, GitTokens: minter}
	})
	p.upstream.TLSClientConfig.RootCAs = github.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	p.upstream.TLSClientConfig.ServerName = "example.com" // the test server's certificate name
	addr := strings.TrimPrefix(github.URL, "https://")
	p.upstream.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	f.client = newTrustingClient(proxyURL, url.User("workload-token"), roots)
	t.Cleanup(f.client.CloseIdleConnections)
	return f
}

// get downloads the job log and returns the status, the bytes received and
// whether the body ended cleanly.
func (f *downloadFixture) get(t *testing.T) (int, int64, error) {
	t.Helper()
	resp, err := f.client.Get("https://api.example.com:" + strconv.Itoa(f.port) + "/repos/example-org/example-repo/actions/jobs/11/logs")
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	n, err := io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, n, err
}

// A log or artifact download of tens of MiB completes under the default
// limit; one over a limit set in the catalog is cut off and audited.
func TestGitHubAPIDownloadsStreamUpToTheLimit(t *testing.T) {
	const size = 24 << 20
	f := newDownloadFixture(t, ``, size, -1)
	code, n, err := f.get(t)
	if code != 200 || n != size || err != nil {
		t.Fatalf("default limit: %d, %d bytes, %v", code, n, err)
	}
	if e := f.audit.last(); e.Outcome != "completed" || e.Status != 200 {
		t.Fatalf("default limit audited %q %d", e.Outcome, e.Status)
	}

	f = newDownloadFixture(t, `"maxResponseBytes":8388608,`, size, -1)
	code, n, err = f.get(t)
	if err == nil || n > 8<<20 {
		t.Fatalf("explicit limit: %d, %d bytes, %v; want a cut-off body of at most 8 MiB", code, n, err)
	}
	if e := f.audit.last(); e.Outcome != "response_too_large" || e.Status != 200 {
		t.Fatalf("explicit limit audited %q %d", e.Outcome, e.Status)
	}
}

// The token screen still covers a download past the old 8 MiB limit: an
// installation token echoed at 12 MiB into a 24 MiB log is cut off before it
// reaches the worker and audited as secret_echo.
func TestGitHubAPIDownloadCutsOffAnEchoedTokenPastTheOldLimit(t *testing.T) {
	const size, plantAt = 24 << 20, 12<<20 + 100
	f := newDownloadFixture(t, ``, size, plantAt)
	resp, err := f.client.Get("https://api.example.com:" + strconv.Itoa(f.port) + "/repos/example-org/example-repo/actions/jobs/11/logs")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err == nil || bytes.Contains(body, []byte(downloadToken)) || int64(len(body)) > plantAt {
		t.Fatalf("got %d bytes, %v; want a body cut off before the token at byte %d", len(body), err, plantAt)
	}
	if e := f.audit.last(); e.Outcome != "secret_echo" {
		t.Fatalf("audited %q %d, want secret_echo", e.Outcome, e.Status)
	}
}
