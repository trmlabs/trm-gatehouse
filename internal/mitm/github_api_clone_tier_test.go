package mitm

import (
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

	"github.com/Infisical/agent-vault/internal/authorize/authorizetest"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/entitlement"
	"github.com/Infisical/agent-vault/internal/githubapp"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/runnerid"
)

// A pull request's file list and a compare return code, so they need the git
// entry they rely on to authorize the requester too. Here the git entry is T1
// and needs a group; the github-api entry is T0. A person outside the group
// reads the pull request but not its files or a compare; a member reads all.
func TestGitHubAPICodeReadsNeedTheCloneEntrysAuthorization(t *testing.T) {
	audit := &adapterAudit{}
	github := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app/installations/42/access_tokens" {
			var body struct {
				Permissions map[string]string `json:"permissions"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"token": "ghs_syntheticclonetiertoken01", "expires_at": time.Now().Add(time.Hour).Format(time.RFC3339),
				"permissions": body.Permissions, "repositories": []map[string]string{{"full_name": "example-org/example-repo"}}})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	}))
	t.Cleanup(github.Close)
	_, portText, _ := net.SplitHostPort(strings.TrimPrefix(github.URL, "https://"))
	port, _ := strconv.Atoi(portText)
	catalog, err := httpcatalog.Parse([]byte(fmt.Sprintf(`{"pools":[
	  {"name":"claude","namespace":"n","serviceAccount":"claude","identity":"claude-session","ccpoolID":"ccpool_abc","ceiling":"T1"}],
	 "entries":[
	  {"name":"github-api","host":"example.com","port":%d,"kind":"github-api","pools":["claude"],
	   "git":{"appID":7,"installationID":42,"repos":[{"repo":"example-org/example-repo","access":"write"}]}},
	  {"name":"github","host":"git.example.com","kind":"git","pools":["claude"],"tier":"T1","requires":["`+authzGroup+`"],
	   "git":{"appID":7,"installationID":42,"repos":[{"repo":"example-org/example-repo","access":"read"}]}}]}`, port)))
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	runner := fakeRunner{"alice": {Kind: runnerid.KindPerson, Subject: "sso|alice", Pools: []string{"ccpool_abc"}, TokenSHA256: "aa"},
		"bob": {Kind: runnerid.KindPerson, Subject: "sso|bob", Pools: []string{"ccpool_abc"}, TokenSHA256: "bb"}}
	scope := &brokercore.ProxyScope{VaultID: "vault-1", AgentID: "pool-agent", Pool: "claude", WorkloadID: "pod-uid-1"}
	proxyURL, roots, p := setupProxy(t, validTokenResolver("workload-token", scope), &fakeCredProvider{}, func(o *Options) {
		o.StrictCredentialProxy = true
		o.HeaderAdapter = &HeaderAdapter{Catalog: catalog, Keys: &adapterKeys{}, Audit: audit, Runner: runner,
			Sessions:     &authorizetest.MemBinder{},
			Entitlements: &entitlement.Cache{Source: directory{"sso|alice": {authzGroup}, "sso|bob": {}}},
			GitTokens:    &githubapp.Minter{Signer: rsaSigner{key}, API: github.URL, Client: github.Client()}}
	})
	p.upstream.TLSClientConfig.RootCAs = github.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	addr := strings.TrimPrefix(github.URL, "https://")
	p.upstream.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	get := func(session, path string) int {
		client := newTrustingClient(proxyURL, url.User("workload-token"), roots)
		defer client.CloseIdleConnections()
		client.Transport.(*http.Transport).ProxyConnectHeader = http.Header{SessionHeader: {session}}
		r, _ := http.NewRequest("GET", "https://example.com:"+strconv.Itoa(port)+path, nil)
		resp, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}
	const repo = "/repos/example-org/example-repo"
	if code := get("bob", repo+"/pulls/12"); code != 200 {
		t.Fatalf("a non-member reading the pull request: %d", code)
	}
	for _, path := range []string{repo + "/pulls/12/files", repo + "/compare/main...feature"} {
		if code := get("bob", path); code != http.StatusForbidden || audit.last().Outcome != "not_entitled" || audit.last().Binding != "github" {
			t.Errorf("non-member %s: %d outcome=%q binding=%q", path, code, audit.last().Outcome, audit.last().Binding)
		}
		if code := get("alice", path); code != 200 {
			t.Errorf("member %s: %d", path, code)
		}
	}
}
