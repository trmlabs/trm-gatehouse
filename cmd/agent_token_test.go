package cmd

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/agenttoken"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/server"
)

const agentCatalogHead = `harnesses:
  - name: token-agents
    identity: {kind: static-token}
    path: {kind: direct}
    authorization: {mode: automation, poolName: automations}
    client: {proxyEnv: EXAMPLE_PROXY, caFileEnv: EXAMPLE_CA_FILE}
pools:
  - {name: automations, namespace: example-agents, serviceAccount: example-worker, identity: cursor-automation}
entries:
  - name: serpapi
    host: serpapi.com
    pathPrefixes: [/search]
    methods: [GET]
    header: X-Api-Key
    placeholder: __vault_SERPAPI_KEY__
    key: {mount: gatehouse, path: vendors/serpapi, field: key}
    pools: [automations]
automations:
`

var tokenLine = regexp.MustCompile(`(?m)^(example-agent\.[A-Za-z0-9_-]{43})$`)

// The mint command prints the token once and a catalog block that the broker's
// own validator accepts and that the token verifies against. Nothing is
// written: the only place the token exists is the output.
func TestMintAgentTokenPrintsATokenAndItsBlock(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	var out bytes.Buffer
	spec := agentBlock{ID: "example-agent", Owner: "platform-team", Entries: []string{"serpapi"}, Expires: time.Now().Add(httpcatalog.MaxTokenLifetime).UTC().Truncate(time.Second)}
	if err := mintAgentToken(spec, &out); err != nil {
		t.Fatal(err)
	}
	m := tokenLine.FindStringSubmatch(out.String())
	if m == nil || strings.Count(out.String(), m[1]) != 1 {
		t.Fatalf("the token is not printed exactly once:\n%s", out.String())
	}
	token := m[1]
	block := blockOf(t, out.String())
	if strings.Contains(block, token) || !strings.Contains(block, "tokenSHA256: [\""+agenttoken.Hash(token)+"\"]") {
		t.Fatalf("the block holds the token or lacks its hash:\n%s", block)
	}
	if !strings.Contains(block, "expires: ") || strings.Contains(block, "write") {
		t.Fatalf("unrequested fields:\n%s", block)
	}
	// The paste goes under "automations:" in a catalog the validator accepts.
	if err := validateBrokerCatalog([]byte(agentCatalogHead+block), nil, true, &bytes.Buffer{}); err != nil {
		t.Fatalf("validator refused the printed block: %v\n%s", err, block)
	}
	document, err := httpcatalog.FromYAML([]byte(agentCatalogHead + block))
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := httpcatalog.Parse(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (agenttoken.Static{Catalog: catalog}).Verify(context.Background(), token); err != nil {
		t.Fatalf("the minted token is refused by its own block: %v", err)
	}
	// Nothing was stored.
	if files, _ := filepath.Glob(filepath.Join(dir, "*")); len(files) != 0 {
		t.Fatalf("mint wrote files: %v", files)
	}
	again := &bytes.Buffer{}
	if err := mintAgentToken(spec, again); err != nil || strings.Contains(again.String(), token) {
		t.Fatal("a second mint repeated the token")
	}
	if home, _ := os.UserHomeDir(); home != "" {
		if _, err := os.Stat(filepath.Join(home, ".agent-vault", token)); err == nil {
			t.Fatal("token stored")
		}
	}
}

// Rotation keeps the old hash beside the new for the overlap, with an expiry
// and a write list when asked for, and the block still validates.
func TestMintAgentTokenRotationExpiryAndWrite(t *testing.T) {
	old := strings.Repeat("a", 64)
	var out bytes.Buffer
	spec := agentBlock{ID: "example-agent", Name: "Example", Owner: "alice@example.com", Entries: []string{"serpapi"}, Write: nil, WriteSet: true, Keep: []string{old}}
	spec.Expires = time.Now().Add(10 * 24 * time.Hour).UTC().Truncate(time.Second)
	if err := mintAgentToken(spec, &out); err != nil {
		t.Fatal(err)
	}
	block := blockOf(t, out.String())
	for _, want := range []string{`name: "Example"`, `owner: "alice@example.com"`, "write: []", `expires: "` + spec.Expires.Format(time.RFC3339) + `"`, `tokenSHA256: ["` + old + `", "`} {
		if !strings.Contains(block, want) {
			t.Errorf("missing %s in\n%s", want, block)
		}
	}
	if err := validateBrokerCatalog([]byte(agentCatalogHead+block), nil, true, &bytes.Buffer{}); err != nil {
		t.Fatalf("%v\n%s", err, block)
	}
}

func TestMintAgentTokenRefusals(t *testing.T) {
	for name, spec := range map[string]agentBlock{
		"no owner":           {ID: "example-agent", Entries: []string{"serpapi"}},
		"no entry":           {ID: "example-agent", Owner: "platform-team"},
		"a bad id":           {ID: "bad id", Owner: "platform-team", Entries: []string{"serpapi"}},
		"a bad entry name":   {ID: "example-agent", Owner: "platform-team", Entries: []string{"bad entry"}},
		"a bad owner":        {ID: "example-agent", Owner: "Platform Team", Entries: []string{"serpapi"}},
		"a bad kept hash":    {ID: "example-agent", Owner: "platform-team", Entries: []string{"serpapi"}, Keep: []string{"nope"}},
		"two hashes kept":    {ID: "example-agent", Owner: "platform-team", Entries: []string{"serpapi"}, Keep: []string{strings.Repeat("a", 64), strings.Repeat("b", 64)}},
		"a quote in the id":  {ID: `a"b`, Owner: "platform-team", Entries: []string{"serpapi"}},
		"a write not listed": {ID: "example-agent", Owner: "platform-team", Entries: []string{"serpapi"}, Write: []string{"other"}, WriteSet: true},
	} {
		var out bytes.Buffer
		err := mintAgentToken(spec, &out)
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
		if strings.Contains(out.String(), "example-agent.") || strings.Contains(out.String(), "tokenSHA256") {
			t.Errorf("%s: printed a token or block before refusing:\n%s", name, out.String())
		}
	}
}

// A token always expires: the command defaults to the longest life the catalog
// accepts, refuses anything longer or not positive, and the block it prints
// loads. A block with no expiry, or one the catalog would refuse, is never
// printed.
func TestTokenExpiryDefaultAndCap(t *testing.T) {
	now := time.Date(2030, 1, 1, 12, 0, 0, 500, time.UTC)
	flag := brokerCatalogMintAgentTokenCmd.Flags().Lookup("expires-in")
	def, err := time.ParseDuration(flag.DefValue)
	if err != nil || def != httpcatalog.MaxTokenLifetime {
		t.Fatalf("expires-in defaults to %q, want the cap %s", flag.DefValue, httpcatalog.MaxTokenLifetime)
	}
	got, err := tokenExpiry(def, now)
	if want := time.Date(2030, 4, 1, 12, 0, 0, 0, time.UTC); err != nil || !got.Equal(want) {
		t.Errorf("default expiry %v %v, want %v", got, err, want)
	}
	if got, err := tokenExpiry(24*time.Hour, now); err != nil || !got.Equal(time.Date(2030, 1, 2, 12, 0, 0, 0, time.UTC)) {
		t.Errorf("a shorter life: %v %v", got, err)
	}
	for _, in := range []time.Duration{httpcatalog.MaxTokenLifetime + time.Second, 365 * 24 * time.Hour, 0, -time.Hour} {
		if _, err := tokenExpiry(in, now); err == nil {
			t.Errorf("%s accepted", in)
		}
	}
	// No expiry on the spec: the block would be refused, so nothing prints.
	var out bytes.Buffer
	err = mintAgentToken(agentBlock{ID: "example-agent", Owner: "platform-team", Entries: []string{"serpapi"}}, &out)
	if err == nil || out.Len() != 0 {
		t.Errorf("a block with no expiry printed: %v\n%s", err, out.String())
	}
}

// The static-token listener starts only with the credential proxy and a PROXY
// header on the HTTP listener, on a real port.
func TestStaticTokenPortNeedsItsPrerequisites(t *testing.T) {
	for name, tc := range map[string]struct{ port, proxyHeader string }{
		"no credential proxy": {"14326", "true"},
		"a text port":         {"abc", "true"},
		"port zero":           {"0", "true"},
		"a port out of range": {"70000", "true"},
		"no PROXY header":     {"14326", ""},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("AGENT_VAULT_STATIC_TOKEN_PORT", tc.port)
			t.Setenv("AGENT_VAULT_MITM_PROXY_PROTOCOL", tc.proxyHeader)
			t.Setenv("AGENT_VAULT_CREDENTIAL_PROXY", "")
			logger := slog.New(slog.DiscardHandler)
			s := server.New("127.0.0.1:0", nil, make([]byte, 32), nil, false, "", logger)
			err := attachServerExtensions(s, "127.0.0.1", 14322, 0, make([]byte, 32), nil, logger, 0, 0)
			if err == nil || !strings.Contains(err.Error(), "AGENT_VAULT_STATIC_TOKEN_PORT needs") {
				t.Fatalf("startup error %v", err)
			}
		})
	}
}

// blockOf is the catalog block in mint's output.
func blockOf(t *testing.T, out string) string {
	t.Helper()
	_, block, ok := strings.Cut(out, "\n  - id:")
	if !ok {
		t.Fatalf("no catalog block in\n%s", out)
	}
	return "  - id:" + block
}
