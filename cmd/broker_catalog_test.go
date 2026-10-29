package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/httpcatalog"
)

const exampleCatalogYAML = `pools:
  - {name: cursor, namespace: example-agents, serviceAccount: example-worker}
entries:
  - name: examplecore
    kind: postgres
    host: p.abc.db.postgresbridge.com
    pools: [cursor]
    postgres: {database: app, mount: database, role: staging.us.example.app-readonly}
  - name: serpapi
    host: serpapi.com
    pathPrefixes: [/search]
    methods: [GET]
    header: X-Api-Key
    placeholder: __vault_SERPAPI_KEY__
    key: {mount: gatehouse, path: vendors/serpapi, field: key}
    pools: [cursor]
`

func TestBrokerCatalogValidate(t *testing.T) {
	httpcatalog.Environment.Store("staging")
	t.Cleanup(func() { httpcatalog.Environment.Store("") })
	var out bytes.Buffer
	if err := validateBrokerCatalog([]byte(exampleCatalogYAML), []string{".postgresbridge.com", "serpapi.com"}, true, &out); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); got != "valid: pools=1 postgres=1 http=1\n" {
		t.Fatalf("summary %q", got)
	}
	for name, tc := range map[string]struct {
		doc      string
		suffixes []string
		pools    bool
	}{
		"wildcard host":   {strings.Replace(exampleCatalogYAML, "host: serpapi.com", "host: '*.serpapi.com'", 1), nil, false},
		"undefined pool":  {strings.Replace(exampleCatalogYAML, "pools: [cursor]\n    postgres", "pools: [ci]\n    postgres", 1), nil, false},
		"outside domains": {exampleCatalogYAML, []string{".postgresbridge.com"}, false},
		"pools required":  {strings.Replace(exampleCatalogYAML, "pools:\n  - {name: cursor, namespace: example-agents, serviceAccount: example-worker}\n", "", 1), nil, true},
		"unknown field":   {exampleCatalogYAML + "    insecure: true\n", nil, false},
		"not yaml":        {"entries: [", nil, false},
	} {
		if err := validateBrokerCatalog([]byte(tc.doc), tc.suffixes, tc.pools, &bytes.Buffer{}); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// broker-catalog validate runs the broker's own parser: an unknown kind and a
// role outside --environment are refused there, as the broker would at load.
func TestBrokerCatalogValidateUsesTheBrokerParser(t *testing.T) {
	t.Cleanup(func() { httpcatalog.Environment.Store("") })
	var out bytes.Buffer
	httpKind := []byte(`{"entries":[{"name":"serpapi","kind":"http","host":"serpapi.com","pathPrefixes":["/search"],"methods":["GET"],"header":"X-Api-Key","placeholder":"__vault_SERPAPI_KEY__","key":{"mount":"gatehouse","path":"vendors/serpapi","field":"key"},"pools":["pool-a"]}]}`)
	if err := validateBrokerCatalog(httpKind, nil, false, &out); err == nil || !strings.Contains(err.Error(), "unknown kind") {
		t.Fatalf("kind http: %v", err)
	}
	if err := catalogEnvironment(func(string) string { return "staging" }); err != nil {
		t.Fatal(err)
	}
	prodRole := []byte(`{"entries":[{"name":"app","kind":"postgres","host":"p.abc.db.postgresbridge.com","pools":["pool-a"],"postgres":{"database":"app","mount":"database","role":"prod.us.example.app-readonly"}}]}`)
	if err := validateBrokerCatalog(prodRole, nil, false, &out); err == nil {
		t.Fatal("a prod role validated for staging")
	}
	if err := catalogEnvironment(func(string) string { return "Staging!" }); err == nil {
		t.Fatal("malformed environment accepted")
	}
}

const identityCatalogYAML = `pools:
  - {name: claude, namespace: example-agents, serviceAccount: example-worker, identity: claude-session, ccpoolID: ccpool_abc, ceiling: T1}
entries:
  - name: example-svc
    kind: gcp
    host: svc.example.com
    tier: T1
    requires: ["22222222-2222-2222-2222-222222222222"]
    placeholder: __vault_GCP__
    pools: [claude]
    pathPrefixes: [/api/]
    gcp:
      serviceAccount: example-svc-caller@example-analytics.iam.gserviceaccount.com
      audience: https://svc.example.com
`

// An identity entry validates as the broker loads it: one service account
// and one audience, no scopes, bucket, prefix or role beside them, and a
// host that is not Google's.
func TestBrokerCatalogValidateGCPIdentity(t *testing.T) {
	var out bytes.Buffer
	if err := validateBrokerCatalog([]byte(identityCatalogYAML), []string{".example.com"}, true, &out); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); got != "valid: pools=1 gcp=1\n" {
		t.Fatalf("summary %q", got)
	}
	for name, doc := range map[string]string{
		"audience with scopes":      strings.Replace(identityCatalogYAML, "      audience:", "      scopes: [https://www.googleapis.com/auth/cloud-platform]\n      audience:", 1),
		"audience with bucket":      strings.Replace(identityCatalogYAML, "      audience:", "      bucket: example-agent-files\n      audience:", 1),
		"audience with role":        strings.Replace(identityCatalogYAML, "      audience:", "      role: roles/storage.objectViewer\n      audience:", 1),
		"empty audience":            strings.Replace(identityCatalogYAML, "audience: https://svc.example.com", `audience: ""`, 1),
		"audience on a Google host": strings.Replace(identityCatalogYAML, "host: svc.example.com", "host: iamcredentials.googleapis.com", 1),
	} {
		if err := validateBrokerCatalog([]byte(doc), nil, false, &bytes.Buffer{}); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
