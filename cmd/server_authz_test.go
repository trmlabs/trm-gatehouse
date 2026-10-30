package cmd

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/entitlement"
)

func TestRunnerPersonDomains(t *testing.T) {
	env := func(values map[string]string) func(string) string { return func(k string) string { return values[k] } }
	base := map[string]string{"AGENT_VAULT_RUNNER_JWKS_URL": "https://api.anthropic.com/v1/code/.well-known/jwks.json"}

	a, err := loadAuthorization(env(base))
	if err != nil || a.runner == nil || len(a.runner.PersonDomains) != 0 {
		t.Fatalf("unset: %+v %v", a.runner, err)
	}
	with := map[string]string{"AGENT_VAULT_RUNNER_PERSON_DOMAINS": "example.org,example.com"}
	for k, v := range base {
		with[k] = v
	}
	a, err = loadAuthorization(env(with))
	if err != nil || len(a.runner.PersonDomains) != 2 || a.runner.PersonDomains[0] != "example.org" {
		t.Fatalf("set: %+v %v", a.runner, err)
	}
	for _, bad := range []string{"EXAMPLE.org", "example.org, example.com", "*.example.org", "example", ",", "example.org,"} {
		with["AGENT_VAULT_RUNNER_PERSON_DOMAINS"] = bad
		if _, err := loadAuthorization(env(with)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestCursorSettings(t *testing.T) {
	env := func(values map[string]string) func(string) string { return func(k string) string { return values[k] } }
	good := map[string]string{"AGENT_VAULT_CURSOR_AUDIENCE": "gatehouse-broker", "AGENT_VAULT_CURSOR_TEAM_IDS": "123,456",
		"AGENT_VAULT_CURSOR_PERSON_DOMAINS": "example.org"}
	a, err := loadAuthorization(env(good))
	if err != nil || a.cursor == nil || a.runner != nil || len(a.cursor.TeamIDs) != 2 || a.cursor.PersonDomains[0] != "example.org" ||
		a.cursor.JWKSURL != "https://api.cursor.com/keys" || a.cursor.Issuer != "https://api.cursor.com" || a.verifier() == nil {
		t.Fatalf("set: %+v %v", a.cursor, err)
	}
	if a, err := loadAuthorization(env(map[string]string{})); err != nil || a.cursor != nil || a.verifier() != nil {
		t.Fatalf("unset: %+v %v", a.cursor, err)
	}
	bad := map[string]string{
		"AGENT_VAULT_CURSOR_TEAM_IDS":       "",
		"AGENT_VAULT_CURSOR_AUDIENCE":       "has space",
		"AGENT_VAULT_CURSOR_PERSON_DOMAINS": "*.example.org",
		"AGENT_VAULT_CURSOR_JWKS_URL":       "http://api.cursor.com/keys",
	}
	for key, value := range bad {
		with := map[string]string{}
		for k, v := range good {
			with[k] = v
		}
		with[key] = value
		if _, err := loadAuthorization(env(with)); err == nil {
			t.Errorf("%s=%q accepted", key, value)
		}
	}
	for _, teams := range []string{"abc", "123,", "12 3"} {
		with := map[string]string{"AGENT_VAULT_CURSOR_AUDIENCE": "gatehouse-broker", "AGENT_VAULT_CURSOR_TEAM_IDS": teams}
		if _, err := loadAuthorization(env(with)); err == nil {
			t.Errorf("teams %q accepted", teams)
		}
	}
}

func TestCursorPeopleFile(t *testing.T) {
	env := func(values map[string]string) func(string) string { return func(k string) string { return values[k] } }
	const a1, a2 = "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"
	write := func(body string) string {
		path := filepath.Join(t.TempDir(), "people.json")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	with := func(path string) map[string]string {
		return map[string]string{"AGENT_VAULT_CURSOR_AUDIENCE": "gatehouse-broker", "AGENT_VAULT_CURSOR_TEAM_IDS": "7",
			"AGENT_VAULT_CURSOR_PERSON_DOMAINS": "example.org", "AGENT_VAULT_CURSOR_PEOPLE_FILE": path}
	}
	a, err := loadAuthorization(env(with(write(`{"42": "` + a1 + `", "user_abc-1.x": "` + a2 + `"}`))))
	if err != nil || a.cursor == nil || len(a.cursor.People) != 2 || a.cursor.People["42"] != a1 {
		t.Fatalf("good map: %+v %v", a.cursor, err)
	}
	// Unset: the email behavior is unchanged.
	unset := with("")
	if a, err := loadAuthorization(env(unset)); err != nil || a.cursor == nil || a.cursor.People != nil {
		t.Fatalf("unset: %+v %v", a.cursor, err)
	}
	for name, path := range map[string]string{
		"relative":         "people.json",
		"missing":          "/nonexistent/people.json",
		"empty file":       write(``),
		"empty object":     write(`{}`),
		"array":            write(`[]`),
		"not json":         write(`{"42": `),
		"trailing data":    write(`{"42": "` + a1 + `"} {}`),
		"non-string value": write(`{"42": 7}`),
		"email value":      write(`{"42": "alice@example.org"}`),
		"upper-case guid":  write(`{"42": "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA"}`),
		"short guid":       write(`{"42": "1111"}`),
		"empty id":         write(`{"": "` + a1 + `"}`),
		"id with a colon":  write(`{"user:42": "` + a1 + `"}`),
		"id with a space":  write(`{"4 2": "` + a1 + `"}`),
		"duplicate id":     write(`{"42": "` + a1 + `", "42": "` + a2 + `"}`),
		"duplicate object": write(`{"42": "` + a1 + `", "43": "` + a1 + `"}`),
		"a directory":      t.TempDir(),
	} {
		if _, err := loadAuthorization(env(with(path))); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// AGENT_VAULT_SANDBOX_PERSON_DOMAINS alone yields a verifier that names
// attested persons; unset, there is none.
func TestSandboxPersonDomains(t *testing.T) {
	env := func(values map[string]string) func(string) string { return func(k string) string { return values[k] } }
	a, err := loadAuthorization(env(nil))
	if err != nil || a.verifier() != nil {
		t.Fatalf("unset: %v", err)
	}
	a, err = loadAuthorization(env(map[string]string{"AGENT_VAULT_SANDBOX_PERSON_DOMAINS": "example.org"}))
	if err != nil {
		t.Fatal(err)
	}
	persons, ok := a.verifier().(interface {
		AttestedPerson(string) (string, error)
	})
	if !ok {
		t.Fatal("verifier names no attested persons")
	}
	if person, err := persons.AttestedPerson("alice.smith@example.org"); err != nil || person != "alice.smith@example.org" {
		t.Fatalf("person %q %v", person, err)
	}
	if _, err := loadAuthorization(env(map[string]string{"AGENT_VAULT_SANDBOX_PERSON_DOMAINS": "*.example.org"})); err == nil {
		t.Fatal("wildcard domain accepted")
	}
}

func TestGraphSettings(t *testing.T) {
	env := func(values map[string]string) func(string) string { return func(k string) string { return values[k] } }
	good := map[string]string{"AGENT_VAULT_ENTITLEMENTS": "graph",
		"AGENT_VAULT_GRAPH_TENANT_ID":  "11111111-1111-1111-1111-111111111111",
		"AGENT_VAULT_GRAPH_CLIENT_ID":  "22222222-2222-2222-2222-222222222222",
		"AGENT_VAULT_GRAPH_TOKEN_FILE": "/var/run/secrets/azure/tokens/azure-identity-token"}
	a, err := loadAuthorization(env(good))
	if err != nil || a.entitlements == nil {
		t.Fatalf("set: %+v %v", a.entitlements, err)
	}
	for key, bad := range map[string]string{
		"AGENT_VAULT_GRAPH_TENANT_ID":  "",
		"AGENT_VAULT_GRAPH_CLIENT_ID":  "22222222-2222-2222-2222-22222222222Z",
		"AGENT_VAULT_GRAPH_TOKEN_FILE": "relative/token",
	} {
		with := map[string]string{}
		for k, v := range good {
			with[k] = v
		}
		with[key] = bad
		if _, err := loadAuthorization(env(with)); err == nil {
			t.Errorf("%s=%q accepted", key, bad)
		}
	}
	if _, err := loadAuthorization(env(map[string]string{"AGENT_VAULT_ENTITLEMENTS": "graph"})); err == nil {
		t.Error("graph without its settings accepted")
	}
}

// Each person's directory budget is a setting: today's 60 by default, and any
// positive count up to a ceiling that is itself a setting, 6,000 by default.
// A budget over the ceiling fails at start rather than removing the guard.
func TestEntitlementLookupsPerMinute(t *testing.T) {
	env := func(values map[string]string) func(string) string { return func(k string) string { return values[k] } }
	with := func(budget, ceiling string) map[string]string {
		values := map[string]string{"AGENT_VAULT_ENTITLEMENTS": "file:/nonexistent/entitlements.json"}
		if budget != "" {
			values["AGENT_VAULT_ENTITLEMENT_LOOKUPS_PER_MINUTE"] = budget
		}
		if ceiling != "" {
			values["AGENT_VAULT_ENTITLEMENT_LOOKUPS_PER_MINUTE_MAX"] = ceiling
		}
		return values
	}
	a, err := loadAuthorization(env(with("", "")))
	if err != nil || a.entitlements == nil || a.entitlements.LookupsPerMinute != entitlement.DefaultLookupsPerMinute || entitlement.DefaultLookupsPerMinute != 60 ||
		entitlement.DefaultMaxLookupsPerMinute != 6000 {
		t.Fatalf("default: %+v %v", a.entitlements, err)
	}
	for _, c := range []struct {
		budget, ceiling string
		want            int
	}{{"1", "", 1}, {"600", "", 600}, {"6000", "", 6000}, {"250000", "250000", 250000}, {"", "1000000", 60}} {
		if a, err := loadAuthorization(env(with(c.budget, c.ceiling))); err != nil || a.entitlements.LookupsPerMinute != c.want {
			t.Errorf("budget %q ceiling %q: %+v %v", c.budget, c.ceiling, a.entitlements, err)
		}
	}
	for _, c := range []struct{ budget, ceiling string }{
		{"0", ""}, {"-5", ""}, {"ten", ""}, {"1.5", ""},
		{"6001", ""}, {"250000", ""}, {"100", "99"}, {"", "30"},
		{"60", "0"}, {"60", "-1"}, {"60", "lots"},
	} {
		if _, err := loadAuthorization(env(with(c.budget, c.ceiling))); err == nil {
			t.Errorf("budget %q ceiling %q accepted", c.budget, c.ceiling)
		}
	}
}

func TestGumloopSettings(t *testing.T) {
	env := func(values map[string]string) func(string) string { return func(k string) string { return values[k] } }
	good := map[string]string{"AGENT_VAULT_GUMLOOP_JWKS_URL": "https://gumloop.example/jwks", "AGENT_VAULT_GUMLOOP_AUDIENCE": "gatehouse-broker", "AGENT_VAULT_STATIC_TOKEN_PORT": "8443"}
	v, err := gumloopVerifier(env(good))
	if err != nil || v == nil || v.Issuer != "https://api.gumloop.com" || v.Audience != "gatehouse-broker" || v.JWKSURL != good["AGENT_VAULT_GUMLOOP_JWKS_URL"] {
		t.Fatalf("set: %+v %v", v, err)
	}
	if v, err := gumloopVerifier(env(nil)); err != nil || v != nil {
		t.Fatalf("unset: %+v %v", v, err)
	}
	for name, with := range map[string]map[string]string{
		"http url":             {"AGENT_VAULT_GUMLOOP_JWKS_URL": "http://gumloop.example/jwks", "AGENT_VAULT_GUMLOOP_AUDIENCE": "gatehouse-broker", "AGENT_VAULT_STATIC_TOKEN_PORT": "8443"},
		"no audience":          {"AGENT_VAULT_GUMLOOP_JWKS_URL": "https://gumloop.example/jwks", "AGENT_VAULT_STATIC_TOKEN_PORT": "8443"},
		"no url":               {"AGENT_VAULT_GUMLOOP_AUDIENCE": "gatehouse-broker", "AGENT_VAULT_STATIC_TOKEN_PORT": "8443"},
		"bad audience":         {"AGENT_VAULT_GUMLOOP_JWKS_URL": "https://gumloop.example/jwks", "AGENT_VAULT_GUMLOOP_AUDIENCE": "has space", "AGENT_VAULT_STATIC_TOKEN_PORT": "8443"},
		"issuer alone":         {"AGENT_VAULT_GUMLOOP_ISSUER": "https://api.gumloop.com", "AGENT_VAULT_STATIC_TOKEN_PORT": "8443"},
		"no static-token port": {"AGENT_VAULT_GUMLOOP_JWKS_URL": "https://gumloop.example/jwks", "AGENT_VAULT_GUMLOOP_AUDIENCE": "gatehouse-broker"},
	} {
		if _, err := gumloopVerifier(env(with)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestCursorPeopleFileLogsThatDomainsAreIgnored(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	path := filepath.Join(t.TempDir(), "people.json")
	if err := os.WriteFile(path, []byte(`{"42": "11111111-1111-1111-1111-111111111111"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"AGENT_VAULT_CURSOR_AUDIENCE": "gatehouse-broker", "AGENT_VAULT_CURSOR_TEAM_IDS": "7",
		"AGENT_VAULT_CURSOR_PERSON_DOMAINS": "example.org", "AGENT_VAULT_CURSOR_PEOPLE_FILE": path}
	if _, err := loadAuthorization(func(k string) string { return env[k] }); err != nil || !strings.Contains(buf.String(), "AGENT_VAULT_CURSOR_PERSON_DOMAINS is ignored") {
		t.Fatalf("no warning: %v %q", err, buf.String())
	}
	buf.Reset()
	delete(env, "AGENT_VAULT_CURSOR_PERSON_DOMAINS")
	if _, err := loadAuthorization(func(k string) string { return env[k] }); err != nil || buf.Len() != 0 {
		t.Fatalf("warned without domains: %v %q", err, buf.String())
	}
}
