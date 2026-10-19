package httpcatalog

import (
	"strings"
	"testing"
)

// An operator whose keys live under another KV path sets the prefix; every
// key path must then lie under it, and vendors/ no longer qualifies.
func TestKeyPrefixSetting(t *testing.T) {
	t.Cleanup(func() { _ = SetKeyPrefix("") })
	doc := func(path string) []byte {
		return []byte(`{"entries":[` + strings.Replace(validEntry, `"path":"vendors/serpapi"`, `"path":"`+path+`"`, 1) + `]}`)
	}
	if _, err := Parse(doc("vendors/serpapi")); err != nil {
		t.Fatalf("default prefix: %v", err)
	}
	if err := SetKeyPrefix("agents/keys"); err != nil {
		t.Fatal(err)
	}
	for path, ok := range map[string]bool{
		"agents/keys/serpapi":    true,
		"agents/keys/search/api": true,
		"vendors/serpapi":        false,
		"agents/keys":            false,
		"agents/keysx/serpapi":   false,
		"agents/keys/../serpapi": false,
		"agents/keys/Serpapi":    false,
	} {
		_, err := Parse(doc(path))
		if (err == nil) != ok {
			t.Errorf("%s: err=%v, want ok=%v", path, err, ok)
		}
		if err != nil && !strings.Contains(err.Error(), "a path under agents/keys/") {
			t.Errorf("%s: error %q does not name the prefix", path, err)
		}
	}
	for _, bad := range []string{"Vendors", "vendors/", "/vendors", "ven*dors", "a//b", "a/../b"} {
		if err := SetKeyPrefix(bad); err == nil || !strings.Contains(err.Error(), KeyPrefixEnv) {
			t.Errorf("prefix %q: err=%v, want refused naming %s", bad, err, KeyPrefixEnv)
		}
	}
	if err := SetKeyPrefix(""); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(doc("vendors/serpapi")); err != nil {
		t.Fatalf("empty prefix restores vendors: %v", err)
	}
}

// A client certificate's path follows the same key prefix as an entry's key,
// so the broker's read grant on the prefix covers both.
func TestKeyPrefixAppliesToClientCertificates(t *testing.T) {
	t.Cleanup(func() { _ = SetKeyPrefix("") })
	doc := func(path string) []byte {
		return []byte(`{"entries":[{"name":"reads","host":"rpc.example.com","http2":true,"pathPrefixes":["/example.v1.Reads/Get"],"methods":["POST"],` +
			`"clientCertificate":{"mount":"gatehouse","path":"` + path + `"},"pools":["pool-agent"]}]}`)
	}
	if _, err := Parse(doc("vendors/example-mtls")); err != nil {
		t.Fatalf("default prefix: %v", err)
	}
	if err := SetKeyPrefix("agents/keys"); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(doc("agents/keys/example-mtls")); err != nil {
		t.Fatalf("certificate under the set prefix: %v", err)
	}
	for _, path := range []string{"vendors/example-mtls", "agents/keys", "agents/keysx/example-mtls", "agents/keys/../example-mtls"} {
		if _, err := Parse(doc(path)); err == nil || !strings.Contains(err.Error(), "a path under agents/keys/") {
			t.Errorf("%s: err=%v, want refused naming the prefix", path, err)
		}
	}
}

// An operator with its own role naming sets the pattern. Roles are still
// named for the catalog's environment, keep the -readonly or -readwrite
// suffix that decides access, and stay plain Vault names.
func TestRolePatternSetting(t *testing.T) {
	doc := func(role, access string) []byte {
		a := ""
		if access != "" {
			a = `,"access":"` + access + `"`
		}
		return []byte(`{"entries":[{"name":"core","kind":"postgres","host":"p.abc.db.postgresbridge.com","pools":["pool-a"],
			"postgres":{"database":"core","mount":"database","role":"` + role + `"` + a + `}}]}`)
	}
	Environment.Store("staging")
	t.Cleanup(func() { Environment.Store(""); _ = SetRolePattern("") })
	if err := SetRolePattern(`(agents-)?{environment}-[a-z0-9]+`); err != nil {
		t.Fatal(err)
	}
	for role, tc := range map[string]struct {
		access string
		ok     bool
	}{
		"staging-app-readonly":        {"", true},
		"agents-staging-app-readonly": {"", true},
		"staging-app-readwrite":       {"write", true},
		"Staging-app-readwrite":       {"write", false},
		"staging-app":                 {"", false},
		"prod-app-readonly":           {"", false},
		"stagingx-app-readonly":       {"", false},
		"staging.us.pg1.app-readonly": {"", false},
	} {
		if _, err := Parse(doc(role, tc.access)); (err == nil) != tc.ok {
			t.Errorf("%q: err=%v, want ok=%v", role, err, tc.ok)
		}
	}
	// An environment change recompiles the rule.
	Environment.Store("prod")
	if _, err := Parse(doc("prod-app-readonly", "")); err != nil {
		t.Errorf("prod role under environment prod: %v", err)
	}
	if _, err := Parse(doc("staging-app-readonly", "")); err == nil {
		t.Error("staging role accepted under environment prod")
	}
	Environment.Store("staging")
	// A pattern wider than a Vault name still yields only plain Vault names.
	if err := SetRolePattern(`{environment}/[a-z]+`); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(doc("staging/app-readonly", "")); err == nil {
		t.Error("a role with / was accepted")
	}
	for _, bad := range []string{`staging-[a-z]+`, `({environment}-[a-z]+`} {
		if err := SetRolePattern(bad); err == nil || !strings.Contains(err.Error(), RolePatternEnv) {
			t.Errorf("pattern %q: err=%v, want refused naming %s", bad, err, RolePatternEnv)
		}
	}
	if err := SetRolePattern(""); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(doc("gatehouse-staging.us.pg1.app-readonly", "")); err != nil {
		t.Errorf("empty pattern restores the default: %v", err)
	}
}
