package auditchain

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// Every field of a row except the MAC itself must change the MAC input, so
// no field added later can be left out of the tamper check.
func TestEveryRowFieldIsInTheMAC(t *testing.T) {
	base := Row{MACVersion: MACVersionCurrent}
	baseInput := base.macInput()
	typ := reflect.TypeOf(base)
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if field.Name == "MAC" {
			continue
		}
		changed := base
		v := reflect.ValueOf(&changed).Elem().Field(i)
		switch v.Kind() {
		case reflect.String:
			v.SetString("x")
		case reflect.Int, reflect.Int64:
			v.SetInt(v.Int() + 7)
		case reflect.Uint64:
			v.SetUint(7)
		default:
			t.Fatalf("field %s has kind %s: teach this test and macInput about it", field.Name, v.Kind())
		}
		if bytes.Equal(changed.macInput(), baseInput) {
			t.Errorf("field %s is not covered by the MAC", field.Name)
		}
	}
}

// Rows written before v2 keep verifying under the v1 input.
func TestV1InputIsUnchanged(t *testing.T) {
	r := Row{Type: RowType, Replica: "broker-0", Event: EventSessionOpen}
	if !bytes.HasPrefix(r.macInput(), []byte("gatehouse-audit-v1\x00")) {
		t.Fatal("a row without a MAC version no longer uses the v1 input")
	}
	r.MACVersion = 2
	if !bytes.HasPrefix(r.macInput(), []byte("gatehouse-audit-v2\x00")) {
		t.Fatal("a v2 row does not use the v2 input")
	}
	r.MACVersion = 3
	if !bytes.HasPrefix(r.macInput(), []byte("gatehouse-audit-v3\x00")) {
		t.Fatal("a v3 row does not use the v3 input")
	}
	r.MACVersion = 4
	if !bytes.HasPrefix(r.macInput(), []byte("gatehouse-audit-v4\x00")) {
		t.Fatal("a v4 row does not use the v4 input")
	}
	r.MACVersion = 5
	if !bytes.HasPrefix(r.macInput(), []byte("gatehouse-audit-v5\x00")) {
		t.Fatal("a v5 row does not use the v5 input")
	}
	r.MACVersion = 6
	if !bytes.HasPrefix(r.macInput(), []byte("gatehouse-audit-v6\x00")) {
		t.Fatal("a v6 row does not use the v6 input")
	}
	r.MACVersion = 7
	if !bytes.HasPrefix(r.macInput(), []byte("gatehouse-audit-v7\x00")) {
		t.Fatal("a v7 row does not use the v7 input")
	}
	r.MACVersion = 8
	if !bytes.HasPrefix(r.macInput(), []byte("gatehouse-audit-v8\x00")) {
		t.Fatal("a v8 row does not use the v8 input")
	}
	r.MACVersion = 9
	if !bytes.HasPrefix(r.macInput(), []byte("gatehouse-audit-v9\x00")) {
		t.Fatal("a v9 row does not use the v9 input")
	}
	r.MACVersion = 10
	if !bytes.HasPrefix(r.macInput(), []byte("gatehouse-audit-v10\x00")) {
		t.Fatal("a v10 row does not use the v10 input")
	}
	r.MACVersion = 11
	if !bytes.HasPrefix(r.macInput(), []byte("gatehouse-audit-v11\x00")) {
		t.Fatal("a v11 row does not use the v11 input")
	}
	r.MACVersion = 12
	if !bytes.HasPrefix(r.macInput(), []byte("gatehouse-audit-v12\x00")) {
		t.Fatal("a v12 row does not use the v12 input")
	}
	r.MACVersion = MACVersionCurrent
	if !bytes.HasPrefix(r.macInput(), []byte("gatehouse-audit-v13\x00")) {
		t.Fatal("a current row does not use the v13 input")
	}
}

func authzFixture(t *testing.T) (*fixture, string) {
	t.Helper()
	f := newFixture(t)
	if err := f.chain.Record(Event{Event: EventDenied, Pool: "claude", Binding: "vault/core", Outcome: "not_entitled",
		RequesterKind: "person", RequesterOID: "oid-1", TokenSHA256: "ab", Tier: "T1", Decision: "not_entitled", Groups: "11111111-2222-3333-4444-555555555555", CacheAgeSec: 3,
		Kid: "invalid", KidSHA256: "0123456789ab", Peer: "10.0.0.5",
		Operation: "pr.open", Database: "examplecore", RequesterDepartment: "Security & IT", Branch: "agent/pool-a/fix",
		Source: "AUTOMATIONS", Automation: "auto-1", AutomationName: "explorer", AutomationOwner: "owner@example.com",
		Path: "/example.v1.Reads/ReadRows", Settings: "API_BASE,MODE", GraphQLErrors: "FORBIDDEN@node.commits.nodes.0.commit",
		PullRequest: 12, Route: "pull-files", GitEntry: "github-git", Cause: "dial_timeout", Match: strings.Repeat("ab", 32), UpstreamMessage: "Update is not a fast forward"}); err != nil {
		t.Fatal(err)
	}
	f.checkpoint(t)
	return f, f.out.String()
}

// The High finding: a log-sink editor flips a decision and the chain must fail.
func TestAuthorizationFieldEditsAreDetected(t *testing.T) {
	for name, edit := range map[string][2]string{
		"decision":        {`"decision":"not_entitled"`, `"decision":"entitled"`},
		"tier":            {`"tier":"T1"`, `"tier":"T0"`},
		"groups":          {`"groups":"11111111-2222-3333-4444-555555555555"`, `"groups":"11111111-2222-3333-4444-555555555556"`},
		"person":          {`"requesterOID":"oid-1"`, `"requesterOID":"oid-2"`},
		"kind":            {`"requesterKind":"person"`, `"requesterKind":"workload"`},
		"token":           {`"tokenSHA256":"ab"`, `"tokenSHA256":"cd"`},
		"cache age":       {`"cacheAgeSec":3`, `"cacheAgeSec":4`},
		"kid":             {`"kid":"invalid"`, `"kid":"k1"`},
		"kid hash":        {`"kidSHA256":"0123456789ab"`, `"kidSHA256":"ba9876543210"`},
		"peer":            {`"peer":"10.0.0.5"`, `"peer":"10.0.0.6"`},
		"version":         {`"macVersion":13`, `"macVersion":12`},
		"operation":       {`"operation":"pr.open"`, `"operation":"pr.read"`},
		"database":        {`"database":"examplecore"`, `"database":"exampletm2"`},
		"department":      {`"requesterDepartment":"Security \u0026 IT"`, `"requesterDepartment":"Engineering"`},
		"branch":          {`"branch":"agent/pool-a/fix"`, `"branch":"main"`},
		"source":          {`"source":"AUTOMATIONS"`, `"source":"WEBSITE"`},
		"automation":      {`"automation":"auto-1"`, `"automation":"auto-2"`},
		"name":            {`"automationName":"explorer"`, `"automationName":"auditor"`},
		"owner":           {`"automationOwner":"owner@example.com"`, `"automationOwner":"other@example.com"`},
		"path":            {`"path":"/example.v1.Reads/ReadRows"`, `"path":"/example.v1.Writes/AppendRows"`},
		"settings":        {`"settings":"API_BASE,MODE"`, `"settings":"API_BASE"`},
		"graphql":         {`"graphqlErrors":"FORBIDDEN@node.commits.nodes.0.commit"`, `"graphqlErrors":"NOT_FOUND@node"`},
		"cause":           {`"cause":"dial_timeout"`, `"cause":"tls_handshake"`},
		"upstreamMessage": {`"upstreamMessage":"Update is not a fast forward"`, `"upstreamMessage":"Update is a fast forward"`},
		"match":           {`"match":"` + strings.Repeat("ab", 32) + `"`, `"match":"` + strings.Repeat("cd", 32) + `"`},
		"pull":            {`"pullRequest":12`, `"pullRequest":13`},
		"route":           {`"route":"pull-files"`, `"route":"read-pull"`},
		"git entry":       {`"gitEntry":"github-git"`, `"gitEntry":"other-git"`},
	} {
		t.Run(name, func(t *testing.T) {
			f, out := authzFixture(t)
			if !strings.Contains(out, edit[0]) {
				t.Fatalf("fixture row lacks %s", edit[0])
			}
			report := verify(t, f.verifier(), strings.Replace(out, edit[0], edit[1], 1))
			if !hasKind(report, FindingEdit) {
				t.Fatalf("edit not detected: %v", kinds(report))
			}
		})
	}
	f, out := authzFixture(t)
	if report := verify(t, f.verifier(), out); len(report.Findings) != 0 {
		t.Fatalf("untouched trail: %v", kinds(report))
	}
}

// A forged row with a valid v1 MAC (someone holding the HMAC key, or a row
// downgraded by removing its version) cannot carry authorization fields, and a
// chain never steps down from v2 to v1.
func TestV1RowsCannotCarryAuthorizationOrDowngrade(t *testing.T) {
	for name, forge := range map[string]func(*Row){
		"v1 row with a decision":    func(r *Row) { r.Decision = "entitled" },
		"v2 row with a peer":        func(r *Row) { r.MACVersion, r.Peer = 2, "10.0.0.5" },
		"v2 row with a kid":         func(r *Row) { r.MACVersion, r.Kid = 2, "k1" },
		"v3 row with a serial":      func(r *Row) { r.MACVersion, r.Serial = 3, "1a" },
		"v3 row with a notAfter":    func(r *Row) { r.MACVersion, r.NotAfter = 3, "2026-10-07T00:00:00Z" },
		"v4 row with a target":      func(r *Row) { r.MACVersion, r.Target = 4, "example.com:443" },
		"v5 row with an operation":  func(r *Row) { r.MACVersion, r.Operation = 5, "pr.open" },
		"v5 row with a database":    func(r *Row) { r.MACVersion, r.Database = 5, "examplecore" },
		"v5 row with a department":  func(r *Row) { r.MACVersion, r.RequesterDepartment = 5, "Engineering" },
		"v6 row with a branch":      func(r *Row) { r.MACVersion, r.Branch = 6, "main" },
		"v7 row with a source":      func(r *Row) { r.MACVersion, r.Source = 7, "AUTOMATIONS" },
		"v7 row with an automation": func(r *Row) { r.MACVersion, r.Automation = 7, "auto-1" },
		"v7 row with a name":        func(r *Row) { r.MACVersion, r.AutomationName = 7, "explorer" },
		"v7 row with an owner":      func(r *Row) { r.MACVersion, r.AutomationOwner = 7, "owner@example.com" },
		"v8 row with a path":        func(r *Row) { r.MACVersion, r.Path = 8, "/example.v1.Reads/ReadRows" },
		"v9 row with settings":      func(r *Row) { r.MACVersion, r.Settings = 9, "API_BASE" },
		"plain downgrade":           func(*Row) {},
		"unknown version":           func(r *Row) { r.MACVersion = MACVersionCurrent + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			f, out := authzFixture(t)
			parsed := rows(t, out)
			last := parsed[len(parsed)-1]
			key, _ := f.keys.lookup(last.KeyVersion)
			forged := Row{Type: RowType, Replica: last.Replica, Boot: last.Boot, Seq: last.Seq + 1, Time: last.Time,
				Event: EventSessionOpen, Pool: "claude", KeyVersion: last.KeyVersion, Prev: last.MAC}
			forge(&forged)
			forged.MAC = forged.computeMAC(key)
			line, _ := json.Marshal(forged)
			if report := verify(t, f.verifier(), out+string(line)+"\n"); !hasKind(report, FindingEdit) {
				t.Fatalf("forged row accepted: %v", kinds(report))
			}
		})
	}
}

func hasKind(r Report, kind string) bool {
	for _, k := range kinds(r) {
		if k == kind {
			return true
		}
	}
	return false
}

// A trail written by a v2 broker, then after upgrades by v3 to v10 ones,
// verifies; an older row after a newer one is a step down and does not.
func TestUpgradeFromV2VerifiesAndNeverStepsDown(t *testing.T) {
	writeMACVersion = 2
	t.Cleanup(func() { writeMACVersion = MACVersionCurrent })
	f := newFixture(t)
	f.session(t, 1)
	f.checkpoint(t)
	writeMACVersion = 3
	f.restart(t)
	if err := f.chain.Record(Event{Event: EventDenied, Outcome: "authentication", Decision: "identity_token_signature", Kid: "k1", Peer: "10.0.0.5"}); err != nil {
		t.Fatal(err)
	}
	f.checkpoint(t)
	writeMACVersion = 4
	f.restart(t)
	if err := f.chain.Record(Event{Event: EventCertificate, Outcome: "issued", Peer: "10.0.0.5", Serial: "1a2b", NotAfter: "2026-10-07T00:00:00Z"}); err != nil {
		t.Fatal(err)
	}
	f.checkpoint(t)
	writeMACVersion = 5
	f.restart(t)
	if err := f.chain.Record(Event{Event: EventDenied, Outcome: "unlisted", Target: "example.com:443"}); err != nil {
		t.Fatal(err)
	}
	f.checkpoint(t)
	writeMACVersion = 6
	f.restart(t)
	if err := f.chain.Record(Event{Event: EventDenied, Outcome: "no_database", Database: "invalid", RequesterDepartment: "Engineering"}); err != nil {
		t.Fatal(err)
	}
	f.checkpoint(t)
	writeMACVersion = 7
	f.restart(t)
	if err := f.chain.Record(Event{Event: EventDenied, Outcome: "run_target", Operation: "actions.rerun", Branch: "main"}); err != nil {
		t.Fatal(err)
	}
	f.checkpoint(t)
	writeMACVersion = 8
	f.restart(t)
	if err := f.chain.Record(Event{Event: EventDenied, Outcome: "automation_unlisted", Source: "AUTOMATIONS", Automation: "auto-9"}); err != nil {
		t.Fatal(err)
	}
	f.checkpoint(t)
	writeMACVersion = 9
	f.restart(t)
	if err := f.chain.Record(Event{Event: EventDenied, Outcome: "unlisted", Method: "POST", Path: "/example.v1.Reads/ReadRows"}); err != nil {
		t.Fatal(err)
	}
	f.checkpoint(t)
	writeMACVersion = 10
	f.restart(t)
	if err := f.chain.Record(Event{Event: EventSettings, Outcome: "served", Automation: "auto-1", Settings: "API_BASE"}); err != nil {
		t.Fatal(err)
	}
	if err := f.chain.Record(Event{Event: EventHTTPResponse, Outcome: "graphql_error", Status: 200, GraphQLErrors: "FORBIDDEN@node"}); err != nil {
		t.Fatal(err)
	}
	f.checkpoint(t)
	writeMACVersion = 11
	f.restart(t)
	if err := f.chain.Record(Event{Event: EventHTTPResponse, Outcome: "upstream_error", Status: 502, Cause: "tls_handshake"}); err != nil {
		t.Fatal(err)
	}
	f.checkpoint(t)
	writeMACVersion = 12
	f.restart(t)
	if err := f.chain.Record(Event{Event: EventInjection, Outcome: "flagged", Route: "read-pull", Decision: "override", Match: strings.Repeat("ab", 32)}); err != nil {
		t.Fatal(err)
	}
	f.checkpoint(t)
	writeMACVersion = MACVersionCurrent
	f.restart(t)
	if err := f.chain.Record(Event{Event: EventHTTPResponse, Outcome: "completed", Status: 422, Route: "update-branch", UpstreamMessage: "Update is not a fast forward"}); err != nil {
		t.Fatal(err)
	}
	f.session(t, 2)
	f.checkpoint(t)
	out := f.out.String()
	versions := map[int]int{}
	for _, r := range rows(t, out) {
		versions[r.MACVersion]++
	}
	if versions[2] == 0 || versions[3] == 0 || versions[4] == 0 || versions[5] == 0 || versions[6] == 0 || versions[7] == 0 || versions[8] == 0 || versions[9] == 0 || versions[10] == 0 || versions[11] == 0 || versions[12] == 0 || versions[MACVersionCurrent] == 0 || len(versions) != 12 {
		t.Fatalf("trail versions %v, want v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12 then v13", versions)
	}
	if report := verify(t, f.verifier(), out); len(report.Findings) != 0 {
		t.Fatalf("upgraded trail: %v", kinds(report))
	}
	parsed := rows(t, out)
	last := parsed[len(parsed)-1]
	key, _ := f.keys.lookup(last.KeyVersion)
	for _, older := range []int{2, 3, 4, 5, 6, 7, 8, 9} {
		forged := Row{Type: RowType, Replica: last.Replica, Boot: last.Boot, Seq: last.Seq + 1, Time: last.Time,
			Event: EventSessionOpen, Pool: "claude", KeyVersion: last.KeyVersion, Prev: last.MAC, MACVersion: older}
		forged.MAC = forged.computeMAC(key)
		line, _ := json.Marshal(forged)
		if report := verify(t, f.verifier(), out+string(line)+"\n"); !hasKind(report, FindingEdit) {
			t.Fatalf("step down from v12 to v%d accepted: %v", older, kinds(report))
		}
	}
}

// A certificate row's serial and notAfter are covered by the MAC, and only a
// hex serial and an RFC 3339 UTC time are accepted.
func TestCertificateFieldsAreCoveredAndBounded(t *testing.T) {
	f := newFixture(t)
	if err := f.chain.Record(Event{Event: EventCertificate, Outcome: "issued", Peer: "10.0.0.5", Serial: "7f00aa", NotAfter: "2026-10-07T00:00:00Z", DNSNames: "proxy.ns.svc,proxy.ns.svc.cluster.local"}); err != nil {
		t.Fatal(err)
	}
	f.checkpoint(t)
	out := f.out.String()
	for _, edit := range [][2]string{{`"serial":"7f00aa"`, `"serial":"7f00ab"`}, {`"dnsNames":"proxy.ns.svc,`, `"dnsNames":"vault.ns.svc,`}, {`"notAfter":"2026-10-07T00:00:00Z"`, `"notAfter":"2027-10-07T00:00:00Z"`}} {
		if !strings.Contains(out, edit[0]) {
			t.Fatalf("row lacks %s", edit[0])
		}
		if report := verify(t, f.verifier(), strings.Replace(out, edit[0], edit[1], 1)); !hasKind(report, FindingEdit) {
			t.Fatalf("%s edit not detected", edit[0])
		}
	}
	for _, e := range []Event{
		{Event: EventCertificate, Serial: "7F00AA"},
		{Event: EventCertificate, Serial: "007f"},
		{Event: EventCertificate, Serial: strings.Repeat("a", 41)},
		{Event: EventCertificate, NotAfter: "2026-10-07T02:00:00+02:00"},
		{Event: EventCertificate, NotAfter: "tomorrow"},
		{Event: EventCertificate, DNSNames: "proxy.svc, other.svc"},
		{Event: EventCertificate, DNSNames: "Proxy.svc"},
	} {
		if e.Validate() == nil {
			t.Errorf("accepted %+v", e)
		}
	}
}

// A decision may check any number of groups: the row records the full list,
// which only Entra object IDs may form, and its MAC covers it.
func TestManyGroupsAreRecordedInFull(t *testing.T) {
	var groups []string
	for i := range 1000 {
		groups = append(groups, fmt.Sprintf("%08x-0000-0000-0000-%012x", i, i))
	}
	many := strings.Join(groups, ",")
	if (Event{Event: EventDenied, Groups: many}).Validate() != nil {
		t.Fatal("1,000 groups refused")
	}
	for _, bad := range []string{"g1", many + ",", many + ",not a group", "11111111-2222-3333-4444-555555555555 "} {
		if (Event{Event: EventDenied, Groups: bad}).Validate() == nil {
			t.Errorf("group list %.40q accepted", bad)
		}
	}
}

// A refusal's target is covered by the MAC, and only the canonical form
// TargetField returns is accepted, so no path, query or free text can enter.
func TestRefusalTargetIsCoveredAndBounded(t *testing.T) {
	f := newFixture(t)
	if err := f.chain.Record(Event{Event: EventDenied, Outcome: "unlisted", Pool: "claude", Target: "api.example.com:443"}); err != nil {
		t.Fatal(err)
	}
	f.checkpoint(t)
	out := f.out.String()
	edit := [2]string{`"target":"api.example.com:443"`, `"target":"api.example.org:443"`}
	if !strings.Contains(out, edit[0]) {
		t.Fatalf("row lacks %s", edit[0])
	}
	if report := verify(t, f.verifier(), strings.Replace(out, edit[0], edit[1], 1)); !hasKind(report, FindingEdit) {
		t.Fatal("target edit not detected")
	}
	for in, want := range map[string]string{
		"":                         "",
		"API.Example.com:443":      "api.example.com:443",
		"api.example.com":          "api.example.com",
		"10.0.0.5:5432":            "10.0.0.5:5432",
		"[2001:DB8::1]:443":        "[2001:db8::1]:443",
		"[2001:db8::1]":            "2001:db8::1",
		"api.example.com:0":        "invalid",
		"api.example.com:070":      "invalid",
		"api.example.com:99999":    "invalid",
		"api.example.com/v1?key=x": "invalid",
		"user@api.example.com:443": "invalid",
		"api example.com:443":      "invalid",
		strings.Repeat("a.", 200):  "invalid",
		"invalid":                  "invalid",
	} {
		got := TargetField(in)
		if got != want {
			t.Errorf("TargetField(%q) = %q, want %q", in, got, want)
		}
		if (Event{Event: EventDenied, Target: got}).Validate() != nil {
			t.Errorf("TargetField(%q) = %q is refused by Validate", in, got)
		}
	}
	for _, bad := range []string{"API.example.com:443", "api.example.com/v1", "api.example.com:070"} {
		if (Event{Event: EventDenied, Target: bad}).Validate() == nil {
			t.Errorf("target %q accepted", bad)
		}
	}
}

func TestDatabaseFieldAdmitsOnlyPlainNames(t *testing.T) {
	for in, want := range map[string]string{
		"":                      "",
		"examplecore":           "examplecore",
		"audit_log-2.v1":        "audit_log-2.v1",
		"has space":             "invalid",
		`quote"d`:               "invalid",
		"line\nbreak":           "invalid",
		strings.Repeat("a", 63): strings.Repeat("a", 63),
		strings.Repeat("a", 64): "invalid",
		"-leading-dash":         "invalid",
	} {
		if got := DatabaseField(in); got != want {
			t.Errorf("DatabaseField(%q) = %q, want %q", in, got, want)
		}
		if got := DatabaseField(in); got != "" && (Event{Event: EventDenied, Database: got}).Validate() != nil {
			t.Errorf("DatabaseField(%q) = %q does not validate", in, got)
		}
	}
	if (Event{Event: EventDenied, Database: "has space"}).Validate() == nil {
		t.Error("a non-canonical database validated")
	}
}

func TestDepartmentFieldIsBoundedText(t *testing.T) {
	for in, want := range map[string]string{
		"":                           "",
		"  Security   &\tIT ":        "Security & IT",
		"Recherche et Développement": "Recherche et Développement",
		`R"D`:                        "invalid",
		`R\D`:                        "invalid",
		"R\u0000D":                   "invalid",
		strings.Repeat("x", 257):     "invalid",
	} {
		if got := DepartmentField(in); got != want {
			t.Errorf("DepartmentField(%q) = %q, want %q", in, got, want)
		}
		if got := DepartmentField(in); got != "" && (Event{Event: EventDenied, RequesterDepartment: got}).Validate() != nil {
			t.Errorf("DepartmentField(%q) = %q does not validate", in, got)
		}
	}
	if (Event{Event: EventDenied, RequesterDepartment: " Security"}).Validate() == nil {
		t.Error("a non-canonical department validated")
	}
}

func TestBranchFieldAdmitsOnlyPlainNames(t *testing.T) {
	for in, want := range map[string]string{
		"":                       "",
		"agent/pool-a/fix-1.2":   "agent/pool-a/fix-1.2",
		"main":                   "main",
		"has space":              "invalid",
		`quote"d`:                "invalid",
		`back\slash`:             "invalid",
		"line\nbreak":            "invalid",
		"caf\u00e9":              "invalid",
		strings.Repeat("b", 255): strings.Repeat("b", 255),
		strings.Repeat("b", 256): "invalid",
	} {
		got := BranchField(in)
		if got != want {
			t.Errorf("BranchField(%q) = %q, want %q", in, got, want)
		}
		if (Event{Event: EventDenied, Branch: got}).Validate() != nil {
			t.Errorf("BranchField(%q) = %q does not validate", in, got)
		}
	}
	if (Event{Event: EventDenied, Branch: "has space"}).Validate() == nil {
		t.Error("a non-canonical branch validated")
	}
}

func TestOperationIsAFixedVocabularyShape(t *testing.T) {
	for _, ok := range []string{"pr.open", "git.fetch", "graphql", "deployments.read", "pr.update_branch", "actions.rerun_failed"} {
		if (Event{Event: EventHTTPRequest, Operation: ok}).Validate() != nil {
			t.Errorf("operation %q refused", ok)
		}
	}
	for _, bad := range []string{"PR.open", "/repos/x", "pr open", "pr..open", ".pr", "a.b.c.d.e"} {
		if (Event{Event: EventHTTPRequest, Operation: bad}).Validate() == nil {
			t.Errorf("operation %q accepted", bad)
		}
	}
}

// A row written under an older MAC version that later gains a field only a
// newer version covers still verifies its MAC, since the old input leaves the
// field out; only the version's field check catches it. Each trail here is a
// genuine one at that version, with nothing newer after it.
func TestOlderRowsCannotGainNewerFields(t *testing.T) {
	t.Cleanup(func() { writeMACVersion = MACVersionCurrent })
	for version, field := range map[int]string{
		0:  `"decision":"entitled"`,
		2:  `"kid":"k1"`,
		3:  `"serial":"1a"`,
		4:  `"target":"example.com:443"`,
		5:  `"operation":"pr.open"`,
		6:  `"branch":"main"`,
		7:  `"source":"AUTOMATIONS"`,
		8:  `"path":"/example.v1.Reads/ReadRows"`,
		9:  `"graphqlErrors":"FORBIDDEN@node"`,
		10: `"cause":"dial_timeout"`,
		11: `"match":"` + strings.Repeat("ab", 32) + `"`,
		12: `"upstreamMessage":"Update is not a fast forward"`,
	} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			writeMACVersion = version
			f := newFixture(t)
			f.session(t, 1)
			f.checkpoint(t)
			out := f.out.String()
			if report := verify(t, f.verifier(), out); len(report.Findings) != 0 {
				t.Fatalf("untouched v%d trail: %v", version, kinds(report))
			}
			const open = `"event":"session_open"`
			if !strings.Contains(out, open) {
				t.Fatal("trail has no session_open row")
			}
			edited := strings.Replace(out, open, open+","+field, 1)
			if report := verify(t, f.verifier(), edited); !hasKind(report, FindingEdit) {
				t.Fatalf("v%d row gained %s unnoticed: %v", version, field, kinds(report))
			}
		})
	}
}

// A row's path is the path as sent, printable and bounded; anything else is
// "invalid", and only canonical paths validate.
func TestPathFieldIsBoundedAndCanonical(t *testing.T) {
	for in, want := range map[string]string{
		"":                                     "",
		"/example.v1.Reads/ReadRows":           "/example.v1.Reads/ReadRows",
		"/storage/v1/b/bucket/o/teams%2Fq.csv": "/storage/v1/b/bucket/o/teams%2Fq.csv",
		"relative":                             "invalid",
		"/has space":                           "invalid",
		"/quote\"":                             "invalid",
		"/back\\slash":                         "invalid",
		"/café":                                "invalid",
		"/line\nbreak":                         "invalid",
	} {
		if got := PathField(in); got != want {
			t.Errorf("PathField(%q) = %q, want %q", in, got, want)
		}
	}
	long := "/" + strings.Repeat("a", maxPathBytes+10)
	cut := PathField(long)
	if len(cut) != maxPathBytes || !strings.HasSuffix(cut, "...") || PathField(cut) != cut {
		t.Fatalf("long path cut to %d bytes, not canonical", len(cut))
	}
	if (Event{Event: EventHTTPRequest, Path: cut}).Validate() != nil {
		t.Error("a cut path refused")
	}
	if (Event{Event: EventHTTPRequest, Path: long}).Validate() == nil {
		t.Error("an uncut long path validated")
	}
	if (Event{Event: EventHTTPRequest, Path: "/has space"}).Validate() == nil {
		t.Error("a non-canonical path validated")
	}
}

// The error summary names types and paths only, bounded, and a hostile or
// malformed value never reaches the row as sent.
func TestGraphQLErrorsFieldIsBoundedAndNamesNoMessage(t *testing.T) {
	for _, tc := range []struct {
		name  string
		types []string
		paths [][]string
		want  string
	}{
		{"none", nil, nil, ""},
		{"type and path", []string{"FORBIDDEN"}, [][]string{{"node", "commits", "nodes", "0", "commit"}}, "FORBIDDEN@node.commits.nodes.0.commit"},
		{"no path", []string{"NOT_FOUND"}, [][]string{nil}, "NOT_FOUND@-"},
		{"no type", []string{""}, nil, "UNKNOWN@-"},
		{"message-shaped type", []string{"Resource not accessible by integration"}, nil, "INVALID@-"},
		{"odd segment", []string{"X"}, [][]string{{"a b", "", "ok"}}, "X@*.*.ok"},
		{"long segment", []string{"X"}, [][]string{{strings.Repeat("a", 41)}}, "X@*"},
	} {
		if got := GraphQLErrorsField(tc.types, tc.paths); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
	many := make([]string, 30)
	for i := range many {
		many[i] = "FORBIDDEN"
	}
	got := GraphQLErrorsField(many, nil)
	if !strings.HasSuffix(got, ",+22") || strings.Count(got, "FORBIDDEN@-") != 8 || len(got) > maxGraphQLErrorsBytes+8 {
		t.Errorf("30 errors: %q", got)
	}
	long := make([][]string, 3)
	for i := range long {
		long[i] = make([]string, 20)
		for j := range long[i] {
			long[i][j] = strings.Repeat("a", 30)
		}
	}
	if got := GraphQLErrorsField([]string{"X", "X", "X"}, long); len(got) > maxGraphQLErrorsBytes+8 {
		t.Errorf("long paths: %d bytes", len(got))
	}
}

// A cause is one of the fixed codes, so no error text can enter the row.
func TestCauseIsAFixedCode(t *testing.T) {
	for _, ok := range Causes {
		if (Event{Event: EventHTTPResponse, Cause: ok}).Validate() != nil {
			t.Errorf("cause %q refused", ok)
		}
	}
	for _, bad := range []string{"dial tcp 10.0.0.1:443: i/o timeout", "Dial_Timeout", "timeout"} {
		if (Event{Event: EventHTTPResponse, Cause: bad}).Validate() == nil {
			t.Errorf("cause %q accepted", bad)
		}
	}
}

func TestMessageFieldIsPrintableAndBounded(t *testing.T) {
	for in, want := range map[string]string{
		"":                       "",
		"  Update failed.\n":     "Update failed.",
		"tab\there \u00e9":       "tab here ?",
		strings.Repeat("a", 300): strings.Repeat("a", 197) + "...",
	} {
		got := MessageField(in)
		if got != want || MessageField(got) != got {
			t.Errorf("MessageField(%.20q) = %.30q, want %.30q", in, got, want)
		}
		if (Event{Event: EventHTTPResponse, UpstreamMessage: got}).Validate() != nil {
			t.Errorf("a field value %.20q was refused", got)
		}
	}
	if (Event{Event: EventHTTPResponse, UpstreamMessage: "has\nnewline"}).Validate() == nil {
		t.Error("an unbounded message validated")
	}
}
