package leakcheck

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Names that must not appear, by the SHA-256 of the lowercase token. The list
// is the operator's, so it lives outside this repository: CI reads it from a
// repository secret into LEAKCHECK_DENIED_TOKENS. A token is a run of
// letters, digits, "_" and "-", so a dotted host is checked one label at a
// time. Every run of a token's consecutive "-" or "_" separated parts is
// checked too, so a name with a prefix or suffix attached is still caught. An
// IPv4 range in CIDR form is checked whole.
//
// The setting holds entries separated by ";" or new lines, each the hex
// SHA-256, then "whole" for a name that is also part of the broker's own
// constants and so is matched as a whole token only, then what the name is,
// such as "cloud project". The hashes are unsalted and the names short, so
// anyone holding the list can confirm a guess.
const (
	deniedEnv = "LEAKCHECK_DENIED_TOKENS"
	// requiredEnv is "true" wherever CI has the secret (pushes, and pull
	// requests from this repository), so the check never passes there with an
	// empty list. A fork's pull request gets no secrets and checks the
	// patterns below only; the push to main checks the list.
	requiredEnv = "LEAKCHECK_REQUIRED"
)

var (
	deniedTokens   = map[string]string{}
	wholeTokenOnly = map[string]bool{}
	sha256Hex      = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// parseDenied reads the LEAKCHECK_DENIED_TOKENS format. An error names the
// entry by number only, so a log never shows the list.
func parseDenied(list string) (map[string]string, map[string]bool, error) {
	denied, whole := map[string]string{}, map[string]bool{}
	for i, entry := range strings.FieldsFunc(list, func(r rune) bool { return r == ';' || r == '\n' }) {
		fields := strings.Fields(entry)
		if len(fields) == 0 {
			continue
		}
		if !sha256Hex.MatchString(fields[0]) {
			return nil, nil, fmt.Errorf("entry %d does not start with a lower-case hex SHA-256", i+1)
		}
		kind := fields[1:]
		if len(kind) > 0 && kind[0] == "whole" {
			whole[fields[0]], kind = true, kind[1:]
		}
		denied[fields[0]] = "internal name"
		if len(kind) > 0 {
			denied[fields[0]] = strings.Join(kind, " ")
		}
	}
	return denied, whole, nil
}

func loadDenied(t *testing.T) {
	t.Helper()
	list := os.Getenv(deniedEnv)
	if strings.TrimSpace(list) == "" {
		if os.Getenv(requiredEnv) == "true" {
			t.Fatalf("%s is empty: set the repository secret of that name", deniedEnv)
		}
		t.Logf("%s is unset: checking hostnames, addresses and IDs only", deniedEnv)
		return
	}
	denied, whole, err := parseDenied(list)
	if err != nil {
		t.Fatalf("%s: %v", deniedEnv, err)
	}
	deniedTokens, wholeTokenOnly = denied, whole
}

var (
	token = regexp.MustCompile(`[A-Za-z0-9_-]{3,}`)
	// Hosts under the operator's domains. The annotation keys the broker reads
	// (gatehouse.trmlabs.com/...) are names, not hosts, and stay allowed.
	internalHost = regexp.MustCompile(`(?i)[a-z0-9-]+(\.[a-z0-9-]+)*\.trmlabs(-[a-z]+)?\.[a-z]{2,}`)
	otherDomain  = regexp.MustCompile(`(?i)trmlabs-[a-z]+\.[a-z]{2,}`)
	email        = regexp.MustCompile(`(?i)[a-z0-9._%+-]*@-?trmlabs\.[a-z]{2,}`)
	// An identity organization ID has the shape org_ and 16 characters; tests
	// use short synthetic ones.
	orgID = regexp.MustCompile(`\borg_[A-Za-z0-9]{16}\b`)
	cidr  = regexp.MustCompile(`\b\d{1,3}(\.\d{1,3}){3}/\d{1,2}\b`)
	// Service accounts are named in an example-* project only.
	serviceAccount = regexp.MustCompile(`[a-z0-9-]+@([a-z][a-z0-9-]*)\.iam\.gserviceaccount\.com`)
)

// The repository's published security contact is the one allowed address.
const securityContact = "security@trmlabs.com"

func TestNoInternalNames(t *testing.T) {
	loadDenied(t)
	root, files := trackedFiles(t)
	for _, name := range files {
		if name == "internal/leakcheck/leakcheck_test.go" || skipped(name) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil || bytes.IndexByte(data[:min(len(data), 8000)], 0) >= 0 {
			continue
		}
		scanner := bufio.NewScanner(bytes.NewReader(data))
		scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
		for n := 1; scanner.Scan(); n++ {
			for _, problem := range problems(name, scanner.Text()) {
				t.Errorf("%s:%d: %s; use an example.com style placeholder", name, n, problem)
			}
		}
	}
}

func problems(name, line string) []string {
	var found []string
	for _, loc := range internalHost.FindAllStringIndex(line, -1) {
		if !strings.EqualFold(line[loc[0]:loc[1]], "gatehouse.trmlabs.com") || !strings.HasPrefix(line[loc[1]:], "/") {
			found = append(found, "internal hostname")
		}
	}
	if otherDomain.MatchString(line) {
		found = append(found, "internal domain")
	}
	for _, m := range email.FindAllString(line, -1) {
		if name != "SECURITY.md" || !strings.EqualFold(m, securityContact) {
			found = append(found, "internal email address")
		}
	}
	if orgID.MatchString(line) {
		found = append(found, "identity organization ID")
	}
	for _, m := range serviceAccount.FindAllStringSubmatch(line, -1) {
		if !strings.HasPrefix(m[1], "example") {
			found = append(found, "cloud service account")
		}
	}
	for _, tok := range append(token.FindAllString(line, -1), cidr.FindAllString(line, -1)...) {
		whole := strings.ToLower(tok)
		for _, run := range runs(whole) {
			sum := sha256.Sum256([]byte(run))
			key := hex.EncodeToString(sum[:])
			if kind, ok := deniedTokens[key]; ok && (run == whole || !wholeTokenOnly[key]) {
				found = append(found, kind)
			}
		}
	}
	return found
}

// runs returns every run of tok's consecutive parts, split at "-" and "_":
// for "a-b_c" that is a, a-b, a-b_c, b, b_c and c. A token with no separator
// is its own only run.
func runs(tok string) []string {
	var starts, ends []int
	start := 0
	for i := 0; i <= len(tok); i++ {
		if i == len(tok) || tok[i] == '-' || tok[i] == '_' {
			if i > start {
				starts, ends = append(starts, start), append(ends, i)
			}
			start = i + 1
		}
	}
	var out []string
	for i := range starts {
		for j := i; j < len(ends); j++ {
			out = append(out, tok[starts[i]:ends[j]])
		}
	}
	return out
}

func skipped(name string) bool {
	base := filepath.Base(name)
	return base == "go.sum" || base == "package-lock.json" || strings.Contains(name, "node_modules/")
}

func trackedFiles(t *testing.T) (string, []string) {
	t.Helper()
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		// CI always runs from a checkout, so a skip there would pass with
		// nothing scanned.
		if os.Getenv("CI") != "" {
			t.Fatalf("git rev-parse: %v", err)
		}
		t.Skip("not a git checkout")
	}
	root := strings.TrimSpace(string(out))
	cmd := exec.Command("git", "ls-files", "-z")
	cmd.Dir = root
	list, err := cmd.Output()
	if err != nil {
		t.Fatalf("git ls-files: %v", err)
	}
	var files []string
	for _, f := range strings.Split(string(list), "\x00") {
		if f != "" {
			files = append(files, f)
		}
	}
	return root, files
}

func TestProblems(t *testing.T) {
	for line, want := range map[string]bool{
		`"host": "api.staging.example.com"`:                  false,
		`"host": "api.corp.trmlabs.com"`:                     true,
		`"https://api.corp.trmlabs.com/v1/x"`:                true,
		`annotation gatehouse.trmlabs.com/requester`:         false,
		`"https://trmlabs.com/email"`:                        false,
		`alice@example.com`:                                  false,
		`alice@trmlabs.com`:                                  true,
		`"orgID": "org_synthetic"`:                           false,
		`"orgID": "org_ABCDEFGHIJKLMNOP"`:                    true,
		`bq-cases@example-analytics.iam.gserviceaccount.com`: false,
		`bq-cases@acme-analytics.iam.gserviceaccount.com`:    true,
		`"sourceCIDRs": ["192.0.2.0/28"]`:                    false,
	} {
		if got := len(problems("x.go", line)) > 0; got != want {
			t.Errorf("%s: flagged %v, want %v", line, got, want)
		}
	}
	sum := sha256.Sum256([]byte("198.51.100.0/24"))
	deniedTokens[hex.EncodeToString(sum[:])] = "test range"
	defer delete(deniedTokens, hex.EncodeToString(sum[:]))
	if len(problems("x.go", `"sourceCIDRs": ["198.51.100.0/24"]`)) == 0 {
		t.Error("a denied range is not flagged")
	}
	if got := cidr.FindAllString(`"sourceCIDRs": ["192.0.2.0/28", "10.0.0.1"]`, -1); len(got) != 1 || got[0] != "192.0.2.0/28" {
		t.Errorf("CIDR ranges found = %q, want only 192.0.2.0/28", got)
	}
	if len(problems("SECURITY.md", securityContact)) != 0 {
		t.Error("the security contact is flagged in SECURITY.md")
	}
	name := sha256.Sum256([]byte("denied-name"))
	deniedTokens[hex.EncodeToString(name[:])] = "test name"
	defer delete(deniedTokens, hex.EncodeToString(name[:]))
	for line, want := range map[string]bool{
		`pod: denied-name`:          true,
		`pod: Denied-Name-7d9`:      true,
		`pod: old-denied-name`:      true,
		`pod: x_denied-name_backup`: true,
		`pod: denied-names`:         false,
		`pod: denied`:               false,
		`pod: deniedname-7d9`:       false,
	} {
		if got := len(problems("x.go", line)) > 0; got != want {
			t.Errorf("%s: flagged %v, want %v", line, got, want)
		}
	}
	wholeTokenOnly[hex.EncodeToString(name[:])] = true
	if len(problems("x.go", `pod: denied-name`)) == 0 || len(problems("x.go", `pod: denied-name-v1`)) != 0 {
		t.Error("a whole-token-only name is not matched as a whole token only")
	}
	delete(wholeTokenOnly, hex.EncodeToString(name[:]))
	if got := runs("a-b_c"); strings.Join(got, " ") != "a a-b a-b_c b b_c c" {
		t.Errorf("runs(a-b_c) = %q", got)
	}
}

func TestParseDenied(t *testing.T) {
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
	denied, whole, err := parseDenied(a + " cloud project;\n" + b + " whole Vault path\n\n;")
	if err != nil || len(denied) != 2 || denied[a] != "cloud project" || denied[b] != "Vault path" || whole[a] || !whole[b] {
		t.Fatalf("parseDenied = %v, %v, %v", denied, whole, err)
	}
	if denied, _, err := parseDenied(a); err != nil || denied[a] != "internal name" {
		t.Errorf("an entry with no kind = %v, %v", denied, err)
	}
	for _, bad := range []string{"secret-name cloud project", strings.ToUpper(a) + " cloud project", a[:63]} {
		if _, _, err := parseDenied(a + ";" + bad); err == nil || !strings.Contains(err.Error(), "entry 2") || strings.Contains(err.Error(), bad) {
			t.Errorf("%q: err = %v, want entry 2 named without its value", bad, err)
		}
	}
}
