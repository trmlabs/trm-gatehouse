package leakcheck

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Names that must not appear, by the SHA-256 of the lowercase token, so this
// file does not publish them itself. A token is a run of letters, digits, "_"
// and "-", so a dotted host is checked one label at a time. An IPv4 range in
// CIDR form is checked whole.
var deniedTokens = map[string]string{
	"ca67af247429a62b379e673e63927761de1dbbff441abc4805a0a060d4d33ff6": "internal domain",
	"e14b2129a1f577184e79a136d011d4a904319500b7cbc952a6d6e03da7fb7eee": "cloud project",
	"a5a8fc7454bdd02eeb587646d619058976b9fccaf3c9aa56789945982318b3d2": "cluster name",
	"d6da43666eba5f72fb8c94ce207ca26d99ba0c1c660a29ce662ff7126dfb107a": "cloud project",
	"c1b6f329020c381ed2c45886e7d0a65157c5a0f401aa28c120cc6bf198ca31d7": "cloud project",
	"20c2f2ca25d854774a621dd06194a34d56cc181343bdce1fa59eb4d9bccb888b": "cloud project",
	"5c0a45da8c29b9287b06ab5feb512e46ec57f45d5d70bcaaedb31aa01762d812": "storage bucket",
	"4fe221c0146513fb74b5221101fd68c6ceb344fa5ff20d3e08466e2c4acb4a60": "cloud folder or profile",
	"7a25af561965d253eff5c923926827a9c2eb6f9143399b8339f28d7ba64fae53": "cloud folder or profile",
	"3f2a67eb77e5c4cc0844a333e83c6fb22ca99cc8cb2d8cdbda0e36fd0c9a76f7": "cloud folder",
	"990b28759b479807a2eecaed2889608fc57b544873e3c218c0ab0eeda5a12400": "cloud folder",
	"8fc9fc91d827821d3370a922c662f5f1054192edd751c5a7d6500f68c8b6e6c3": "Vault auth mount",
	"d471b2c4834d7787014c8b163377b03726d05e0dfc2d8e77c86ecf141d3785c2": "identity client ID",
	"6c8c06f39af92c31cff20e3514897d0668ef6dd1e4d9154db8b172b6ea96820e": "identity organization ID",
	"146299597a5acd470406558c4a50f109243c41061193ff34a064f9de87cfe25c": "internal repository",
	"bb605219226a8c52f42316811b09914f6879a125832754bc31d47c1555624d1e": "cluster name",
	"97746ee30cae484c081177f12324cd6f54537969b15120fd0bf41199ab334232": "internal repository",
	"9ae3dc92e9137517495dc1c656a048f7f763a6057235d38d1b4d867c102eb723": "internal repository",
	"264cc08778738997d728a1cecd8fa8b04c3d7a126324935415e29e50adc54d10": "internal repository",
	"c4e2ac731a84381767ee0a18af86d2b90cea120a1555d1ebe170dc6e83218845": "internal repository",
	"5a942b56ec3b77561facb25a2fde6812fc7c79df61c6a76842eaaab0374da783": "database name",
	"66b21d0fc0ed0d31c17b602e8949519e492eeca2c817abd8698399c4b58315bb": "Terraform module",
	"23e2d8e3ea0806799a7048cc65f86fd36f9476edffdc87a32057ae7c9a655550": "Vault auth mount",
	"59cb8ef0cbd82e937750dca3f1be6b7288ea1890060b76fa08f2c580bc0077d4": "Vault auth mount",
	"b89e09a93cb2570fdbe167d4c2ddd40b83b1008053de8692f161462d6f694edf": "Vault path",
	"d897cc5356b8aa87160de3573b756069b708b15f64f13824176c8d22b3843923": "Vault Transit key",
	"5634bab52c3bf5c18feefbea5c969c17e0f38c851f4bf1df9f8fd4f9ebb17049": "Vault path",
	"4d23f28f1cfbca6596ecd33143e4f990d0781a26a4c9c39f321c7ed9d8496097": "Kubernetes namespace",
	"daa2445ec56aa583042f054770e54a49968017781a2f70858404751f0d93d9ba": "Kubernetes namespace",
	"c835c4c852650903560865dab425a5aaa1bc10c60d8db63680cddd240e281105": "Kubernetes namespace",
	"964ee147cd75f9cdf4a2f5795cb83c0f70a25f9f0c21d4e4981537859fda463b": "harness profile",
	"6b96e09376668e07db22c2123f36bd9df0df1a3fa45c0d79611f978357a3f791": "harness profile",
	"cfa8abfd49ebf537d1e8d294f4cbc3790ffeace0861094ed1026bd9e3458c753": "image repository",
	"b092e7144150b49ea4acf5949946896a35a96d6fe8c147c54d6f45f60a5b1c9f": "Terraform resource",
	"b1b40dcb8dfab37fbc24c70e867c80c9bb9fb04a5d0ea6ec9e3ef8672d8ec396": "network vendor",
	"1df409158dbb0528d87b5fd13e5aa1f88aed66c54078b5b5afb223959eec48bd": "network range",
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
		sum := sha256.Sum256([]byte(strings.ToLower(tok)))
		if kind, ok := deniedTokens[hex.EncodeToString(sum[:])]; ok {
			found = append(found, kind)
		}
	}
	return found
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
	if got := cidr.FindAllString(`"sourceCIDRs": ["192.0.2.0/28", "10.0.0.1"]`, -1); len(got) != 1 || got[0] != "192.0.2.0/28" {
		t.Errorf("CIDR ranges found = %q, want only 192.0.2.0/28", got)
	}
	if len(problems("SECURITY.md", securityContact)) != 0 {
		t.Error("the security contact is flagged in SECURITY.md")
	}
}
