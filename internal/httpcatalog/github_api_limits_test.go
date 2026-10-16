package httpcatalog

import (
	"strings"
	"testing"
)

// An unset limit takes the github-api default; any value written in the
// catalog is kept as written, including one equal to the git default.
func TestGitHubAPILimitsKeepExplicitValues(t *testing.T) {
	for _, tc := range []struct {
		name, limits      string
		request, response int64
	}{
		{"unset", ``, 1 << 20, 4 << 30},
		{"response at the git default", `"maxResponseBytes":4294967296,`, 1 << 20, 4 << 30},
		{"smaller response", `"maxResponseBytes":8388608,`, 1 << 20, 8 << 20},
		{"largest response", `"maxResponseBytes":8589934592,`, 1 << 20, 8 << 30},
		{"largest request", `"maxRequestBytes":16777216,`, 16 << 20, 4 << 30},
		{"both", `"maxRequestBytes":65536,"maxResponseBytes":1048576,`, 64 << 10, 1 << 20},
	} {
		doc := strings.Replace(apiEntry, `"pools"`, tc.limits+`"pools"`, 1)
		c, err := Parse([]byte(`{"entries":[` + doc + `]}`))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if e := c.Entries()[0]; e.MaxRequestBytes != tc.request || e.MaxResponseBytes != tc.response {
			t.Errorf("%s: limits %d %d, want %d %d", tc.name, e.MaxRequestBytes, e.MaxResponseBytes, tc.request, tc.response)
		}
	}
	for name, limits := range map[string]string{
		// Refused like any request above 16 MiB, not quietly lowered to 1 MiB.
		"request at the git default": `"maxRequestBytes":1073741824,`,
		"response above 8 GiB":       `"maxResponseBytes":8589934593,`,
		"negative response":          `"maxResponseBytes":-1,`,
		"negative request":           `"maxRequestBytes":-1,`,
	} {
		doc := strings.Replace(apiEntry, `"pools"`, limits+`"pools"`, 1)
		if _, err := Parse([]byte(`{"entries":[` + doc + `]}`)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
