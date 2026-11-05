package httpcatalog

import (
	"strings"
	"testing"
)

func TestExternalPoolHoldsNoEntries(t *testing.T) {
	pools := `{"name":"p","namespace":"n","serviceAccount":"s"},{"name":"team-a","namespace":"o","serviceAccount":"s","ceiling":"external"}`
	if _, err := Parse([]byte(`{"pools":[` + pools + `],"entries":[{` + entryBase + `}]}`)); err != nil {
		t.Fatalf("external pool with no entries refused: %v", err)
	}
	for name, grant := range map[string]string{
		"T0 entry":   `"pools":["p","team-a"]`,
		"only grant": `"pools":["team-a"]`,
	} {
		entry := strings.Replace(entryBase, `"pools":["p"]`, grant, 1)
		if _, err := Parse([]byte(`{"pools":[` + pools + `],"entries":[{` + entry + `}]}`)); err == nil {
			t.Errorf("%s granted to an external pool", name)
		}
	}
	for name, pool := range map[string]string{
		"with a person":   `{"name":"team-a","namespace":"o","serviceAccount":"s","ceiling":"external","identity":"claude-session","ccpoolID":"ccpool_abc"}`,
		"with a workload": `{"name":"team-a","namespace":"o","serviceAccount":"s","ceiling":"external","identity":"workload"}`,
		"unknown ceiling": `{"name":"team-a","namespace":"o","serviceAccount":"s","ceiling":"T-1"}`,
	} {
		if _, err := Parse([]byte(`{"pools":[{"name":"p","namespace":"n","serviceAccount":"s"},` + pool + `],"entries":[{` + entryBase + `}]}`)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
