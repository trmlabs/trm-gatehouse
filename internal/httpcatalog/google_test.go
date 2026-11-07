package httpcatalog

import (
	"encoding/json"
	"strings"
	"testing"
)

const (
	googleTestEmail = "worker-one@example-project.iam.gserviceaccount.com"
	googleTestID    = "104857263948571029384"
)

func googleBlock(id, email, uniqueID string) map[string]any {
	return map[string]any{"id": id, "name": id, "owner": "platform-team", "entries": []any{"tracker"},
		"googleServiceAccount": map[string]any{"email": email, "uniqueID": uniqueID}}
}

func TestGoogleAgentLookup(t *testing.T) {
	catalog, err := parseCatalog(t, gumloopCatalog(
		googleBlock("one", googleTestEmail, googleTestID),
		googleBlock("two", "worker-two@example-project.iam.gserviceaccount.com", "204857263948571029384")))
	if err != nil {
		t.Fatal(err)
	}
	for uniqueID, want := range map[string]string{googleTestID: "one", "204857263948571029384": "two", "304857263948571029384": "", "": ""} {
		a, pool, ok := catalog.GoogleAgent(uniqueID)
		if (want != "") != ok || a.ID != want || (ok && pool != "example-workers") {
			t.Errorf("%q: %q %q %v", uniqueID, a.ID, pool, ok)
		}
	}
	if _, _, ok := catalog.GoogleAgent(googleTestEmail); ok {
		t.Error("a block was found by email")
	}
	if _, _, ok := catalog.StaticAgent("one"); ok {
		t.Error("a Google block is reachable by static token")
	}
	if _, _, ok := catalog.GumloopAgent("one", ""); ok {
		t.Error("a Google block is reachable as a Gumloop org")
	}
}

func TestGoogleAgentNeedsAStaticTokenHarness(t *testing.T) {
	c := gumloopCatalog(googleBlock("one", googleTestEmail, googleTestID))
	c["harnesses"] = c["harnesses"].([]any)[:len(c["harnesses"].([]any))-1]
	catalog, err := parseCatalog(t, c)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := catalog.GoogleAgent(googleTestID); ok {
		t.Error("served by a pool with no static-token harness")
	}
}

func TestGoogleBlockValidation(t *testing.T) {
	withToken := googleBlock("both", googleTestEmail, googleTestID)
	withToken["tokenSHA256"], withToken["expires"] = []any{hashOf("both.x")}, soonText()
	withGumloop := googleBlock("gl", googleTestEmail, googleTestID)
	withGumloop["gumloop"] = map[string]any{"orgID": "org-1"}
	withSubagents := googleBlock("subs", googleTestEmail, googleTestID)
	withSubagents["subagents"] = 2
	emailOwner := googleBlock("mail", googleTestEmail, googleTestID)
	emailOwner["owner"] = "team@example.com"
	unknownField := googleBlock("extra", googleTestEmail, googleTestID)
	unknownField["googleServiceAccount"].(map[string]any)["project"] = "example-project"
	const second = "worker-two@example-project.iam.gserviceaccount.com"
	for name, tc := range map[string]struct {
		blocks []map[string]any
		ok     bool
		want   string
	}{
		"one block":                       {[]map[string]any{googleBlock("a", googleTestEmail, googleTestID)}, true, ""},
		"two accounts":                    {[]map[string]any{googleBlock("a", googleTestEmail, googleTestID), googleBlock("b", second, "204857263948571029384")}, true, ""},
		"default compute account":         {[]map[string]any{googleBlock("a", "123456789012-compute@developer.gserviceaccount.com", googleTestID)}, true, ""},
		"app engine account":              {[]map[string]any{googleBlock("a", "example-project@appspot.gserviceaccount.com", googleTestID)}, true, ""},
		"a token and a Google identity":   {[]map[string]any{withToken}, false, "ways to prove one identity"},
		"gumloop and a Google identity":   {[]map[string]any{withGumloop}, false, "ways to prove one identity"},
		"subagents on a Google identity":  {[]map[string]any{withSubagents}, false, "subagents is for"},
		"an owner that is an email":       {[]map[string]any{emailOwner}, false, "not an email address"},
		"an unknown field":                {[]map[string]any{unknownField}, false, "unknown field"},
		"the same unique ID twice":        {[]map[string]any{googleBlock("a", googleTestEmail, googleTestID), googleBlock("b", second, googleTestID)}, false, "name the same google service account"},
		"the same email twice":            {[]map[string]any{googleBlock("a", googleTestEmail, googleTestID), googleBlock("b", googleTestEmail, "204857263948571029384")}, false, "name the same google service account"},
		"no unique ID":                    {[]map[string]any{googleBlock("a", googleTestEmail, "")}, false, "numeric unique ID"},
		"a unique ID that is not numeric": {[]map[string]any{googleBlock("a", googleTestEmail, "abc-123")}, false, "numeric unique ID"},
		"a short unique ID":               {[]map[string]any{googleBlock("a", googleTestEmail, "123")}, false, "numeric unique ID"},
		"no email":                        {[]map[string]any{googleBlock("a", "", googleTestID)}, false, "lower-case service account email"},
		"upper case":                      {[]map[string]any{googleBlock("a", "Worker-one@example-project.iam.gserviceaccount.com", googleTestID)}, false, "lower-case service account email"},
		"a person's email":                {[]map[string]any{googleBlock("a", "person@example.com", googleTestID)}, false, "lower-case service account email"},
		"a wildcard":                      {[]map[string]any{googleBlock("a", "*@example-project.iam.gserviceaccount.com", googleTestID)}, false, "lower-case service account email"},
		"a suffix trick":                  {[]map[string]any{googleBlock("a", googleTestEmail+".evil.example", googleTestID)}, false, "lower-case service account email"},
	} {
		_, err := parseCatalog(t, gumloopCatalog(tc.blocks...))
		if (err == nil) != tc.ok || (err != nil && !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
}

func TestTolerantLoadDropsEveryHolderOfAConflictingGoogleBinding(t *testing.T) {
	const second = "worker-two@example-project.iam.gserviceaccount.com"
	for name, blocks := range map[string][]map[string]any{
		"one unique ID": {googleBlock("a", googleTestEmail, googleTestID), googleBlock("b", second, googleTestID)},
		"one email":     {googleBlock("a", googleTestEmail, googleTestID), googleBlock("b", googleTestEmail, "204857263948571029384")},
	} {
		blocks = append(blocks, googleBlock("keeper", "worker-three@example-project.iam.gserviceaccount.com", "304857263948571029384"))
		data, err := json.Marshal(gumloopCatalog(blocks...))
		if err != nil {
			t.Fatal(err)
		}
		c, dropped, err := ParseTolerant(data)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if _, ok := c.Automation("a"); ok {
			t.Errorf("%s: block a was kept", name)
		}
		if _, ok := c.Automation("b"); ok {
			t.Errorf("%s: block b was kept", name)
		}
		if _, ok := c.Automation("keeper"); !ok {
			t.Errorf("%s: the unrelated block was dropped", name)
		}
		if got := droppedNames(dropped); !strings.Contains(got, "automation:a") || !strings.Contains(got, "automation:b") || strings.Contains(got, "keeper") {
			t.Errorf("%s: dropped %q", name, got)
		}
		for _, d := range dropped {
			if strings.Contains(d.Reason, googleTestID) || strings.Contains(d.Reason, "example-project") {
				t.Errorf("%s: the drop reason echoes an identifier: %q", name, d.Reason)
			}
		}
	}
}
