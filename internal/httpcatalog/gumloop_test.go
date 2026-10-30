package httpcatalog

import "testing"

func gumloopCatalog(blocks ...map[string]any) map[string]any {
	c := staticTokenCatalog()
	list := c["automations"].([]any)[:2] // drop the token block
	for _, b := range blocks {
		list = append(list, b)
	}
	c["automations"] = list
	return c
}

func gumloopBlock(id, org, owner string) map[string]any {
	g := map[string]any{"orgID": org}
	if owner != "" {
		g["ownerID"] = owner
	}
	return map[string]any{"id": id, "name": id, "owner": "platform-team", "entries": []any{"tracker"}, "gumloop": g}
}

func TestGumloopAgentLookup(t *testing.T) {
	catalog, err := parseCatalog(t, gumloopCatalog(gumloopBlock("org-wide", "org-1", ""), gumloopBlock("one-owner", "org-1", "owner-7"), gumloopBlock("other", "org-2", "")))
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct{ org, owner, want string }{
		"the owner's own block":     {"org-1", "owner-7", "one-owner"},
		"the org's block":           {"org-1", "owner-8", "org-wide"},
		"the org's block, no owner": {"org-1", "", "org-wide"},
		"another org":               {"org-2", "owner-7", "other"},
		"an unlisted org":           {"org-3", "", ""},
		"no org":                    {"", "owner-7", ""},
	} {
		a, pool, ok := catalog.GumloopAgent(tc.org, tc.owner)
		if (tc.want != "") != ok || a.ID != tc.want || (ok && pool != "example-workers") {
			t.Errorf("%s: %q %q %v", name, a.ID, pool, ok)
		}
	}
	// A Gumloop block is not reachable by a static token's id, nor is a token block by Gumloop.
	if _, _, ok := catalog.StaticAgent("org-wide"); ok {
		t.Error("a Gumloop block is reachable by static token")
	}
}

func TestGumloopAgentNeedsAStaticTokenHarness(t *testing.T) {
	c := gumloopCatalog(gumloopBlock("org-wide", "org-1", ""))
	c["harnesses"] = c["harnesses"].([]any)[:len(c["harnesses"].([]any))-1]
	catalog, err := parseCatalog(t, c)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := catalog.GumloopAgent("org-1", ""); ok {
		t.Error("served by a pool with no static-token harness")
	}
}

func TestGumloopBlockValidation(t *testing.T) {
	withToken := gumloopBlock("both", "org-1", "")
	withToken["tokenSHA256"], withToken["expires"] = []any{hashOf("both.x")}, soonText()
	withSubagents := gumloopBlock("subs", "org-1", "")
	withSubagents["subagents"] = 2
	for name, tc := range map[string]struct {
		blocks []map[string]any
		ok     bool
	}{
		"subagents on a Gumloop identity": {[]map[string]any{withSubagents}, false},
		"one block":                       {[]map[string]any{gumloopBlock("a", "org-1", "")}, true},
		"an org and an owner each":        {[]map[string]any{gumloopBlock("a", "org-1", ""), gumloopBlock("b", "org-1", "o1"), gumloopBlock("c", "org-1", "o2")}, true},
		"a token and a Gumloop identity":  {[]map[string]any{withToken}, false},
		"the same org twice":              {[]map[string]any{gumloopBlock("a", "org-1", ""), gumloopBlock("b", "org-1", "")}, false},
		"the same org and owner twice":    {[]map[string]any{gumloopBlock("a", "org-1", "o1"), gumloopBlock("b", "org-1", "o1")}, false},
		"an empty org":                    {[]map[string]any{gumloopBlock("a", "", "")}, false},
		"an org with a space":             {[]map[string]any{gumloopBlock("a", "org 1", "")}, false},
		"an owner with a slash":           {[]map[string]any{gumloopBlock("a", "org-1", "o/1")}, false},
	} {
		if _, err := parseCatalog(t, gumloopCatalog(tc.blocks...)); (err == nil) != tc.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
}
