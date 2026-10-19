package httpcatalog

import (
	"fmt"
	"strings"
	"testing"
)

func TestRequesterSegment(t *testing.T) {
	for _, tc := range []struct{ kind, subject, want string }{
		{"person", "alice@example.com", "alice@example.com"},
		{"person", "Alice.Smith+ci@Example.com", "alice.smith+ci@example.com"},
		{"automation", "auto-1", "automation-auto-1"},
		{"automation", "Nightly.Fix_2", "automation-Nightly.Fix_2"},
		// No segment: a kind that names no person or Automation, a person
		// without exactly one "@", an Automation id holding one, and names git
		// cannot carry in a branch.
		{"agent", "agent:helper", ""},
		{"workload", "", ""},
		{"none", "", ""},
		{"person", "alice", ""},
		{"person", "a@b@example.com", ""},
		{"person", "", ""},
		{"automation", "", ""},
		{"automation", "x@example.com", ""},
		{"person", "o'brien@example.com", ""},
		{"person", "a..b@example.com", ""},
		{"person", "alice@example.lock", ""},
		{"person", "alice@example.", ""},
		{"person", ".alice@example.com", ""},
		{"person", "al ice@example.com", ""},
		{"person", strings.Repeat("a", 200) + "@example.com", ""},
	} {
		if got := RequesterSegment(tc.kind, tc.subject); got != tc.want {
			t.Errorf("%s %q: %q, want %q", tc.kind, tc.subject, got, tc.want)
		}
	}
}

// requesterCatalog is a catalog with a person pool, an Automation pool and a
// pool that names no one, and one git entry whose example-repo binding
// carries prefixes.
func requesterCatalog(pools, prefixes string) string {
	return `{"pools":[
	  {"name":"people","namespace":"n","serviceAccount":"people","identity":"cursor-session"},
	  {"name":"automations","namespace":"n","serviceAccount":"automations","identity":"cursor-automation"},
	  {"name":"plain","namespace":"n","serviceAccount":"plain"}],
	 "entries":[{"name":"github","host":"github.com","kind":"git","pools":` + pools + `,
	  "git":{"appID":7,"installationID":42,"repos":[{"repo":"example-org/example-repo","access":"write",` + prefixes + `}]}}]}`
}

// A {requester} push prefix narrows to each requester's own branches, and to
// none for a request that names no one; other prefixes stay shared, after the
// requester's own.
func TestRequesterPrefixesNarrowToTheRequester(t *testing.T) {
	c, err := Parse([]byte(requesterCatalog(`["people","automations"]`,
		`"refPrefixes":["refs/heads/factory/"],"poolRefPrefixes":{"people":["refs/heads/cursor/people/{requester}/"],"automations":["refs/heads/cursor/automations/{requester}/"]}`)))
	if err != nil {
		t.Fatal(err)
	}
	push, _, err := c.GitMatch("github.com", 443, "POST", "/example-org/example-repo.git/git-receive-pack", "", "people")
	if err != nil || !push.Limited || fmt.Sprint(push.RefPrefixes) != "[refs/heads/factory/ refs/heads/cursor/people/{requester}/]" {
		t.Fatalf("match: %v %+v", err, push)
	}
	for segment, want := range map[string]string{
		"alice@example.com": "[refs/heads/cursor/people/alice@example.com/ refs/heads/factory/]",
		"":                  "[refs/heads/factory/]",
	} {
		if got := push.ForRequester(segment); fmt.Sprint(got.RefPrefixes) != want || !got.Limited {
			t.Errorf("%q: %v", segment, got.RefPrefixes)
		}
	}
	// A fetch is not narrowed: reads stay per pool.
	if fetch, _, err := c.GitMatch("github.com", 443, "POST", "/example-org/example-repo.git/git-upload-pack", "", "people"); err != nil || fetch.Limited || len(fetch.ForRequester("").RefPrefixes) != 0 {
		t.Errorf("fetch: %v %+v", err, fetch)
	}
}

// A github-api entry's pull request reach follows the same narrowing: a
// requester opens and writes only on their own branches, and the repository's
// pull request prefixes stay open to every requester of the pool.
func TestRequesterPrefixesNarrowPullRequestReach(t *testing.T) {
	git := `{"name":"github","host":"github.com","kind":"git","pools":["people"],"git":{"appID":7,"installationID":42,"repos":[
	  {"repo":"example-org/example-repo","access":"write","poolRefPrefixes":{"people":["refs/heads/cursor/people/{requester}/"]}}]}}`
	api := `{"name":"github-api","host":"api.github.com","kind":"github-api","pools":["people"],"git":{"appID":7,"installationID":42,"repos":[
	  {"repo":"example-org/example-repo","access":"write","operations":["pr.open","pr.read","pr.comment","pr.update_branch"],"pullRequestPrefixes":["factory/"]}]}}`
	c, err := Parse([]byte(`{"pools":[{"name":"people","namespace":"n","serviceAccount":"people","identity":"cursor-session"}],"entries":[` + git + `,` + api + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ method, path, before, after string }{
		{"POST", "/repos/example-org/example-repo/pulls", "[cursor/people/{requester}/]", "[cursor/people/bob@example.com/]"},
		{"POST", "/repos/example-org/example-repo/issues/7/comments", "[cursor/people/{requester}/ factory/]", "[cursor/people/bob@example.com/ factory/]"},
		{"PUT", "/repos/example-org/example-repo/pulls/7/update-branch", "[cursor/people/{requester}/]", "[cursor/people/bob@example.com/]"},
	} {
		m, _, err := c.GitHubAPIMatch("api.github.com", 443, tc.method, tc.path, "", "people")
		if err != nil || fmt.Sprint(m.HeadPrefixes) != tc.before || fmt.Sprint(m.ForRequester("bob@example.com").HeadPrefixes) != tc.after {
			t.Errorf("%s %s: %v %v", tc.method, tc.path, err, m.HeadPrefixes)
		}
	}
	// GraphQL's repositories carry the same prefixes.
	if g, err := c.GitHubAPIRepository("api.github.com", 443, "example-org/example-repo", "people"); err != nil ||
		fmt.Sprint(g.ForRequester("bob@example.com").HeadPrefixes) != "[cursor/people/bob@example.com/ factory/]" {
		t.Errorf("graphql: %v %v", err, g.HeadPrefixes)
	}
}

func TestRequesterPrefixShapes(t *testing.T) {
	for name, tc := range map[string]struct {
		pools, prefixes string
		ok              bool
	}{
		"per pool":               {`["people"]`, `"poolRefPrefixes":{"people":["refs/heads/cursor/people/{requester}/"]}`, true},
		"shared":                 {`["people","automations"]`, `"refPrefixes":["refs/heads/cursor/{requester}/"]`, true},
		"an Automation pool":     {`["automations"]`, `"poolRefPrefixes":{"automations":["refs/heads/cursor/automations/{requester}/"]}`, true},
		"two pools apart":        {`["people","automations"]`, `"poolRefPrefixes":{"people":["refs/heads/cursor/people/{requester}/"],"automations":["refs/heads/cursor/automations/{requester}/"]}`, true},
		"beside a shared prefix": {`["people"]`, `"poolRefPrefixes":{"people":["refs/heads/cursor/people/{requester}/","refs/heads/factory/"]}`, true},

		"not at the end":           {`["people"]`, `"poolRefPrefixes":{"people":["refs/heads/cursor/{requester}/people/"]}`, false},
		"without its slash":        {`["people"]`, `"poolRefPrefixes":{"people":["refs/heads/cursor/people/{requester}"]}`, false},
		"twice":                    {`["people"]`, `"poolRefPrefixes":{"people":["refs/heads/{requester}/{requester}/"]}`, false},
		"part of a segment":        {`["people"]`, `"poolRefPrefixes":{"people":["refs/heads/cursor/people-{requester}/"]}`, false},
		"right under refs/heads":   {`["people"]`, `"poolRefPrefixes":{"people":["refs/heads/{requester}/"]}`, false},
		"a tag":                    {`["people"]`, `"poolRefPrefixes":{"people":["refs/tags/people/{requester}/"]}`, false},
		"a misspelled token":       {`["people"]`, `"poolRefPrefixes":{"people":["refs/heads/cursor/people/{person}/"]}`, false},
		"a pool that names no one": {`["plain"]`, `"poolRefPrefixes":{"plain":["refs/heads/cursor/plain/{requester}/"]}`, false},
		"shared with such a pool":  {`["people","plain"]`, `"refPrefixes":["refs/heads/cursor/{requester}/"]`, false},
		// No prefix anyone else holds may reach into a requester's branches:
		// not the same pool's, not a shared one, not another pool's.
		"the pool's own prefix above it": {`["people"]`, `"poolRefPrefixes":{"people":["refs/heads/cursor/people/{requester}/","refs/heads/cursor/"]}`, false},
		"the pool's own prefix below it": {`["people"]`, `"poolRefPrefixes":{"people":["refs/heads/cursor/people/{requester}/","refs/heads/cursor/people/shared/"]}`, false},
		"a shared prefix above it":       {`["people"]`, `"refPrefixes":["refs/heads/cursor/"],"poolRefPrefixes":{"people":["refs/heads/cursor/people/{requester}/"]}`, false},
		"a shared one below it":          {`["people"]`, `"refPrefixes":["refs/heads/cursor/{requester}/","refs/heads/cursor/x/"]`, false},
		"another pool's prefix in it":    {`["people","automations"]`, `"poolRefPrefixes":{"people":["refs/heads/cursor/{requester}/"],"automations":["refs/heads/cursor/automations/"]}`, false},
		"two of the pool's own":          {`["people"]`, `"poolRefPrefixes":{"people":["refs/heads/cursor/{requester}/","refs/heads/cursor/people/{requester}/"]}`, false},
	} {
		_, err := Parse([]byte(requesterCatalog(tc.pools, tc.prefixes)))
		if (err == nil) != tc.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Without defined pools no pool names its requester.
	undefined := `{"entries":[{"name":"github","host":"github.com","kind":"git","pools":["people"],"git":{"appID":7,"installationID":42,
	  "repos":[{"repo":"example-org/example-repo","access":"write","refPrefixes":["refs/heads/cursor/{requester}/"]}]}}]}`
	if _, err := Parse([]byte(undefined)); err == nil {
		t.Error("a {requester} prefix without defined pools loaded")
	}
	// A tolerant load drops only that entry.
	data := strings.Replace(requesterCatalog(`["plain"]`, `"poolRefPrefixes":{"plain":["refs/heads/cursor/plain/{requester}/"]}`),
		`"entries":[`, `"entries":[{"name":"docs","host":"docs.example.com","pathPrefixes":["/"],"methods":["GET"],"header":"Authorization",
		"placeholder":"__vault_DOCS__","key":{"mount":"gatehouse","path":"vendors/docs","field":"key"},"pools":["plain"]},`, 1)
	c, dropped, err := ParseTolerant([]byte(data))
	if err != nil || len(dropped) != 1 || dropped[0].Name != "github" || !strings.Contains(dropped[0].Reason, "{requester}") || len(c.entries) != 1 {
		t.Errorf("tolerant: %v %+v", err, dropped)
	}
}

// No pull request prefix may reach into a {requester} push prefix, the same
// pool's included: it would let one requester comment on, edit, label or
// mark ready another's pull requests.
func TestPullRequestPrefixesStayOutOfRequesterBranches(t *testing.T) {
	entries := func(prs string) string {
		return `{"pools":[{"name":"people","namespace":"n","serviceAccount":"people","identity":"cursor-session"}],"entries":[
		{"name":"github","host":"github.com","kind":"git","pools":["people"],"git":{"appID":7,"installationID":42,"repos":[
		  {"repo":"example-org/example-repo","access":"write","poolRefPrefixes":{"people":["refs/heads/cursor/people/{requester}/","refs/heads/factory/"]}}]}},
		{"name":"github-api","host":"api.github.com","kind":"github-api","pools":["people"],"git":{"appID":7,"installationID":42,"repos":[
		  {"repo":"example-org/example-repo","access":"write","operations":["pr.read","pr.comment"],` + prs + `}]}}]}`
	}
	for prs, ok := range map[string]bool{
		`"pullRequestPrefixes":["factory/"]`:                      true, // shared on purpose
		`"pullRequestPrefixes":["review/"]`:                       true,
		`"pullRequestPrefixes":["cursor/people/"]`:                false,
		`"pullRequestPrefixes":["cursor/"]`:                       false,
		`"pullRequestPrefixes":["cursor/people/shared/"]`:         false,
		`"poolPullRequestPrefixes":{"people":["cursor/people/"]}`: false,
	} {
		_, err := Parse([]byte(entries(prs)))
		if (err == nil) != ok {
			t.Errorf("%s: %v", prs, err)
		}
		if !ok {
			if c, dropped, err := ParseTolerant([]byte(entries(prs))); err != nil || len(dropped) != 2 || len(c.entries) != 0 {
				t.Errorf("tolerant %s: %v %+v", prs, err, dropped)
			}
		}
	}
}

// A repository with {requester} push prefixes is listed by one git entry
// only: a pool's pull request reach joins every git entry's push prefixes for
// the repository, so a prefix in a second entry, on another port, could reach
// into each requester's branches.
func TestRequesterRepositoryInOneGitEntry(t *testing.T) {
	catalog := func(first, second string) string {
		return `{"pools":[{"name":"people","namespace":"n","serviceAccount":"people","identity":"cursor-session"}],"entries":[
		{"name":"github","host":"github.com","kind":"git","pools":["people"],"git":{"appID":7,"installationID":42,"repos":[
		  {"repo":"example-org/example-repo","access":"write",` + first + `}]}},
		{"name":"github-alt","host":"github.com","port":8443,"kind":"git","pools":["people"],"git":{"appID":7,"installationID":42,"repos":[
		  {"repo":"Example-Org/example-repo","access":"write",` + second + `}]}}]}`
	}
	requester := `"poolRefPrefixes":{"people":["refs/heads/cursor/people/{requester}/"]}`
	for name, tc := range map[string]struct {
		first, second string
		ok            bool
	}{
		"neither per requester": {`"refPrefixes":["refs/heads/factory/"]`, `"refPrefixes":["refs/heads/cursor/"]`, true},
		"the first":             {requester, `"refPrefixes":["refs/heads/cursor/"]`, false},
		"the second":            {`"refPrefixes":["refs/heads/factory/"]`, requester, false},
		"both":                  {requester, requester, false},
	} {
		_, err := Parse([]byte(catalog(tc.first, tc.second)))
		if (err == nil) != tc.ok {
			t.Errorf("%s: %v", name, err)
		}
		if !tc.ok {
			if c, dropped, err := ParseTolerant([]byte(catalog(tc.first, tc.second))); err != nil || len(dropped) != 2 || len(c.entries) != 0 {
				t.Errorf("tolerant %s: %v %+v", name, err, dropped)
			}
		}
	}
}

// Only a pool that names who runs each request takes a {requester} prefix.
func TestRequesterPoolIdentities(t *testing.T) {
	e := Entry{Kind: "git", Git: &GitBinding{Repos: []GitRepo{{Repo: "example-org/example-repo", Access: "write",
		PoolRefPrefixes: map[string][]string{"p": {"refs/heads/cursor/p/{requester}/"}}}}}}
	for identity, ok := range map[string]bool{
		"claude-session": true, "cursor-session": true, "attested-person": true, IdentityCursorAutomation: true,
		"workload": false, "none": false, "": false,
	} {
		if err := requesterGrantable(e, "p", Pool{Identity: identity}, true); (err == nil) != ok {
			t.Errorf("%q: %v", identity, err)
		}
	}
	if err := requesterGrantable(e, "p", Pool{Identity: "cursor-session"}, false); err == nil {
		t.Error("an undefined pool took a {requester} prefix")
	}
	// Another pool's {requester} prefix asks nothing of this one.
	if err := requesterGrantable(e, "q", Pool{Identity: "workload"}, true); err != nil {
		t.Error(err)
	}
}
