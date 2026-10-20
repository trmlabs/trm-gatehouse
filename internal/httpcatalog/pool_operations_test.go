package httpcatalog

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// appOperations are example-app's operations in poolOperationsCatalog.
const appOperations = `,"operations":["pr.open","pr.read","pr.list","pr.comment","dispatch","graphql"],"dispatchEvents":["preview-build"]`

// poolOperationsCatalog is a github-api entry on a person pool and an
// Automation pool, with two repositories: example-app has appOperations and
// carries repoFields, and docs lists neither pool in poolOperations.
func poolOperationsCatalog(repoFields string) string {
	return poolOperationsCatalogWith(appOperations + repoFields)
}

// poolOperationsCatalogWith is poolOperationsCatalog with all of example-app's
// fields after its access given.
func poolOperationsCatalogWith(appFields string) string {
	return `{"pools":[
	  {"name":"people","namespace":"n","serviceAccount":"people","identity":"cursor-session"},
	  {"name":"automations","namespace":"n","serviceAccount":"automations","identity":"cursor-automation"}],
	 "entries":[{"name":"github-api","host":"api.github.com","kind":"github-api","pools":["people","automations"],
	  "git":{"appID":7,"installationID":42,"repos":[
	   {"repo":"example-org/example-app","access":"write"` + appFields + `},
	   {"repo":"example-org/docs","access":"write","operations":["pr.read","pr.comment"]}]}}]}`
}

func apiMatch(t *testing.T, c Catalog, method, path, pool string) (GitRequest, error) {
	t.Helper()
	g, ok, err := c.GitHubAPIMatch("api.github.com", 443, method, path, "", pool)
	if !ok {
		t.Fatalf("%s %s: no github-api entry", method, path)
	}
	return g, err
}

// An Automation pool reaches no operation on a repository whose line does not
// name it; once named, exactly its own. A person pool keeps the repository's
// operations unless named, and is then narrowed the same way.
func TestPoolOperationsNarrowEachPool(t *testing.T) {
	routes := map[string][2]string{
		"pr.open":    {"POST", "/repos/example-org/example-app/pulls"},
		"pr.read":    {"GET", "/repos/example-org/example-app/pulls/1"},
		"pr.list":    {"GET", "/repos/example-org/example-app/pulls"},
		"pr.comment": {"POST", "/repos/example-org/example-app/issues/1/comments"},
		"dispatch":   {"POST", "/repos/example-org/example-app/dispatches"},
	}
	check := func(t *testing.T, c Catalog, pool string, want ...string) {
		t.Helper()
		for op, route := range routes {
			_, err := apiMatch(t, c, route[0], route[1], pool)
			if allowed := contains(want, op); (err == nil) != allowed || (!allowed && !errors.Is(err, ErrPool)) {
				t.Errorf("%s %s: %v, want allowed %v", pool, op, err, allowed)
			}
		}
		repos, _ := c.GitHubAPIRepos("api.github.com", 443, pool)
		for _, g := range repos {
			if g.Repo.Repo == "example-org/example-app" && g.Repo.Allows("graphql") != contains(want, "graphql") {
				t.Errorf("%s over GraphQL: allowed %v", pool, g.Repo.Allows("graphql"))
			}
		}
	}
	c, err := Parse([]byte(poolOperationsCatalog("")))
	if err != nil {
		t.Fatal(err)
	}
	check(t, c, "automations")
	check(t, c, "people", "pr.open", "pr.read", "pr.list", "pr.comment", "dispatch", "graphql")
	// The token scopes an Automation pool's GraphQL repository would need are
	// none: GitHubAPIRepos hands back the narrowed repository.
	repos, _ := c.GitHubAPIRepos("api.github.com", 443, "automations")
	for _, g := range repos {
		if g.Repo.GrantsScope("pull-requests") || g.Repo.GrantsScope("contents-write") {
			t.Errorf("an unnamed Automation pool keeps scopes on %s", g.Repo.Repo)
		}
	}

	c, err = Parse([]byte(poolOperationsCatalog(`,"poolOperations":{"automations":["pr.read","dispatch"],"people":["pr.read","graphql"]}`)))
	if err != nil {
		t.Fatal(err)
	}
	check(t, c, "automations", "pr.read", "dispatch")
	check(t, c, "people", "pr.read", "graphql")
	// docs names no pool: the person pool keeps its operations there, the
	// Automation pool still has none.
	if _, err := apiMatch(t, c, "GET", "/repos/example-org/docs/pulls/1", "people"); err != nil {
		t.Errorf("person pool on docs: %v", err)
	}
	if _, err := apiMatch(t, c, "GET", "/repos/example-org/docs/pulls/1", "automations"); !errors.Is(err, ErrPool) {
		t.Errorf("Automation pool on docs: %v", err)
	}
	// A dispatch's reach is the pool's own: its pull request prefixes and the
	// shared ones, never another pool's.
	c, err = Parse([]byte(poolOperationsCatalog(`,"pullRequestPrefixes":["factory/"],"poolPullRequestPrefixes":{"automations":["automation/"],"people":["person/"]},` +
		`"poolOperations":{"automations":["pr.comment","dispatch"]}`)))
	if err != nil {
		t.Fatal(err)
	}
	g, err := apiMatch(t, c, "POST", "/repos/example-org/example-app/dispatches", "automations")
	if err != nil || strings.Join(g.HeadPrefixes, ",") != "factory/,automation/" || g.Route != "dispatch" || g.Permissions != "contents-write" {
		t.Fatalf("dispatch match: %v %+v", err, g)
	}
}

func TestPoolOperationsRefusals(t *testing.T) {
	for name, fields := range map[string]string{
		"an unknown operation":                 `,"poolOperations":{"automations":["pr.merge"]}`,
		"a duplicate operation":                `,"poolOperations":{"automations":["pr.read","pr.read"]}`,
		"an operation the repository lacks":    `,"poolOperations":{"automations":["actions.read"]}`,
		"a pool the entry does not grant":      `,"poolOperations":{"strangers":["pr.read"]}`,
		"a pool with no operations":            `,"poolOperations":{"automations":[]}`,
		"no pools at all":                      `,"poolOperations":{}`,
		"null":                                 `,"poolOperations":null`,
		"a pool listed with null":              `,"poolOperations":{"automations":null}`,
		"an operation not a string":            `,"poolOperations":{"automations":[7]}`,
		"an operation spelled in another case": `,"poolOperations":{"automations":["PR.READ"]}`,
	} {
		if _, err := Parse([]byte(poolOperationsCatalog(fields))); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// With no operations listed, the defaults are the repository's set.
	if _, err := Parse([]byte(poolOperationsCatalogWith(`,"poolOperations":{"automations":["pr.read"]}`))); err != nil {
		t.Errorf("an operation from the defaults: %v", err)
	}
	if _, err := Parse([]byte(poolOperationsCatalogWith(`,"poolOperations":{"automations":["pr.list"]}`))); err == nil {
		t.Error("an operation outside the defaults: accepted")
	}
	// A git entry takes no operations of any kind.
	git := strings.Replace(gitEntry, `{"repo":"example-org/docs","access":"read"}`, `{"repo":"example-org/docs","access":"read","poolOperations":{"pool-a":["pr.read"]}}`, 1)
	if _, err := Parse([]byte(`{"entries":[` + git + `]}`)); err == nil || !strings.Contains(err.Error(), "pool operations") {
		t.Errorf("a git entry with poolOperations: %v", err)
	}
}

// A repository line whose poolOperations fails validation, as a field from a
// newer broker would, drops only its entry: the rest of the version applies,
// a removal included.
func TestSourceDropsABadPoolOperationsEntryAndAppliesTheRest(t *testing.T) {
	good := poolOperationsCatalog(`,"poolOperations":{"automations":["pr.read"]}`)
	withRetired := strings.Replace(good, `"entries":[`, `"entries":[`+strings.Replace(entryNamed("retired", "retired.example.com"), `"pools":["pool-a"]`, `"pools":["people"]`, 1)+`,`, 1)
	loader := &scriptedLoader{doc: withRetired, version: 1}
	source, err := Start(context.Background(), loader.load, nil, nil)
	if err != nil || entryNames(source.Current()) != "github-api,retired" {
		t.Fatalf("start: %v %q", err, entryNames(source.Current()))
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	var rejected []error
	go source.Watch(ctx, 5*time.Millisecond, loader.load, func(_ int, err error) {
		mu.Lock()
		rejected = append(rejected, err)
		mu.Unlock()
	})
	// Version 2 removes retired and gives the Automation pool an operation the
	// repository does not have.
	bad := strings.Replace(good, `["pr.read"]`, `["actions.read"]`, 1)
	bad = strings.Replace(bad, `"entries":[`, `"entries":[`+strings.Replace(entryNamed("kept", "kept.example.com"), `"pools":["pool-a"]`, `"pools":["people"]`, 1)+`,`, 1)
	loader.set(bad, 2, nil)
	waitFor(t, "version 2", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return source.Version() == 2 || len(rejected) > 0
	})
	mu.Lock()
	defer mu.Unlock()
	if len(rejected) > 0 {
		t.Fatalf("version 2 refused: %v", rejected[0])
	}
	c := source.Current()
	if entryNames(c) != "kept" || droppedNames(source.Dropped()) != "entry:github-api" || !strings.Contains(source.Dropped()[0].Reason, "actions.read") {
		t.Fatalf("in force %q, dropped %+v", entryNames(c), source.Dropped())
	}
	if c.HasHost("retired.example.com", 443) {
		t.Fatal("the removed entry is still reachable")
	}
	if _, ok, _ := c.GitHubAPIMatch("api.github.com", 443, "GET", "/repos/example-org/example-app/pulls/1", "", "automations"); ok {
		t.Fatal("the dropped github-api entry still matches")
	}
}
