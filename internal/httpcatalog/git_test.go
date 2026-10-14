package httpcatalog

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

const gitEntry = `{"name":"github","host":"github.com","kind":"git","pools":["pool-a"],
	"git":{"appID":7,"installationID":42,"repos":[
		{"repo":"TRMLabs/example-app","access":"write","refPrefixes":["refs/heads/cursor/"]},
		{"repo":"trmlabs/docs","access":"read"}]}}`

func TestGitEntriesParseAndReject(t *testing.T) {
	c, err := Parse([]byte(`{"entries":[` + gitEntry + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	e := c.Entries()[0]
	if e.Git.Repos[0].Repo != "trmlabs/example-app" || e.MaxRequestBytes != 1<<30 || e.MaxResponseBytes != 4<<30 || !c.HasHost("github.com", 443) {
		t.Fatalf("normalized: %+v", e)
	}
	for name, doc := range map[string]string{
		"header fields":      strings.Replace(gitEntry, `"kind":"git"`, `"kind":"git","header":"Authorization"`, 1),
		"no app":             strings.Replace(gitEntry, `"appID":7`, `"appID":0`, 1),
		"bad access":         strings.Replace(gitEntry, `"access":"read"`, `"access":"admin"`, 1),
		"read with prefixes": strings.Replace(gitEntry, `"access":"read"`, `"access":"read","refPrefixes":["refs/heads/x/"]`, 1),
		"bad ref prefix":     strings.Replace(gitEntry, `refs/heads/cursor/`, `heads/cursor`, 1),
		"traversal repo":     strings.Replace(gitEntry, `trmlabs/docs`, `trmlabs/..`, 1),
		"dot git repo":       strings.Replace(gitEntry, `trmlabs/docs`, `trmlabs/docs.git`, 1),
		"duplicate repo":     strings.Replace(gitEntry, `trmlabs/docs`, `trmlabs/example-app`, 1),
		"unknown kind":       strings.Replace(gitEntry, `"kind":"git"`, `"kind":"ssh"`, 1),
		"git without kind":   strings.Replace(gitEntry, `"kind":"git",`, ``, 1),
	} {
		if _, err := Parse([]byte(`{"entries":[` + doc + `]}`)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	header := strings.Replace(validEntry, `"serpapi.com"`, `"github.com"`, 1)
	if _, err := Parse([]byte(`{"entries":[` + gitEntry + `,` + header + `]}`)); err == nil {
		t.Error("git and header entries mixed on one host")
	}
	twin := strings.Replace(strings.Replace(gitEntry, `"github"`, `"github-2"`, 1), `trmlabs/docs`, `trmlabs/other`, 1)
	if _, err := Parse([]byte(`{"entries":[` + gitEntry + `,` + twin + `]}`)); err == nil {
		t.Error("a repository bound twice")
	}
}

func TestGitMatchEndpointsAndAccess(t *testing.T) {
	c, err := Parse([]byte(`{"entries":[` + gitEntry + `,` + validEntry + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		method, path, query, pool, repo string
		write                           bool
		err                             error
	}{
		{"GET", "/trmlabs/example-app.git/info/refs", "service=git-upload-pack", "pool-a", "trmlabs/example-app", false, nil},
		{"POST", "/TRMLabs/example-app/git-upload-pack", "", "pool-a", "trmlabs/example-app", false, nil},
		{"GET", "/trmlabs/example-app.git/info/refs", "service=git-receive-pack", "pool-a", "trmlabs/example-app", true, nil},
		{"POST", "/trmlabs/example-app.git/git-receive-pack", "", "pool-a", "trmlabs/example-app", true, nil},
		{"POST", "/trmlabs/docs.git/git-upload-pack", "", "pool-a", "trmlabs/docs", false, nil},
		{"POST", "/trmlabs/docs.git/git-receive-pack", "", "pool-a", "trmlabs/docs", true, ErrReadOnly},
		{"GET", "/trmlabs/docs.git/info/refs", "service=git-receive-pack", "pool-a", "trmlabs/docs", true, ErrReadOnly},
		{"POST", "/trmlabs/example-app.git/git-upload-pack", "", "pool-b", "trmlabs/example-app", false, ErrPool},
		{"POST", "/trmlabs/secret.git/git-upload-pack", "", "pool-a", "", false, ErrUnlisted},
		{"GET", "/trmlabs/example-app.git/info/refs", "service=git-upload-pack&x=1", "pool-a", "", false, ErrUnlisted},
		{"GET", "/trmlabs/example-app.git/info/lfs/objects/batch", "", "pool-a", "", false, ErrUnlisted},
		{"GET", "/trmlabs/example-app.git/git-upload-pack", "", "pool-a", "", false, ErrMethod},
		{"GET", "/trmlabs/example-app", "", "pool-a", "", false, ErrUnlisted},
	} {
		got, ok, err := c.GitMatch("github.com", 443, tc.method, tc.path, tc.query, tc.pool)
		if !ok || !errors.Is(err, tc.err) || (tc.repo != "" && (got.Repo.Repo != tc.repo || got.Write != tc.write)) {
			t.Errorf("%s %s?%s: ok=%v repo=%q write=%v err=%v", tc.method, tc.path, tc.query, ok, got.Repo.Repo, got.Write, err)
		}
	}
	if _, ok, _ := c.GitMatch("serpapi.com", 443, "GET", "/search", "", "pool-a"); ok {
		t.Fatal("header host routed to git")
	}
	if e, err := c.Match("github.com", 443, "POST", "/trmlabs/example-app.git/git-upload-pack", "pool-a"); e != nil || !errors.Is(err, ErrUnlisted) {
		t.Fatal("git entry matched as a header entry")
	}
}

const apiEntry = `{"name":"github-api","host":"api.github.com","kind":"github-api","pools":["pool-a"],
	"git":{"appID":7,"installationID":42,"repos":[{"repo":"trmlabs/example-app","access":"write"}]}}`

func TestGitHubAPIEntries(t *testing.T) {
	c, err := Parse([]byte(`{"entries":[` + gitEntry + `,` + apiEntry + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	if e := c.Entries()[1]; e.MaxRequestBytes != 1<<20 || e.MaxResponseBytes != 8<<20 {
		t.Fatalf("api limits: %d %d", e.MaxRequestBytes, e.MaxResponseBytes)
	}
	for name, doc := range map[string]string{
		"read access":  strings.Replace(apiEntry, `"access":"write"`, `"access":"read"`, 1),
		"ref prefixes": strings.Replace(apiEntry, `"access":"write"`, `"access":"write","refPrefixes":["refs/heads/x/"]`, 1),
		"large body":   strings.Replace(apiEntry, `"pools"`, `"maxRequestBytes":33554432,"pools"`, 1),
	} {
		if _, err := Parse([]byte(`{"entries":[` + doc + `]}`)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	for _, tc := range []struct {
		method, path, query, pool string
		err                       error
	}{
		{"POST", "/repos/trmlabs/example-app/pulls", "", "pool-a", nil},
		{"POST", "/repos/TRMLabs/example-app/issues/12/comments", "", "pool-a", nil},
		{"POST", "/repos/trmlabs/example-app/pulls/12/comments", "", "pool-a", nil},
		{"POST", "/repos/trmlabs/example-app/pulls/12/comments/99/replies", "", "pool-a", nil},
		{"POST", "/repos/trmlabs/example-app/pulls/12/reviews", "", "pool-a", ErrUnlisted},
		{"PUT", "/repos/trmlabs/example-app/pulls/12/merge", "", "pool-a", ErrUnlisted},
		{"POST", "/repos/trmlabs/example-app/issues/abc/comments", "", "pool-a", ErrUnlisted},
		{"POST", "/repos/trmlabs/example-app/git/refs", "", "pool-a", ErrUnlisted},
		{"POST", "/repos/trmlabs/other/pulls", "", "pool-a", ErrUnlisted},
		{"POST", "/repos/trmlabs/example-app/pulls", "per_page=1", "pool-a", ErrUnlisted},
		// The default operations (pr.open, pr.read, pr.comment) open no other route.
		{"GET", "/repos/trmlabs/example-app/pulls", "", "pool-a", ErrMethod},
		{"DELETE", "/repos/trmlabs/example-app/pulls", "", "pool-a", ErrMethod},
		{"GET", "/repos/trmlabs/example-app/pulls/12", "", "pool-a", nil},
		{"PATCH", "/repos/trmlabs/example-app/pulls/12", "", "pool-a", ErrMethod},
		{"POST", "/repos/trmlabs/example-app/pulls/12/ready", "", "pool-a", ErrUnlisted},
		{"GET", "/repos/trmlabs/example-app/issues/12/comments", "", "pool-a", ErrMethod},
		{"PATCH", "/repos/trmlabs/example-app/issues/comments/5", "", "pool-a", ErrUnlisted},
		{"POST", "/repos/trmlabs/example-app/issues/12/labels", "", "pool-a", ErrUnlisted},
		{"POST", "/repos/trmlabs/example-app/dispatches", "", "pool-a", ErrUnlisted},
		{"GET", "/repos/trmlabs/example-app/actions/runs", "", "pool-a", ErrUnlisted},
		{"GET", "/repos/trmlabs/example-app/deployments", "", "pool-a", ErrUnlisted},
		{"PATCH", "/repos/trmlabs/example-app/issues/12", "", "pool-a", ErrUnlisted},
		// pr.read also lists a pull request's files and compares two refs: code
		// the pool can already clone.
		{"GET", "/repos/trmlabs/example-app/pulls/12/files", "", "pool-a", nil},
		{"GET", "/repos/trmlabs/example-app/compare/main...feature", "", "pool-a", nil},
		{"GET", "/repos/trmlabs/example-app/commits/abc1234/status", "", "pool-a", ErrUnlisted},
		{"GET", "/repos/trmlabs/example-app/check-runs/9/annotations", "", "pool-a", ErrUnlisted},
		{"POST", "/repos/trmlabs/example-app/pulls", "", "pool-b", ErrPool},
		{"POST", "/user/repos", "", "pool-a", ErrUnlisted},
	} {
		if _, ok, err := c.GitHubAPIMatch("api.github.com", 443, tc.method, tc.path, tc.query, tc.pool); !ok || !errors.Is(err, tc.err) {
			t.Errorf("%s %s: ok=%v err=%v", tc.method, tc.path, ok, err)
		}
	}
	if _, ok, _ := c.GitHubAPIMatch("github.com", 443, "POST", "/repos/trmlabs/example-app/pulls", "", "pool-a"); ok {
		t.Fatal("git host routed to the API")
	}
	// Opening a pull request carries the pool's own push prefixes; other routes do not.
	if m, _, _ := c.GitHubAPIMatch("api.github.com", 443, "POST", "/repos/trmlabs/example-app/pulls", "", "pool-a"); !m.OpensPullRequest || fmt.Sprint(m.HeadPrefixes) != "[cursor/]" {
		t.Fatalf("create: %+v", m)
	}
	if m, _, _ := c.GitHubAPIMatch("api.github.com", 443, "POST", "/repos/trmlabs/example-app/issues/7/comments", "", "pool-a"); m.OpensPullRequest || m.CommentsOn != 7 || fmt.Sprint(m.HeadPrefixes) != "[cursor/]" {
		t.Fatalf("comment: %+v", m)
	}
	if m, _, _ := c.GitHubAPIMatch("api.github.com", 443, "POST", "/repos/trmlabs/example-app/pulls/8/comments/99/replies", "", "pool-a"); m.CommentsOn != 8 {
		t.Fatalf("reply: %+v", m)
	}
	if _, _, err := c.GitHubAPIMatch("api.github.com", 443, "POST", "/repos/trmlabs/example-app/issues/007/comments", "", "pool-a"); !errors.Is(err, ErrUnlisted) {
		t.Fatalf("a padded number matched: %v", err)
	}
	if m, _, _ := c.GitHubAPIMatch("api.github.com", 443, "GET", "/repos/trmlabs/example-app/pulls/1", "", "pool-a"); m.Write {
		t.Fatalf("read marked as a write: %+v", m)
	}
	// Without a git entry for the pool, there is no branch to open one from.
	alone, err := Parse([]byte(`{"entries":[` + apiEntry + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	if m, _, _ := alone.GitHubAPIMatch("api.github.com", 443, "POST", "/repos/trmlabs/example-app/pulls", "", "pool-a"); !m.OpensPullRequest || len(m.HeadPrefixes) != 0 {
		t.Fatalf("no git entry: %+v", m)
	}
}

// Labels, repository dispatch, Actions and deployments exist only where a
// repository grants them, and pull request prefixes widen which existing pull
// requests a write may act on, never which branch one may be opened from.
func TestGitHubAPIRepositoryGrants(t *testing.T) {
	granted := strings.Replace(apiEntry, `"access":"write"`, `"access":"write","operations":["pr.open","pr.read","pr.list","pr.comment","pr.edit","pr.label","pr.ready","dispatch","actions.read","deployments.read"],"pullRequestPrefixes":["factory/"],"labels":["preview"],"dispatchEvents":["preview-build"]`, 1)
	c, err := Parse([]byte(`{"entries":[` + gitEntry + `,` + granted + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		method, path, query, route, permissions string
		download                                bool
		err                                     error
	}{
		{"GET", "/repos/trmlabs/example-app/pulls", "head=trmlabs:factory/x&state=open", "list-pulls", "pull-requests", false, nil},
		{"GET", "/repos/trmlabs/example-app/pulls", "q=x", "", "", false, ErrUnlisted},
		{"GET", "/repos/trmlabs/example-app/issues/12/comments", "per_page=100&page=2", "list-comments", "pull-requests", false, nil},
		{"PATCH", "/repos/trmlabs/example-app/pulls/12", "", "edit-pull", "pull-requests", false, nil},
		{"PATCH", "/repos/trmlabs/example-app/issues/comments/5", "", "edit-comment", "pull-requests", false, nil},
		{"POST", "/repos/trmlabs/example-app/pulls/12/ready", "", "ready", "pull-requests", false, nil},
		{"POST", "/repos/trmlabs/example-app/issues/12/labels", "", "label", "pull-requests", false, nil},
		{"POST", "/repos/trmlabs/example-app/dispatches", "", "dispatch", "contents-write", false, nil},
		{"GET", "/repos/trmlabs/example-app/actions/runs", "head_sha=abc&per_page=5", "actions", "actions", false, nil},
		{"GET", "/repos/trmlabs/example-app/actions/workflows/eval-replay.yml/runs", "branch=main", "actions", "actions", false, nil},
		{"GET", "/repos/trmlabs/example-app/actions/workflows/123/runs", "", "actions", "actions", false, nil},
		{"GET", "/repos/trmlabs/example-app/actions/runs/9/jobs", "", "actions", "actions", false, nil},
		{"GET", "/repos/trmlabs/example-app/actions/runs/9/artifacts", "name=results", "actions", "actions", false, nil},
		{"GET", "/repos/trmlabs/example-app/actions/runs/9/logs", "", "actions-download", "actions", true, nil},
		{"GET", "/repos/trmlabs/example-app/actions/jobs/9/logs", "", "actions-download", "actions", true, nil},
		{"GET", "/repos/trmlabs/example-app/actions/artifacts/9/zip", "", "actions-download", "actions", true, nil},
		{"GET", "/repos/trmlabs/example-app/deployments", "environment=preview-1&sha=abc", "deployments", "deployments", false, nil},
		{"GET", "/repos/trmlabs/example-app/deployments/4/statuses", "", "deployments", "deployments", false, nil},
		{"GET", "/repos/trmlabs/example-app/actions/runs/9", "exclude_pull_requests=true", "actions", "actions", false, nil},
		{"GET", "/repos/trmlabs/example-app/actions/workflows/ci.yml", "", "actions", "actions", false, nil},
		{"GET", "/repos/trmlabs/example-app/actions/workflows/1234", "", "actions", "actions", false, nil},
		{"GET", "/repos/trmlabs/example-app/commits/0123456789abcdef0123456789abcdef01234567/status", "", "statuses", "statuses", false, nil},
		{"GET", "/repos/trmlabs/example-app/commits/0123abc/statuses", "per_page=100", "statuses", "statuses", false, nil},
		{"GET", "/repos/trmlabs/example-app/commits/0123abc/check-runs", "check_name=unit&filter=latest&per_page=100", "check-runs", "checks", false, nil},
		{"GET", "/repos/trmlabs/example-app/commits/0123abc/check-runs", "check_name=build+%28ubuntu-latest%29", "check-runs", "checks", false, nil},
		{"GET", "/repos/trmlabs/example-app/check-runs/9", "", "check-run", "checks", false, nil},
		{"GET", "/repos/trmlabs/example-app/check-runs/9/annotations", "per_page=100", "check-annotations", "checks", false, nil},
		{"GET", "/repos/trmlabs/example-app/pulls/12/files", "per_page=100&page=2", "pull-files", "pull-requests", false, nil},
		{"GET", "/repos/trmlabs/example-app/compare/staging...0123abc", "", "compare", "pull-requests", false, nil},
		{"GET", "/repos/trmlabs/example-app/compare/main...staging", "per_page=1", "compare", "pull-requests", false, nil},
		{"GET", "/repos/trmlabs/example-app/compare/staging..0123abc", "", "", "", false, ErrUnlisted},
		{"GET", "/repos/trmlabs/example-app/compare/a....b", "", "", "", false, ErrUnlisted},
		{"GET", "/repos/trmlabs/example-app/compare/staging...", "", "", "", false, ErrUnlisted},
		{"GET", "/repos/trmlabs/example-app/commits/main/status", "", "", "", false, ErrUnlisted},
		{"GET", "/repos/trmlabs/example-app/commits/0123abc", "", "", "", false, ErrUnlisted},
		{"POST", "/repos/trmlabs/example-app/statuses/0123abc", "", "", "", false, ErrUnlisted},
		{"POST", "/repos/trmlabs/example-app/check-runs", "", "", "", false, ErrUnlisted},
		{"PATCH", "/repos/trmlabs/example-app/check-runs/9", "", "", "", false, ErrMethod},
		{"GET", "/repos/trmlabs/example-app/actions/runs/9", "exclude_pull_requests=true&x=1", "", "", false, ErrUnlisted},
		{"POST", "/repos/trmlabs/example-app/actions/workflows/ci.yml/dispatches", "", "", "", false, ErrUnlisted},
		{"POST", "/repos/trmlabs/example-app/actions/runs/9/rerun", "", "", "", false, ErrUnlisted},
		{"GET", "/repos/trmlabs/example-app/actions/workflows/../runs", "", "", "", false, ErrUnlisted},
		{"GET", "/repos/trmlabs/example-app/actions/secrets", "", "", "", false, ErrUnlisted},
		{"POST", "/repos/trmlabs/example-app/deployments", "", "", "", false, ErrMethod},
		{"GET", "/repos/trmlabs/example-app/actions/runs", "actor=someone", "", "", false, ErrUnlisted},
	} {
		m, ok, err := c.GitHubAPIMatch("api.github.com", 443, tc.method, tc.path, tc.query, "pool-a")
		if !ok || !errors.Is(err, tc.err) || (err == nil && (m.Route != tc.route || m.Permissions != tc.permissions || m.Download != tc.download)) {
			t.Errorf("%s %s?%s: ok=%v err=%v route=%q permissions=%q download=%v", tc.method, tc.path, tc.query, ok, err, m.Route, m.Permissions, m.Download)
		}
	}
	if m, _, _ := c.GitHubAPIMatch("api.github.com", 443, "POST", "/repos/trmlabs/example-app/pulls", "", "pool-a"); fmt.Sprint(m.HeadPrefixes) != "[cursor/]" {
		t.Errorf("open from a pull request prefix: %+v", m)
	}
	for _, path := range []string{"/repos/trmlabs/example-app/issues/7/labels", "/repos/trmlabs/example-app/pulls/7", "/repos/trmlabs/example-app/pulls/7/ready", "/repos/trmlabs/example-app/issues/7/comments"} {
		method := map[bool]string{true: "PATCH", false: "POST"}[strings.HasSuffix(path, "/7")]
		if m, _, _ := c.GitHubAPIMatch("api.github.com", 443, method, path, "", "pool-a"); m.Target != 7 || fmt.Sprint(m.HeadPrefixes) != "[cursor/ factory/]" {
			t.Errorf("%s %s: %+v", method, path, m)
		}
	}
	if m, _, _ := c.GitHubAPIMatch("api.github.com", 443, "PATCH", "/repos/trmlabs/example-app/issues/comments/5", "", "pool-a"); m.CommentID != 5 || m.Target != 0 || fmt.Sprint(m.HeadPrefixes) != "[cursor/ factory/]" {
		t.Errorf("edit comment: %+v", m)
	}
	for _, scope := range []string{"pull-requests", "contents-write", "actions", "deployments", "checks", "statuses"} {
		if !c.GitGranted(42, "trmlabs/example-app", scope) {
			t.Errorf("GitGranted %s = false", scope)
		}
	}
	if s := c.GitScope(42); len(s.Repos) != 3 || !s.PullRequests || !s.Actions || !s.Deployments || !s.Checks || !s.Statuses {
		t.Errorf("GitScope = %+v", s)
	}
	for name, doc := range map[string]string{
		"operations on a git entry": strings.Replace(gitEntry, `"access":"write"`, `"access":"write","operations":["pr.read"]`, 1),
		"unknown operation":         strings.Replace(apiEntry, `"access":"write"`, `"access":"write","operations":["pr.merge"]`, 1),
		"duplicate operation":       strings.Replace(apiEntry, `"access":"write"`, `"access":"write","operations":["pr.read","pr.read"]`, 1),
		"empty operations":          strings.Replace(apiEntry, `"access":"write"`, `"access":"write","operations":[]`, 1),
		"pr.label without labels":   strings.Replace(apiEntry, `"access":"write"`, `"access":"write","operations":["pr.label"]`, 1),
		"labels without pr.label":   strings.Replace(apiEntry, `"access":"write"`, `"access":"write","labels":["preview"]`, 1),
		"dispatch without events":   strings.Replace(apiEntry, `"access":"write"`, `"access":"write","operations":["dispatch"]`, 1),
		"events without dispatch":   strings.Replace(apiEntry, `"access":"write"`, `"access":"write","dispatchEvents":["x"]`, 1),
		"prefixes with reads only":  strings.Replace(apiEntry, `"access":"write"`, `"access":"write","operations":["pr.read"],"pullRequestPrefixes":["factory/"]`, 1),
		"prefix without a slash":    strings.Replace(apiEntry, `"access":"write"`, `"access":"write","pullRequestPrefixes":["factory"]`, 1),
		"prefix with refs/heads":    strings.Replace(apiEntry, `"access":"write"`, `"access":"write","pullRequestPrefixes":["refs/heads/factory/"]`, 1),
		"prefix escaping":           strings.Replace(apiEntry, `"access":"write"`, `"access":"write","pullRequestPrefixes":["../"]`, 1),
		"duplicate label":           strings.Replace(apiEntry, `"access":"write"`, `"access":"write","operations":["pr.label"],"labels":["a","A"]`, 1),
		"label with a control":      strings.Replace(apiEntry, `"access":"write"`, `"access":"write","operations":["pr.label"],"labels":["a\n"]`, 1),
		"event with a space":        strings.Replace(apiEntry, `"access":"write"`, `"access":"write","operations":["dispatch"],"dispatchEvents":["a b"]`, 1),
	} {
		if _, err := Parse([]byte(`{"entries":[` + doc + `]}`)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// A scope with no catalog pool (a non-pool agent, or an Attestor that set
// none) matches no grant of any kind, even on a listed route.
func TestEmptyPoolMatchesNoGrant(t *testing.T) {
	doc := `{"pools":[{"name":"pool-a","namespace":"agents","serviceAccount":"worker"}],"entries":[` + validEntry + `,` + gitEntry + `,` + apiEntry + `,
		{"name":"core","kind":"postgres","host":"p.abc.db.postgresbridge.com","pools":["pool-a"],"postgres":{"database":"core","mount":"database","role":"r-readonly"}}]}`
	c, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Match("serpapi.com", 443, "GET", "/search", ""); !errors.Is(err, ErrPool) {
		t.Errorf("header entry: %v", err)
	}
	if _, _, err := c.GitMatch("github.com", 443, "POST", "/trmlabs/example-app.git/git-upload-pack", "", ""); !errors.Is(err, ErrPool) {
		t.Errorf("git entry: %v", err)
	}
	if _, _, err := c.GitHubAPIMatch("api.github.com", 443, "POST", "/repos/trmlabs/example-app/pulls", "", ""); !errors.Is(err, ErrPool) {
		t.Errorf("github-api entry: %v", err)
	}
	if _, err := c.Database("core", ""); !errors.Is(err, ErrPool) {
		t.Errorf("postgres entry: %v", err)
	}
}

// Each operation opens exactly its routes, with its token scope, and nothing
// else; every route belongs to an operation in the vocabulary.
func TestGitHubOperationsMapRoutesAndScopes(t *testing.T) {
	samples := []string{
		"POST pulls", "GET pulls", "GET pulls/1", "PATCH pulls/1", "POST pulls/1/ready",
		"POST issues/1/comments", "GET issues/1/comments", "POST pulls/1/comments", "POST pulls/1/comments/2/replies",
		"PATCH issues/comments/2", "POST issues/1/labels", "POST dispatches",
		"GET actions/runs", "GET actions/runs/1", "GET actions/runs/1/jobs", "GET actions/runs/1/artifacts", "GET actions/runs/1/logs",
		"GET actions/workflows/ci.yml/runs", "GET actions/jobs/1", "GET actions/jobs/1/logs", "GET actions/artifacts/1", "GET actions/artifacts/1/zip",
		"GET deployments", "GET deployments/1", "GET deployments/1/statuses",
		"GET actions/workflows/ci.yml", "GET pulls/1/files", "GET compare/main...feature", "GET commits/abc1234/status",
		"GET commits/abc1234/statuses", "GET commits/abc1234/check-runs", "GET check-runs/1", "GET check-runs/1/annotations",
	}
	want := map[string][]string{
		"pr.open":    {"POST pulls"},
		"pr.read":    {"GET pulls/1"}, // files and compare also need a git entry (TestGitHubAPICodeReadsNeedClone)
		"pr.list":    {"GET pulls", "GET issues/1/comments"},
		"pr.comment": {"POST issues/1/comments", "POST pulls/1/comments", "POST pulls/1/comments/2/replies"},
		"pr.edit":    {"PATCH pulls/1", "PATCH issues/comments/2"},
		"pr.label":   {"POST issues/1/labels"},
		"pr.ready":   {"POST pulls/1/ready"},
		"dispatch":   {"POST dispatches"},
		"actions.read": {"GET actions/runs", "GET actions/runs/1", "GET actions/runs/1/jobs", "GET actions/runs/1/artifacts", "GET actions/runs/1/logs",
			"GET actions/workflows/ci.yml/runs", "GET actions/jobs/1", "GET actions/jobs/1/logs", "GET actions/artifacts/1", "GET actions/artifacts/1/zip",
			"GET actions/workflows/ci.yml", "GET commits/abc1234/status", "GET commits/abc1234/statuses", "GET commits/abc1234/check-runs",
			"GET check-runs/1", "GET check-runs/1/annotations"},
		"deployments.read": {"GET deployments", "GET deployments/1", "GET deployments/1/statuses"},
	}
	if len(want) != len(githubOperations) {
		t.Fatalf("the vocabulary has %d operations, this test covers %d", len(githubOperations), len(want))
	}
	for op, routes := range want {
		params := ""
		switch op {
		case "pr.label":
			params = `,"labels":["preview"]`
		case "dispatch":
			params = `,"dispatchEvents":["build"]`
		}
		doc := strings.Replace(apiEntry, `"access":"write"`, `"access":"write","operations":["`+op+`"]`+params, 1)
		c, err := Parse([]byte(`{"entries":[` + doc + `]}`))
		if err != nil {
			t.Fatalf("%s: %v", op, err)
		}
		var got []string
		for _, sample := range samples {
			method, rest, _ := strings.Cut(sample, " ")
			m, _, err := c.GitHubAPIMatch("api.github.com", 443, method, "/repos/trmlabs/example-app/"+rest, "", "pool-a")
			if err != nil {
				continue
			}
			got = append(got, sample)
			scope := githubOperations[op]
			switch {
			case strings.Contains(sample, "check-runs"):
				scope = "checks"
			case strings.HasPrefix(sample, "GET commits/"):
				scope = "statuses"
			}
			if m.Operation != op || m.Permissions != scope {
				t.Errorf("%s %s: operation %q scope %q, want %q", op, sample, m.Operation, m.Permissions, scope)
			}
		}
		if fmt.Sprint(got) != fmt.Sprint(routes) {
			t.Errorf("%s opens %v, want %v", op, got, routes)
		}
		for _, scope := range []string{"pull-requests", "contents-write", "actions", "deployments", "checks", "statuses"} {
			want := githubOperations[op] == scope || contains(githubRouteScopes[op], scope)
			if c.GitGranted(42, "trmlabs/example-app", scope) != want {
				t.Errorf("%s: GitGranted(%s) = %v", op, scope, !want)
			}
		}
	}
}

// A pull request's files and a compare return code, so they open only for a
// pool whose git entry can already clone the repository.
func TestGitHubAPICodeReadsNeedClone(t *testing.T) {
	withGit, err := Parse([]byte(`{"entries":[` + gitEntry + `,` + apiEntry + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	alone, err := Parse([]byte(`{"entries":[` + apiEntry + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/repos/trmlabs/example-app/pulls/12/files", "/repos/trmlabs/example-app/compare/main...feature"} {
		if m, _, err := withGit.GitHubAPIMatch("api.github.com", 443, "GET", path, "", "pool-a"); err != nil || m.Operation != "pr.read" || m.CloneEntry == nil || m.CloneEntry.Kind != "git" {
			t.Errorf("%s with a git entry: %v %+v", path, err, m)
		}
		if _, _, err := alone.GitHubAPIMatch("api.github.com", 443, "GET", path, "", "pool-a"); !errors.Is(err, ErrUnlisted) {
			t.Errorf("%s without a git entry: %v", path, err)
		}
	}
	if m, _, err := alone.GitHubAPIMatch("api.github.com", 443, "GET", "/repos/trmlabs/example-app/pulls/12", "", "pool-a"); err != nil || m.CloneEntry != nil {
		t.Errorf("reading a pull request still needs no git entry: %v %+v", err, m)
	}
}

// A code read picks its git entry the way a clone does: the git entry on the
// git host (github.com for api.github.com) that lists the repository, which the
// catalog allows only once per host, and nothing when that entry does not grant
// the pool. An entry on another host is never used.
func TestGitHubAPICodeReadsUseTheCloneSelection(t *testing.T) {
	entry := func(name, host, pool string) string {
		return `{"name":"` + name + `","host":"` + host + `","kind":"git","pools":["` + pool + `"],
			"git":{"appID":7,"installationID":42,"repos":[{"repo":"trmlabs/example-app","access":"read"}]}}`
	}
	match := func(entries ...string) (GitRequest, error) {
		t.Helper()
		c, err := Parse([]byte(`{"entries":[` + strings.Join(append(entries, apiEntry), ",") + `]}`))
		if err != nil {
			t.Fatal(err)
		}
		m, _, err := c.GitHubAPIMatch("api.github.com", 443, "GET", "/repos/trmlabs/example-app/compare/main...feature", "", "pool-a")
		return m, err
	}
	// An entry on another host comes first in the catalog; the github.com one is used.
	if m, err := match(entry("elsewhere", "git.example.com", "pool-a"), entry("github", "github.com", "pool-a")); err != nil || m.CloneEntry == nil || m.CloneEntry.Name != "github" {
		t.Errorf("git host entry: %v %+v", err, m.CloneEntry)
	}
	// The github.com entry does not grant the pool: a clone gets ErrPool, so no
	// code read, even though another host's entry grants it.
	if _, err := match(entry("elsewhere", "git.example.com", "pool-a"), entry("github", "github.com", "pool-b")); !errors.Is(err, ErrUnlisted) {
		t.Errorf("git host entry without the pool: %v", err)
	}
	// Only another host lists the repository.
	if _, err := match(entry("elsewhere", "git.example.com", "pool-a")); !errors.Is(err, ErrUnlisted) {
		t.Errorf("git entry on another host only: %v", err)
	}
	// Another port on the git host is a different endpoint: an entry there,
	// listed first, never stands in for the clone entry on 443.
	altPort := strings.Replace(entry("alt-port", "github.com", "pool-a"), `"host":"github.com"`, `"host":"github.com","port":8443`, 1)
	if m, err := match(altPort, entry("github", "github.com", "pool-a")); err != nil || m.CloneEntry == nil || m.CloneEntry.Name != "github" {
		t.Errorf("alternate port listed first: %v %+v", err, m.CloneEntry)
	}
	if _, err := match(altPort); !errors.Is(err, ErrUnlisted) {
		t.Errorf("only an alternate port lists the repository: %v", err)
	}
}
