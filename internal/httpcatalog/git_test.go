package httpcatalog

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

const gitEntry = `{"name":"github","host":"github.com","kind":"git","pools":["pool-a"],
	"git":{"appID":7,"installationID":42,"repos":[
		{"repo":"TRMLabs/trm-b2b","access":"write","refPrefixes":["refs/heads/cursor/"]},
		{"repo":"trmlabs/docs","access":"read"}]}}`

func TestGitEntriesParseAndReject(t *testing.T) {
	c, err := Parse([]byte(`{"entries":[` + gitEntry + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	e := c.Entries()[0]
	if e.Git.Repos[0].Repo != "trmlabs/trm-b2b" || e.MaxRequestBytes != 1<<30 || e.MaxResponseBytes != 4<<30 || !c.HasHost("github.com", 443) {
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
		"duplicate repo":     strings.Replace(gitEntry, `trmlabs/docs`, `trmlabs/trm-b2b`, 1),
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
		{"GET", "/trmlabs/trm-b2b.git/info/refs", "service=git-upload-pack", "pool-a", "trmlabs/trm-b2b", false, nil},
		{"POST", "/TRMLabs/trm-b2b/git-upload-pack", "", "pool-a", "trmlabs/trm-b2b", false, nil},
		{"GET", "/trmlabs/trm-b2b.git/info/refs", "service=git-receive-pack", "pool-a", "trmlabs/trm-b2b", true, nil},
		{"POST", "/trmlabs/trm-b2b.git/git-receive-pack", "", "pool-a", "trmlabs/trm-b2b", true, nil},
		{"POST", "/trmlabs/docs.git/git-upload-pack", "", "pool-a", "trmlabs/docs", false, nil},
		{"POST", "/trmlabs/docs.git/git-receive-pack", "", "pool-a", "trmlabs/docs", true, ErrReadOnly},
		{"GET", "/trmlabs/docs.git/info/refs", "service=git-receive-pack", "pool-a", "trmlabs/docs", true, ErrReadOnly},
		{"POST", "/trmlabs/trm-b2b.git/git-upload-pack", "", "pool-b", "trmlabs/trm-b2b", false, ErrPool},
		{"POST", "/trmlabs/secret.git/git-upload-pack", "", "pool-a", "", false, ErrUnlisted},
		{"GET", "/trmlabs/trm-b2b.git/info/refs", "service=git-upload-pack&x=1", "pool-a", "", false, ErrUnlisted},
		{"GET", "/trmlabs/trm-b2b.git/info/lfs/objects/batch", "", "pool-a", "", false, ErrUnlisted},
		{"GET", "/trmlabs/trm-b2b.git/git-upload-pack", "", "pool-a", "", false, ErrMethod},
		{"GET", "/trmlabs/trm-b2b", "", "pool-a", "", false, ErrUnlisted},
	} {
		got, ok, err := c.GitMatch("github.com", 443, tc.method, tc.path, tc.query, tc.pool)
		if !ok || !errors.Is(err, tc.err) || (tc.repo != "" && (got.Repo.Repo != tc.repo || got.Write != tc.write)) {
			t.Errorf("%s %s?%s: ok=%v repo=%q write=%v err=%v", tc.method, tc.path, tc.query, ok, got.Repo.Repo, got.Write, err)
		}
	}
	if _, ok, _ := c.GitMatch("serpapi.com", 443, "GET", "/search", "", "pool-a"); ok {
		t.Fatal("header host routed to git")
	}
	if e, err := c.Match("github.com", 443, "POST", "/trmlabs/trm-b2b.git/git-upload-pack", "pool-a"); e != nil || !errors.Is(err, ErrUnlisted) {
		t.Fatal("git entry matched as a header entry")
	}
}

const apiEntry = `{"name":"github-api","host":"api.github.com","kind":"github-api","pools":["pool-a"],
	"git":{"appID":7,"installationID":42,"repos":[{"repo":"trmlabs/trm-b2b","access":"write"}]}}`

func TestGitHubAPIEntries(t *testing.T) {
	c, err := Parse([]byte(`{"entries":[` + gitEntry + `,` + apiEntry + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	if e := c.Entries()[1]; e.MaxRequestBytes != 1<<20 || e.MaxResponseBytes != 4<<30 {
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
		{"POST", "/repos/trmlabs/trm-b2b/pulls", "", "pool-a", nil},
		{"POST", "/repos/TRMLabs/trm-b2b/issues/12/comments", "", "pool-a", nil},
		{"POST", "/repos/trmlabs/trm-b2b/pulls/12/comments", "", "pool-a", nil},
		{"POST", "/repos/trmlabs/trm-b2b/pulls/12/comments/99/replies", "", "pool-a", nil},
		{"POST", "/repos/trmlabs/trm-b2b/pulls/12/reviews", "", "pool-a", ErrUnlisted},
		{"PUT", "/repos/trmlabs/trm-b2b/pulls/12/merge", "", "pool-a", ErrUnlisted},
		{"POST", "/repos/trmlabs/trm-b2b/issues/abc/comments", "", "pool-a", ErrUnlisted},
		{"POST", "/repos/trmlabs/trm-b2b/git/refs", "", "pool-a", ErrUnlisted},
		{"POST", "/repos/trmlabs/other/pulls", "", "pool-a", ErrUnlisted},
		{"POST", "/repos/trmlabs/trm-b2b/pulls", "per_page=1", "pool-a", ErrUnlisted},
		// The default operations (pr.open, pr.read, pr.comment) open no other route.
		{"GET", "/repos/trmlabs/trm-b2b/pulls", "", "pool-a", ErrMethod},
		{"DELETE", "/repos/trmlabs/trm-b2b/pulls", "", "pool-a", ErrMethod},
		{"GET", "/repos/trmlabs/trm-b2b/pulls/12", "", "pool-a", nil},
		{"PATCH", "/repos/trmlabs/trm-b2b/pulls/12", "", "pool-a", ErrMethod},
		{"POST", "/repos/trmlabs/trm-b2b/pulls/12/ready", "", "pool-a", ErrUnlisted},
		{"GET", "/repos/trmlabs/trm-b2b/issues/12/comments", "", "pool-a", ErrMethod},
		{"PATCH", "/repos/trmlabs/trm-b2b/issues/comments/5", "", "pool-a", ErrUnlisted},
		{"POST", "/repos/trmlabs/trm-b2b/issues/12/labels", "", "pool-a", ErrUnlisted},
		{"POST", "/repos/trmlabs/trm-b2b/dispatches", "", "pool-a", ErrUnlisted},
		{"GET", "/repos/trmlabs/trm-b2b/actions/runs", "", "pool-a", ErrUnlisted},
		{"GET", "/repos/trmlabs/trm-b2b/deployments", "", "pool-a", ErrUnlisted},
		{"PATCH", "/repos/trmlabs/trm-b2b/issues/12", "", "pool-a", ErrUnlisted},
		// pr.read also lists a pull request's files and compares two refs: code
		// the pool can already clone.
		{"GET", "/repos/trmlabs/trm-b2b/pulls/12/files", "", "pool-a", nil},
		{"GET", "/repos/trmlabs/trm-b2b/compare/main...feature", "", "pool-a", nil},
		{"GET", "/repos/trmlabs/trm-b2b/commits/abc1234/status", "", "pool-a", ErrUnlisted},
		{"GET", "/repos/trmlabs/trm-b2b/check-runs/9/annotations", "", "pool-a", ErrUnlisted},
		{"POST", "/repos/trmlabs/trm-b2b/pulls", "", "pool-b", ErrPool},
		{"POST", "/user/repos", "", "pool-a", ErrUnlisted},
	} {
		if _, ok, err := c.GitHubAPIMatch("api.github.com", 443, tc.method, tc.path, tc.query, tc.pool); !ok || !errors.Is(err, tc.err) {
			t.Errorf("%s %s: ok=%v err=%v", tc.method, tc.path, ok, err)
		}
	}
	if _, ok, _ := c.GitHubAPIMatch("github.com", 443, "POST", "/repos/trmlabs/trm-b2b/pulls", "", "pool-a"); ok {
		t.Fatal("git host routed to the API")
	}
	// Opening a pull request carries the pool's own push prefixes; other routes do not.
	if m, _, _ := c.GitHubAPIMatch("api.github.com", 443, "POST", "/repos/trmlabs/trm-b2b/pulls", "", "pool-a"); !m.OpensPullRequest || fmt.Sprint(m.HeadPrefixes) != "[cursor/]" {
		t.Fatalf("create: %+v", m)
	}
	if m, _, _ := c.GitHubAPIMatch("api.github.com", 443, "POST", "/repos/trmlabs/trm-b2b/issues/7/comments", "", "pool-a"); m.OpensPullRequest || m.CommentsOn != 7 || fmt.Sprint(m.HeadPrefixes) != "[cursor/]" {
		t.Fatalf("comment: %+v", m)
	}
	if m, _, _ := c.GitHubAPIMatch("api.github.com", 443, "POST", "/repos/trmlabs/trm-b2b/pulls/8/comments/99/replies", "", "pool-a"); m.CommentsOn != 8 {
		t.Fatalf("reply: %+v", m)
	}
	if _, _, err := c.GitHubAPIMatch("api.github.com", 443, "POST", "/repos/trmlabs/trm-b2b/issues/007/comments", "", "pool-a"); !errors.Is(err, ErrUnlisted) {
		t.Fatalf("a padded number matched: %v", err)
	}
	if m, _, _ := c.GitHubAPIMatch("api.github.com", 443, "GET", "/repos/trmlabs/trm-b2b/pulls/1", "", "pool-a"); m.Write {
		t.Fatalf("read marked as a write: %+v", m)
	}
	// Without a git entry for the pool, there is no branch to open one from.
	alone, err := Parse([]byte(`{"entries":[` + apiEntry + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	if m, _, _ := alone.GitHubAPIMatch("api.github.com", 443, "POST", "/repos/trmlabs/trm-b2b/pulls", "", "pool-a"); !m.OpensPullRequest || len(m.HeadPrefixes) != 0 {
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
		{"GET", "/repos/trmlabs/trm-b2b/pulls", "head=trmlabs:factory/x&state=open", "list-pulls", "pull-requests", false, nil},
		{"GET", "/repos/trmlabs/trm-b2b/pulls", "q=x", "", "", false, ErrUnlisted},
		{"GET", "/repos/trmlabs/trm-b2b/issues/12/comments", "per_page=100&page=2", "list-comments", "pull-requests", false, nil},
		{"PATCH", "/repos/trmlabs/trm-b2b/pulls/12", "", "edit-pull", "pull-requests", false, nil},
		{"PATCH", "/repos/trmlabs/trm-b2b/issues/comments/5", "", "edit-comment", "pull-requests", false, nil},
		{"POST", "/repos/trmlabs/trm-b2b/pulls/12/ready", "", "ready", "update-branch", false, nil},
		{"POST", "/repos/trmlabs/trm-b2b/issues/12/labels", "", "label", "pull-requests", false, nil},
		{"POST", "/repos/trmlabs/trm-b2b/dispatches", "", "dispatch", "contents-write", false, nil},
		{"GET", "/repos/trmlabs/trm-b2b/actions/runs", "head_sha=abc&per_page=5", "actions", "actions", false, nil},
		{"GET", "/repos/trmlabs/trm-b2b/actions/workflows/eval-replay.yml/runs", "branch=main", "actions", "actions", false, nil},
		{"GET", "/repos/trmlabs/trm-b2b/actions/workflows/123/runs", "", "actions", "actions", false, nil},
		{"GET", "/repos/trmlabs/trm-b2b/actions/runs/9/jobs", "", "actions", "actions", false, nil},
		{"GET", "/repos/trmlabs/trm-b2b/actions/runs/9/artifacts", "name=results", "actions", "actions", false, nil},
		{"GET", "/repos/trmlabs/trm-b2b/actions/runs/9/logs", "", "actions-download", "actions", true, nil},
		{"GET", "/repos/trmlabs/trm-b2b/actions/jobs/9/logs", "", "actions-download", "actions", true, nil},
		{"GET", "/repos/trmlabs/trm-b2b/actions/artifacts/9/zip", "", "actions-download", "actions", true, nil},
		{"GET", "/repos/trmlabs/trm-b2b/deployments", "environment=preview-1&sha=abc", "deployments", "deployments", false, nil},
		{"GET", "/repos/trmlabs/trm-b2b/deployments/4/statuses", "", "deployments", "deployments", false, nil},
		{"GET", "/repos/trmlabs/trm-b2b/actions/runs/9", "exclude_pull_requests=true", "actions", "actions", false, nil},
		{"GET", "/repos/trmlabs/trm-b2b/actions/workflows/ci.yml", "", "actions", "actions", false, nil},
		{"GET", "/repos/trmlabs/trm-b2b/actions/workflows/1234", "", "actions", "actions", false, nil},
		{"GET", "/repos/trmlabs/trm-b2b/commits/0123456789abcdef0123456789abcdef01234567/status", "", "statuses", "statuses", false, nil},
		{"GET", "/repos/trmlabs/trm-b2b/commits/0123abc/statuses", "per_page=100", "statuses", "statuses", false, nil},
		{"GET", "/repos/trmlabs/trm-b2b/commits/0123abc/check-runs", "check_name=unit&filter=latest&per_page=100", "check-runs", "checks", false, nil},
		{"GET", "/repos/trmlabs/trm-b2b/commits/0123abc/check-runs", "check_name=build+%28ubuntu-latest%29", "check-runs", "checks", false, nil},
		{"GET", "/repos/trmlabs/trm-b2b/check-runs/9", "", "check-run", "checks", false, nil},
		{"GET", "/repos/trmlabs/trm-b2b/check-runs/9/annotations", "per_page=100", "check-annotations", "checks", false, nil},
		{"GET", "/repos/trmlabs/trm-b2b/pulls/12/files", "per_page=100&page=2", "pull-files", "pull-requests", false, nil},
		{"GET", "/repos/trmlabs/trm-b2b/compare/staging...0123abc", "", "compare", "pull-requests", false, nil},
		{"GET", "/repos/trmlabs/trm-b2b/compare/main...staging", "per_page=1", "compare", "pull-requests", false, nil},
		{"GET", "/repos/trmlabs/trm-b2b/compare/staging..0123abc", "", "", "", false, ErrUnlisted},
		{"GET", "/repos/trmlabs/trm-b2b/compare/a....b", "", "", "", false, ErrUnlisted},
		{"GET", "/repos/trmlabs/trm-b2b/compare/staging...", "", "", "", false, ErrUnlisted},
		{"GET", "/repos/trmlabs/trm-b2b/commits/main/status", "", "", "", false, ErrUnlisted},
		{"GET", "/repos/trmlabs/trm-b2b/commits/0123abc", "", "", "", false, ErrUnlisted},
		{"POST", "/repos/trmlabs/trm-b2b/statuses/0123abc", "", "", "", false, ErrUnlisted},
		{"POST", "/repos/trmlabs/trm-b2b/check-runs", "", "", "", false, ErrUnlisted},
		{"PATCH", "/repos/trmlabs/trm-b2b/check-runs/9", "", "", "", false, ErrMethod},
		{"GET", "/repos/trmlabs/trm-b2b/actions/runs/9", "exclude_pull_requests=true&x=1", "", "", false, ErrUnlisted},
		{"POST", "/repos/trmlabs/trm-b2b/actions/workflows/ci.yml/dispatches", "", "", "", false, ErrUnlisted},
		{"POST", "/repos/trmlabs/trm-b2b/actions/runs/9/rerun", "", "", "", false, ErrUnlisted},
		{"GET", "/repos/trmlabs/trm-b2b/actions/workflows/../runs", "", "", "", false, ErrUnlisted},
		{"GET", "/repos/trmlabs/trm-b2b/actions/secrets", "", "", "", false, ErrUnlisted},
		{"POST", "/repos/trmlabs/trm-b2b/deployments", "", "", "", false, ErrMethod},
		{"GET", "/repos/trmlabs/trm-b2b/actions/runs", "actor=someone", "", "", false, ErrUnlisted},
	} {
		m, ok, err := c.GitHubAPIMatch("api.github.com", 443, tc.method, tc.path, tc.query, "pool-a")
		if !ok || !errors.Is(err, tc.err) || (err == nil && (m.Route != tc.route || m.Permissions != tc.permissions || m.Download != tc.download)) {
			t.Errorf("%s %s?%s: ok=%v err=%v route=%q permissions=%q download=%v", tc.method, tc.path, tc.query, ok, err, m.Route, m.Permissions, m.Download)
		}
	}
	if m, _, _ := c.GitHubAPIMatch("api.github.com", 443, "POST", "/repos/trmlabs/trm-b2b/pulls", "", "pool-a"); fmt.Sprint(m.HeadPrefixes) != "[cursor/]" {
		t.Errorf("open from a pull request prefix: %+v", m)
	}
	for _, path := range []string{"/repos/trmlabs/trm-b2b/issues/7/labels", "/repos/trmlabs/trm-b2b/pulls/7", "/repos/trmlabs/trm-b2b/pulls/7/ready", "/repos/trmlabs/trm-b2b/issues/7/comments"} {
		method := map[bool]string{true: "PATCH", false: "POST"}[strings.HasSuffix(path, "/7")]
		if m, _, _ := c.GitHubAPIMatch("api.github.com", 443, method, path, "", "pool-a"); m.Target != 7 || fmt.Sprint(m.HeadPrefixes) != "[cursor/ factory/]" {
			t.Errorf("%s %s: %+v", method, path, m)
		}
	}
	if m, _, _ := c.GitHubAPIMatch("api.github.com", 443, "PATCH", "/repos/trmlabs/trm-b2b/issues/comments/5", "", "pool-a"); m.CommentID != 5 || m.Target != 0 || fmt.Sprint(m.HeadPrefixes) != "[cursor/ factory/]" {
		t.Errorf("edit comment: %+v", m)
	}
	for _, scope := range []string{"pull-requests", "contents-write", "actions", "deployments", "checks", "statuses"} {
		if !c.GitGranted(42, "trmlabs/trm-b2b", scope) {
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
	if _, _, err := c.GitMatch("github.com", 443, "POST", "/trmlabs/trm-b2b.git/git-upload-pack", "", ""); !errors.Is(err, ErrPool) {
		t.Errorf("git entry: %v", err)
	}
	if _, _, err := c.GitHubAPIMatch("api.github.com", 443, "POST", "/repos/trmlabs/trm-b2b/pulls", "", ""); !errors.Is(err, ErrPool) {
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
		"PUT pulls/1/update-branch", "POST actions/runs/1/rerun", "POST actions/runs/1/rerun-failed-jobs",
	}
	want := map[string][]string{
		"graphql":    nil, // POST /graphql only (graphql_test.go); no REST route
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
		// CI restarts also need a git entry with push prefixes (TestGitHubCIRestartsNeedPushPrefixes).
		"pr.update_branch":     nil,
		"actions.rerun":        nil,
		"actions.rerun_failed": nil,
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
			m, _, err := c.GitHubAPIMatch("api.github.com", 443, method, "/repos/trmlabs/trm-b2b/"+rest, "", "pool-a")
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
		for _, scope := range []string{"pull-requests", "contents-write", "actions", "deployments", "checks", "statuses", "update-branch", "actions-write"} {
			want := githubOperations[op] == scope || contains(githubRouteScopes[op], scope)
			if c.GitGranted(42, "trmlabs/trm-b2b", scope) != want {
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
	for _, path := range []string{"/repos/trmlabs/trm-b2b/pulls/12/files", "/repos/trmlabs/trm-b2b/compare/main...feature"} {
		if m, _, err := withGit.GitHubAPIMatch("api.github.com", 443, "GET", path, "", "pool-a"); err != nil || m.Operation != "pr.read" || m.CloneEntry == nil || m.CloneEntry.Kind != "git" {
			t.Errorf("%s with a git entry: %v %+v", path, err, m)
		}
		if _, _, err := alone.GitHubAPIMatch("api.github.com", 443, "GET", path, "", "pool-a"); !errors.Is(err, ErrUnlisted) {
			t.Errorf("%s without a git entry: %v", path, err)
		}
	}
	if m, _, err := alone.GitHubAPIMatch("api.github.com", 443, "GET", "/repos/trmlabs/trm-b2b/pulls/12", "", "pool-a"); err != nil || m.CloneEntry != nil {
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
			"git":{"appID":7,"installationID":42,"repos":[{"repo":"trmlabs/trm-b2b","access":"read"}]}}`
	}
	match := func(entries ...string) (GitRequest, error) {
		t.Helper()
		c, err := Parse([]byte(`{"entries":[` + strings.Join(append(entries, apiEntry), ",") + `]}`))
		if err != nil {
			t.Fatal(err)
		}
		m, _, err := c.GitHubAPIMatch("api.github.com", 443, "GET", "/repos/trmlabs/trm-b2b/compare/main...feature", "", "pool-a")
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

// One git entry and one github-api entry serve several pools, each on its own
// branches: per-pool prefixes apply to their pool only, beside the shared
// ones, and a pool is refused on another pool's prefix for a push, opening a
// pull request and acting on one.
const poolsGitEntry = `{"name":"github","host":"github.com","kind":"git","pools":["pool-a","pool-b","pool-c"],
	"git":{"appID":7,"installationID":42,"repos":[
		{"repo":"example-org/example-repo","access":"write","poolRefPrefixes":{
			"pool-a":["refs/heads/cursor/pool-a/"],
			"pool-b":["refs/heads/cursor/pool-b/","refs/heads/factory/"]}},
		{"repo":"example-org/docs","access":"read"}]}}`

const poolsAPIEntry = `{"name":"github-api","host":"api.github.com","kind":"github-api","pools":["pool-a","pool-b","pool-c"],
	"git":{"appID":7,"installationID":42,"repos":[{"repo":"example-org/example-repo","access":"write",
		"operations":["pr.open","pr.read","pr.comment","pr.edit","pr.label","pr.ready"],"labels":["preview"],
		"poolPullRequestPrefixes":{"pool-a":["review/"]}}]}}`

func TestPoolPrefixesKeepEachPoolOnItsOwnBranches(t *testing.T) {
	c, err := Parse([]byte(`{"entries":[` + poolsGitEntry + `,` + poolsAPIEntry + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		pool, method, path, query, prefixes string
		err                                 error
	}{
		{"pool-a", "POST", "/example-org/example-repo.git/git-receive-pack", "", "[refs/heads/cursor/pool-a/]", nil},
		{"pool-b", "POST", "/example-org/example-repo.git/git-receive-pack", "", "[refs/heads/cursor/pool-b/ refs/heads/factory/]", nil},
		{"pool-b", "GET", "/example-org/example-repo.git/info/refs", "service=git-receive-pack", "[refs/heads/cursor/pool-b/ refs/heads/factory/]", nil},
		// pool-c is granted the repository but lists no prefix there: it
		// clones and fetches, and never pushes.
		{"pool-c", "POST", "/example-org/example-repo.git/git-upload-pack", "", "[]", nil},
		{"pool-c", "POST", "/example-org/example-repo.git/git-receive-pack", "", "[]", ErrReadOnly},
		{"pool-c", "GET", "/example-org/example-repo.git/info/refs", "service=git-receive-pack", "[]", ErrReadOnly},
		{"pool-d", "POST", "/example-org/example-repo.git/git-upload-pack", "", "[]", ErrPool},
	} {
		m, ok, err := c.GitMatch("github.com", 443, tc.method, tc.path, tc.query, tc.pool)
		if !ok || !errors.Is(err, tc.err) || (err == nil && fmt.Sprint(m.RefPrefixes) != tc.prefixes) {
			t.Errorf("%s %s %s: ok=%v err=%v prefixes=%v", tc.pool, tc.method, tc.path, ok, err, m.RefPrefixes)
		}
	}
	// A pull request opens only from the pool's own push prefixes, and a write
	// acts only on pull requests under them or the pool's own pull request
	// prefixes: pool-b never reaches review/, and nobody else reaches factory/.
	for _, tc := range []struct{ pool, open, target string }{
		{"pool-a", "[cursor/pool-a/]", "[cursor/pool-a/ review/]"},
		{"pool-b", "[cursor/pool-b/ factory/]", "[cursor/pool-b/ factory/]"},
		{"pool-c", "[]", "[]"},
	} {
		m, _, err := c.GitHubAPIMatch("api.github.com", 443, "POST", "/repos/example-org/example-repo/pulls", "", tc.pool)
		if err != nil || !m.OpensPullRequest || fmt.Sprint(m.HeadPrefixes) != tc.open {
			t.Errorf("%s opens from %v (%v), want %s", tc.pool, m.HeadPrefixes, err, tc.open)
		}
		for _, route := range []struct{ method, path string }{
			{"POST", "/repos/example-org/example-repo/issues/7/comments"},
			{"PATCH", "/repos/example-org/example-repo/pulls/7"},
			{"PATCH", "/repos/example-org/example-repo/issues/comments/5"},
			{"POST", "/repos/example-org/example-repo/issues/7/labels"},
			{"POST", "/repos/example-org/example-repo/pulls/7/ready"},
		} {
			m, _, err := c.GitHubAPIMatch("api.github.com", 443, route.method, route.path, "", tc.pool)
			if err != nil || fmt.Sprint(m.HeadPrefixes) != tc.target {
				t.Errorf("%s %s %s reaches %v (%v), want %s", tc.pool, route.method, route.path, m.HeadPrefixes, err, tc.target)
			}
		}
	}
	// The shared lists still apply to every pool of the entry, before its own.
	mixed := strings.Replace(poolsGitEntry, `"access":"write",`, `"access":"write","refPrefixes":["refs/heads/shared/"],`, 1)
	if c, err := Parse([]byte(`{"entries":[` + mixed + `]}`)); err != nil {
		t.Fatal(err)
	} else {
		for pool, want := range map[string]string{"pool-a": "[refs/heads/shared/ refs/heads/cursor/pool-a/]", "pool-c": "[refs/heads/shared/]"} {
			if m, _, err := c.GitMatch("github.com", 443, "POST", "/example-org/example-repo.git/git-receive-pack", "", pool); err != nil || fmt.Sprint(m.RefPrefixes) != want {
				t.Errorf("%s with shared prefixes: %v %v", pool, m.RefPrefixes, err)
			}
		}
	}
	// A write repository that lists no prefix at all still leaves every pool
	// to GitHub's branch protection, as before.
	open := strings.Replace(gitEntry, `,"refPrefixes":["refs/heads/cursor/"]`, ``, 1)
	if c, err := Parse([]byte(`{"entries":[` + open + `]}`)); err != nil {
		t.Fatal(err)
	} else if m, _, err := c.GitMatch("github.com", 443, "POST", "/trmlabs/trm-b2b.git/git-receive-pack", "", "pool-a"); err != nil || len(m.RefPrefixes) != 0 {
		t.Errorf("unlimited repository: %v %v", m.RefPrefixes, err)
	}
}

func TestPoolPrefixesAreValidatedAndDisjoint(t *testing.T) {
	refs := func(m string) string {
		return strings.Replace(poolsGitEntry, `"poolRefPrefixes":{
			"pool-a":["refs/heads/cursor/pool-a/"],
			"pool-b":["refs/heads/cursor/pool-b/","refs/heads/factory/"]}`, `"poolRefPrefixes":`+m, 1)
	}
	heads := func(m string) string {
		return strings.Replace(poolsAPIEntry, `"poolPullRequestPrefixes":{"pool-a":["review/"]}`, `"poolPullRequestPrefixes":`+m, 1)
	}
	if refs(`{}`) == poolsGitEntry || heads(`{}`) == poolsAPIEntry {
		t.Fatal("fixture replacement did not apply")
	}
	for name, doc := range map[string]string{
		"pool the entry does not grant":     refs(`{"pool-x":["refs/heads/cursor/pool-x/"]}`),
		"pool with no prefixes":             refs(`{"pool-a":[]}`),
		"invalid ref prefix":                refs(`{"pool-a":["heads/cursor/pool-a/"]}`),
		"escaping ref prefix":               refs(`{"pool-a":["refs/heads/../main"]}`),
		"duplicate within a pool":           refs(`{"pool-a":["refs/heads/a/","refs/heads/A/"]}`),
		"same prefix for two pools":         refs(`{"pool-a":["refs/heads/factory/"],"pool-b":["refs/heads/factory/"]}`),
		"one pool's prefix starts another":  refs(`{"pool-a":["refs/heads/cursor/"],"pool-b":["refs/heads/cursor/pool-b/"]}`),
		"overlap past a pool's own nesting": refs(`{"pool-a":["refs/heads/a","refs/heads/ab/"],"pool-b":["refs/heads/ac/"]}`),
		"overlap ignoring case":             refs(`{"pool-a":["refs/heads/Factory/"],"pool-b":["refs/heads/factory/x/"]}`),
		"per-pool prefixes on a read repository": strings.Replace(poolsGitEntry, `{"repo":"example-org/docs","access":"read"}`,
			`{"repo":"example-org/docs","access":"read","poolRefPrefixes":{"pool-a":["refs/heads/x/"]}}`, 1),
		"pull request prefixes on a git entry": strings.Replace(poolsGitEntry, `{"repo":"example-org/docs","access":"read"}`,
			`{"repo":"example-org/docs","access":"read","poolPullRequestPrefixes":{"pool-a":["x/"]}}`, 1),
		"ref prefixes on a github-api entry":     strings.Replace(poolsAPIEntry, `"access":"write",`, `"access":"write","poolRefPrefixes":{"pool-a":["refs/heads/x/"]},`, 1),
		"pull request prefix for another pool":   heads(`{"pool-x":["review/"]}`),
		"pull request prefix with refs/heads":    heads(`{"pool-a":["refs/heads/review/"]}`),
		"pull request prefix without a slash":    heads(`{"pool-a":["review"]}`),
		"same pull request prefix for two pools": heads(`{"pool-a":["review/"],"pool-b":["review/"]}`),
		"nested pull request prefixes":           heads(`{"pool-a":["review/"],"pool-b":["review/b/"]}`),
		"pull request prefixes with reads only":  strings.Replace(heads(`{"pool-a":["review/"]}`), `"operations":["pr.open","pr.read","pr.comment","pr.edit","pr.label","pr.ready"],"labels":["preview"]`, `"operations":["pr.open","pr.read"]`, 1),
		// A present but empty map would read as no limit at all, and so would
		// null, which decodes to no map.
		"empty per-pool ref prefixes":          refs(`{}`),
		"empty per-pool pull request prefixes": heads(`{}`),
		"null per-pool ref prefixes":           refs(`null`),
		"null per-pool pull request prefixes":  heads(`null`),
		"null prefixes for a pool":             refs(`{"pool-a":null}`),
		// The shared lists apply to every pool, so they may not reach a pool's own.
		"a shared prefix starts a pool's own":              strings.Replace(refs(`{"pool-a":["refs/heads/cursor/pool-a/"]}`), `"access":"write",`, `"access":"write","refPrefixes":["refs/heads/cursor/"],`, 1),
		"a pool's own starts a shared prefix":              strings.Replace(refs(`{"pool-a":["refs/heads/"]}`), `"access":"write",`, `"access":"write","refPrefixes":["refs/heads/shared/"],`, 1),
		"a shared pull request prefix starts a pool's own": strings.Replace(heads(`{"pool-a":["review/a/"]}`), `"access":"write",`, `"access":"write","pullRequestPrefixes":["review/"],`, 1),
		"a pool's own starts a shared pull request prefix": strings.Replace(heads(`{"pool-a":["review/"]}`), `"access":"write",`, `"access":"write","pullRequestPrefixes":["review/shared/"],`, 1),
	} {
		if _, err := Parse([]byte(`{"entries":[` + doc + `]}`)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// Prefixes that only share text, not a starting run, are disjoint.
	for name, doc := range map[string]string{
		"sibling pools":         refs(`{"pool-a":["refs/heads/cursor/pool-a/"],"pool-ab":["refs/heads/cursor/pool-ab/"]}`),
		"same pool nests":       refs(`{"pool-a":["refs/heads/a/","refs/heads/a/b/"]}`),
		"pull request siblings": heads(`{"pool-a":["review/a/"],"pool-b":["review/b/"]}`),
	} {
		doc = strings.Replace(doc, `"pools":["pool-a","pool-b","pool-c"]`, `"pools":["pool-a","pool-ab","pool-b","pool-c"]`, 1)
		if _, err := Parse([]byte(`{"entries":[` + doc + `]}`)); err != nil {
			t.Errorf("%s refused: %v", name, err)
		}
	}
}

// An explicit null for either per-pool field is refused by name at load, in
// the strict and the tolerant load alike, rather than read as an absent field.
func TestPoolPrefixesNullIsRefused(t *testing.T) {
	git := strings.Replace(poolsGitEntry, `"poolRefPrefixes":{
			"pool-a":["refs/heads/cursor/pool-a/"],
			"pool-b":["refs/heads/cursor/pool-b/","refs/heads/factory/"]}`, `"poolRefPrefixes":null`, 1)
	api := strings.Replace(poolsAPIEntry, `"poolPullRequestPrefixes":{"pool-a":["review/"]}`, `"poolPullRequestPrefixes":null`, 1)
	if git == poolsGitEntry || api == poolsAPIEntry {
		t.Fatal("fixture replacement did not apply")
	}
	for name, entry := range map[string]string{"github": git, "github-api": api} {
		if _, err := Parse([]byte(`{"entries":[` + entry + `]}`)); !errors.Is(err, errNullPoolPrefixes) {
			t.Errorf("%s: %v", name, err)
		}
		c, dropped, err := ParseTolerant([]byte(`{"entries":[` + validEntry + `,` + entry + `]}`))
		if err != nil || entryNames(c) != "serpapi" || droppedNames(dropped) != "entry:"+name {
			t.Errorf("%s tolerant: kept %q dropped %q err %v", name, entryNames(c), droppedNames(dropped), err)
		}
	}
}

// The tolerant load drops only the entry whose per-pool prefixes fail, and
// keeps the rest of the catalog in force.
func TestPoolPrefixesFailingEntryIsDroppedAlone(t *testing.T) {
	bad := strings.Replace(poolsGitEntry, `"pool-b":["refs/heads/cursor/pool-b/","refs/heads/factory/"]`, `"pool-b":["refs/heads/cursor/pool-a/x/"]`, 1)
	if bad == poolsGitEntry {
		t.Fatal("fixture replacement did not apply")
	}
	c, dropped, err := ParseTolerant([]byte(`{"entries":[` + validEntry + `,` + bad + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(dropped) != 1 || dropped[0].Kind != "entry" || dropped[0].Name != "github" || !strings.Contains(dropped[0].Reason, "overlaps") {
		t.Fatalf("dropped %+v", dropped)
	}
	if len(c.Entries()) != 1 || c.Entries()[0].Name != "serpapi" {
		t.Fatalf("kept %+v", c.Entries())
	}
	if _, ok, _ := c.GitMatch("github.com", 443, "POST", "/example-org/example-repo.git/git-receive-pack", "", "pool-a"); ok {
		t.Fatal("the dropped entry still routes")
	}
}

// An overlap names both prefixes as the catalog spells them, so an author can
// find them.
func TestPoolPrefixOverlapKeepsTheAuthorsSpelling(t *testing.T) {
	doc := strings.Replace(poolsGitEntry, `"pool-b":["refs/heads/cursor/pool-b/","refs/heads/factory/"]`, `"pool-b":["refs/heads/Cursor/Pool-A/x/"]`, 1)
	_, err := Parse([]byte(`{"entries":[` + doc + `]}`))
	if err == nil || !strings.Contains(err.Error(), `"refs/heads/Cursor/Pool-A/x/" (pool "pool-b") overlaps "refs/heads/cursor/pool-a/" (pool "pool-a")`) {
		t.Fatalf("overlap error: %v", err)
	}
}

// A github-api repository's pull request prefixes may not reach another
// pool's own push prefixes in the git entry a clone of the repository uses:
// that pool's pull requests would be in reach of the other's comment, edit,
// label and ready routes. The load refuses it whichever entry comes first, and
// the tolerant load drops both entries.
func TestPullRequestPrefixesStayOffOtherPoolsBranches(t *testing.T) {
	heads := func(field, value string) string {
		return strings.Replace(poolsAPIEntry, `"poolPullRequestPrefixes":{"pool-a":["review/"]}`, `"`+field+`":`+value, 1)
	}
	if heads("poolPullRequestPrefixes", `{}`) == poolsAPIEntry {
		t.Fatal("fixture replacement did not apply")
	}
	for name, api := range map[string]string{
		"inside another pool's push prefix":   heads("poolPullRequestPrefixes", `{"pool-b":["cursor/pool-a/x/"]}`),
		"starting another pool's push prefix": heads("poolPullRequestPrefixes", `{"pool-b":["cursor/"]}`),
		"equal to another pool's push prefix": heads("poolPullRequestPrefixes", `{"pool-a":["factory/"]}`),
		"ignoring case":                       heads("poolPullRequestPrefixes", `{"pool-b":["Cursor/Pool-A/"]}`),
		"a shared prefix on one pool's own":   heads("pullRequestPrefixes", `["cursor/pool-a/"]`),
	} {
		for order, doc := range []string{poolsGitEntry + `,` + api, api + `,` + poolsGitEntry} {
			if _, err := Parse([]byte(`{"entries":[` + doc + `]}`)); err == nil || !strings.Contains(err.Error(), "overlaps push prefix") {
				t.Errorf("%s (order %d): %v", name, order, err)
			}
		}
	}
	// A pool's own pull request prefixes under its own push prefixes, the git
	// entry's shared push prefixes and a git entry on another host cross
	// nothing.
	sharedPush := strings.Replace(poolsGitEntry, `"access":"write",`, `"access":"write","refPrefixes":["refs/heads/shared/"],`, 1)
	otherHost := strings.NewReplacer(`"name":"github"`, `"name":"elsewhere"`, `"host":"github.com"`, `"host":"git.example.com"`).Replace(poolsGitEntry)
	for name, doc := range map[string]string{
		"its own push prefix":       poolsGitEntry + `,` + heads("poolPullRequestPrefixes", `{"pool-a":["cursor/pool-a/sub/"]}`),
		"a shared push prefix":      sharedPush + `,` + heads("poolPullRequestPrefixes", `{"pool-b":["shared/x/"]}`),
		"a git entry on other host": otherHost + `,` + heads("poolPullRequestPrefixes", `{"pool-b":["cursor/pool-a/"]}`),
	} {
		if _, err := Parse([]byte(`{"entries":[` + doc + `]}`)); err != nil {
			t.Errorf("%s refused: %v", name, err)
		}
	}
	// A shared pull request prefix on a pool's own push prefix crosses nothing
	// when the github-api entry grants only that pool.
	onlyA := strings.Replace(heads("pullRequestPrefixes", `["cursor/pool-a/"]`), `"pools":["pool-a","pool-b","pool-c"]`, `"pools":["pool-a"]`, 1)
	if _, err := Parse([]byte(`{"entries":[` + poolsGitEntry + `,` + onlyA + `]}`)); err != nil {
		t.Errorf("shared prefix with one pool refused: %v", err)
	}
	crossing := heads("poolPullRequestPrefixes", `{"pool-b":["cursor/pool-a/"]}`)
	c, dropped, err := ParseTolerant([]byte(`{"entries":[` + validEntry + `,` + poolsGitEntry + `,` + crossing + `]}`))
	if err != nil || entryNames(c) != "serpapi" || droppedNames(dropped) != "entry:github,entry:github-api" {
		t.Fatalf("tolerant: kept %q dropped %q err %v", entryNames(c), droppedNames(dropped), err)
	}
	for _, d := range dropped {
		if !strings.Contains(d.Reason, `"cursor/pool-a/" (pool "pool-b") in entry "github-api" overlaps push prefix "refs/heads/cursor/pool-a/" (pool "pool-a") in entry "github"`) {
			t.Errorf("%s reason: %s", d.Name, d.Reason)
		}
	}
	// The git entry's shared push prefixes are held by each pool of that entry,
	// so a github-api pool outside it may not reach them either, by its own
	// pull request prefixes or the shared ones.
	withD := strings.Replace(poolsAPIEntry, `"pools":["pool-a","pool-b","pool-c"]`, `"pools":["pool-a","pool-b","pool-c","pool-d"]`, 1)
	outside := func(field, value string) string {
		return strings.Replace(withD, `"poolPullRequestPrefixes":{"pool-a":["review/"]}`, `"`+field+`":`+value, 1)
	}
	if withD == poolsAPIEntry || outside("pullRequestPrefixes", `[]`) == withD {
		t.Fatal("fixture replacement did not apply")
	}
	sharedOnly := `{"name":"github","host":"github.com","kind":"git","pools":["pool-a","pool-b","pool-c"],"git":{"appID":7,"installationID":42,
		"repos":[{"repo":"example-org/example-repo","access":"write","refPrefixes":["refs/heads/shared/"]}]}}`
	for name, api := range map[string]string{
		"inside a shared push prefix, ignoring case":        outside("poolPullRequestPrefixes", `{"pool-d":["Shared/X/"]}`),
		"equal to a shared push prefix":                     outside("poolPullRequestPrefixes", `{"pool-d":["shared/"]}`),
		"a shared prefix with a pool outside the git entry": outside("pullRequestPrefixes", `["shared/x/"]`),
	} {
		for _, git := range []string{sharedPush, sharedOnly} {
			for order, doc := range []string{git + `,` + api, api + `,` + git} {
				if _, err := Parse([]byte(`{"entries":[` + doc + `]}`)); err == nil || !strings.Contains(err.Error(), "overlaps push prefix") {
					t.Errorf("%s (order %d): %v", name, order, err)
				}
			}
		}
	}
	if _, err := Parse([]byte(`{"entries":[` + sharedPush + `,` + outside("poolPullRequestPrefixes", `{"pool-d":["renovate/"]}`) + `]}`)); err != nil {
		t.Errorf("a pool outside the git entry, off every push prefix, refused: %v", err)
	}
	// A write repository that lists no push prefixes lets each pool of its git
	// entry push any branch, as a shared push prefix of refs/heads/ would, so
	// no pull request prefix of a pool outside that entry may reach it. A
	// read-only repository pushes nothing and crosses nothing.
	unlimited := func(pools, access string) string {
		return `{"name":"github","host":"github.com","kind":"git","pools":` + pools + `,"git":{"appID":7,"installationID":42,
		"repos":[{"repo":"example-org/example-repo","access":"` + access + `"}]}}`
	}
	for name, doc := range map[string]string{
		"a pool's own prefix, three git pools": unlimited(`["pool-a","pool-b","pool-c"]`, "write") + `,` + outside("poolPullRequestPrefixes", `{"pool-d":["feature/"]}`),
		"a shared prefix, three git pools":     unlimited(`["pool-a","pool-b","pool-c"]`, "write") + `,` + outside("pullRequestPrefixes", `["feature/"]`),
		"a shared prefix, one git pool":        unlimited(`["pool-a"]`, "write") + `,` + heads("pullRequestPrefixes", `["feature/"]`),
	} {
		if _, err := Parse([]byte(`{"entries":[` + doc + `]}`)); err == nil || !strings.Contains(err.Error(), `overlaps push prefix "refs/heads/" (shared by every pool)`) {
			t.Errorf("unlimited push, %s: %v", name, err)
		}
	}
	for name, doc := range map[string]string{
		"every pool inside the git entry": unlimited(`["pool-a","pool-b","pool-c"]`, "write") + `,` + heads("pullRequestPrefixes", `["feature/"]`),
		"a read-only repository":          unlimited(`["pool-a"]`, "read") + `,` + outside("pullRequestPrefixes", `["feature/"]`),
	} {
		if _, err := Parse([]byte(`{"entries":[` + doc + `]}`)); err != nil {
			t.Errorf("unlimited push, %s refused: %v", name, err)
		}
	}
	c, dropped, err = ParseTolerant([]byte(`{"entries":[` + validEntry + `,` + sharedPush + `,` + outside("poolPullRequestPrefixes", `{"pool-d":["shared/x/"]}`) + `]}`))
	if err != nil || entryNames(c) != "serpapi" || droppedNames(dropped) != "entry:github,entry:github-api" {
		t.Fatalf("tolerant, shared push prefix: kept %q dropped %q err %v", entryNames(c), droppedNames(dropped), err)
	}
	for _, d := range dropped {
		if !strings.Contains(d.Reason, `"shared/x/" (pool "pool-d") in entry "github-api" overlaps push prefix "refs/heads/shared/" (shared by every pool) in entry "github"`) {
			t.Errorf("%s reason: %s", d.Name, d.Reason)
		}
	}
}

// A CI restart (a branch update, a rerun) exists only where the repository
// opts in and the git entry a push would use lets the pool push to branch
// prefixes. Its head must then be under those prefixes alone, never the
// repository's pullRequestPrefixes, and the requester must pass that git
// entry too.
func TestGitHubCIRestartsNeedPushPrefixes(t *testing.T) {
	api := `{"name":"github-api","host":"api.github.com","kind":"github-api","pools":["pool-a"],
		"git":{"appID":7,"installationID":42,"repos":[{"repo":"example-org/example-repo","access":"write",
		"operations":["pr.comment","pr.update_branch","actions.rerun","actions.rerun_failed"],"pullRequestPrefixes":["factory/"]}]}}`
	git := func(host, access, prefixes string) string {
		return `{"name":"github","host":"` + host + `","kind":"git","pools":["pool-a"],"git":{"appID":7,"installationID":42,
			"repos":[{"repo":"example-org/example-repo","access":"` + access + `"` + prefixes + `}]}}`
	}
	routes := map[string]struct{ method, op, scope string }{
		"/repos/example-org/example-repo/pulls/12/update-branch":            {"PUT", "pr.update_branch", "update-branch"},
		"/repos/example-org/example-repo/actions/runs/34/rerun":             {"POST", "actions.rerun", "actions-write"},
		"/repos/example-org/example-repo/actions/runs/34/rerun-failed-jobs": {"POST", "actions.rerun_failed", "actions-write"},
	}
	c, err := Parse([]byte(`{"entries":[` + api + `,` + git("github.com", "write", `,"refPrefixes":["refs/heads/agent/","refs/tags/agent/"]`) + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range routes {
		m, _, err := c.GitHubAPIMatch("api.github.com", 443, want.method, path, "", "pool-a")
		if err != nil || m.Operation != want.op || m.Permissions != want.scope || m.RestartOf == 0 || m.Target != 0 ||
			m.CloneEntry == nil || m.CloneEntry.Name != "github" || fmt.Sprint(m.HeadPrefixes) != "[agent/]" {
			t.Errorf("%s: %v %+v", path, err, m)
		}
		if _, _, err := c.GitHubAPIMatch("api.github.com", 443, want.method, path, "", "pool-b"); !errors.Is(err, ErrPool) {
			t.Errorf("%s for another pool: %v", path, err)
		}
	}
	if !c.GitGranted(42, "example-org/example-repo", "update-branch") || !c.GitGranted(42, "example-org/example-repo", "actions-write") ||
		c.GitGranted(42, "example-org/example-repo", "actions") {
		t.Error("GitGranted does not follow the restart operations")
	}
	if s := c.GitScope(42); !s.PullRequests || !s.ActionsWrite || s.Actions {
		t.Errorf("GitScope = %+v", s)
	}
	// Each restart operation alone sets the installation scope its token needs.
	for op, want := range map[string][2]bool{ // pull requests write, actions write
		"pr.update_branch":     {true, false},
		"actions.rerun":        {false, true},
		"actions.rerun_failed": {false, true},
	} {
		c, err := Parse([]byte(`{"entries":[{"name":"github-api","host":"api.github.com","kind":"github-api","pools":["pool-a"],
			"git":{"appID":7,"installationID":42,"repos":[{"repo":"example-org/example-repo","access":"write","operations":["` + op + `"]}]}}]}`))
		if err != nil {
			t.Fatalf("%s: %v", op, err)
		}
		if s := c.GitScope(42); s.PullRequests != want[0] || s.ActionsWrite != want[1] || s.Actions || s.Deployments || s.Checks || s.Statuses {
			t.Errorf("%s alone: GitScope = %+v", op, s)
		}
	}
	for name, doc := range map[string]string{
		"no git entry":         api,
		"read-only git entry":  api + `,` + git("github.com", "read", ``),
		"push anywhere":        api + `,` + git("github.com", "write", ``),
		"tag prefixes only":    api + `,` + git("github.com", "write", `,"refPrefixes":["refs/tags/agent/"]`),
		"git entry elsewhere":  api + `,` + git("git.example.com", "write", `,"refPrefixes":["refs/heads/agent/"]`),
		"every branch is none": api + `,` + git("github.com", "write", `,"refPrefixes":["refs/heads/"]`),
	} {
		c, err := Parse([]byte(`{"entries":[` + doc + `]}`))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for path, want := range routes {
			if _, _, err := c.GitHubAPIMatch("api.github.com", 443, want.method, path, "", "pool-a"); !errors.Is(err, ErrUnlisted) {
				t.Errorf("%s: %s: %v", name, path, err)
			}
		}
	}
}

// One git entry serves several pools on their own branches: a CI restart
// reads the pool's own push prefixes beside the shared ones, never another
// pool's and never its pull request prefixes, and a pool with none has no
// restart routes.
func TestGitHubCIRestartsUseThePoolsOwnPrefixes(t *testing.T) {
	api := strings.Replace(poolsAPIEntry, `"pr.ready"]`, `"pr.ready","pr.update_branch","actions.rerun"]`, 1)
	if api == poolsAPIEntry {
		t.Fatal("fixture replacement did not apply")
	}
	routes := []struct{ method, path string }{
		{"PUT", "/repos/example-org/example-repo/pulls/12/update-branch"},
		{"POST", "/repos/example-org/example-repo/actions/runs/34/rerun"},
	}
	shared := strings.Replace(poolsGitEntry, `"access":"write",`, `"access":"write","refPrefixes":["refs/heads/shared/"],`, 1)
	for git, wants := range map[string]map[string]string{
		poolsGitEntry: {"pool-a": "[cursor/pool-a/]", "pool-b": "[cursor/pool-b/ factory/]"},
		shared:        {"pool-a": "[shared/ cursor/pool-a/]", "pool-b": "[shared/ cursor/pool-b/ factory/]", "pool-c": "[shared/]"},
	} {
		c, err := Parse([]byte(`{"entries":[` + git + `,` + api + `]}`))
		if err != nil {
			t.Fatal(err)
		}
		for _, pool := range []string{"pool-a", "pool-b", "pool-c"} {
			for _, route := range routes {
				m, _, err := c.GitHubAPIMatch("api.github.com", 443, route.method, route.path, "", pool)
				want, ok := wants[pool]
				if !ok {
					if !errors.Is(err, ErrUnlisted) {
						t.Errorf("%s with no push prefix: %s %s: %v %v", pool, route.method, route.path, err, m.HeadPrefixes)
					}
					continue
				}
				if err != nil || m.RestartOf == 0 || fmt.Sprint(m.HeadPrefixes) != want {
					t.Errorf("%s %s %s reaches %v (%v), want %s", pool, route.method, route.path, m.HeadPrefixes, err, want)
				}
			}
		}
	}
}
