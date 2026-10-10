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
		{"GET", "/repos/trmlabs/trm-b2b/pulls", "", "pool-a", nil},
		{"GET", "/repos/trmlabs/trm-b2b/pulls", "head=trmlabs:cursor/x&state=open", "pool-a", nil},
		{"GET", "/repos/trmlabs/trm-b2b/pulls", "q=x", "pool-a", ErrUnlisted},
		{"DELETE", "/repos/trmlabs/trm-b2b/pulls", "", "pool-a", ErrMethod},
		{"GET", "/repos/trmlabs/trm-b2b/pulls/12", "", "pool-a", nil},
		{"PATCH", "/repos/trmlabs/trm-b2b/pulls/12", "", "pool-a", nil},
		{"PUT", "/repos/trmlabs/trm-b2b/pulls/12", "", "pool-a", ErrMethod},
		{"POST", "/repos/trmlabs/trm-b2b/pulls/12/ready", "", "pool-a", nil},
		{"GET", "/repos/trmlabs/trm-b2b/issues/12/comments", "per_page=100&page=2", "pool-a", nil},
		{"PATCH", "/repos/trmlabs/trm-b2b/issues/comments/5", "", "pool-a", nil},
		{"POST", "/repos/trmlabs/trm-b2b/issues/12/labels", "", "pool-a", ErrUnlisted},
		{"POST", "/repos/trmlabs/trm-b2b/dispatches", "", "pool-a", ErrUnlisted},
		{"GET", "/repos/trmlabs/trm-b2b/actions/runs", "", "pool-a", ErrUnlisted},
		{"GET", "/repos/trmlabs/trm-b2b/deployments", "", "pool-a", ErrUnlisted},
		{"PATCH", "/repos/trmlabs/trm-b2b/issues/12", "", "pool-a", ErrUnlisted},
		{"GET", "/repos/trmlabs/trm-b2b/pulls/12/files", "", "pool-a", ErrUnlisted},
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
	granted := strings.Replace(apiEntry, `"access":"write"`, `"access":"write","pullRequestPrefixes":["factory/"],"labels":["preview"],"dispatchEvents":["preview-build"],"actions":true,"deployments":true`, 1)
	c, err := Parse([]byte(`{"entries":[` + gitEntry + `,` + granted + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		method, path, query, route, permissions string
		download                                bool
		err                                     error
	}{
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
	for _, scope := range []string{"pull-requests", "contents-write", "actions", "deployments"} {
		if !c.GitGranted(42, "trmlabs/trm-b2b", scope) {
			t.Errorf("GitGranted %s = false", scope)
		}
	}
	if repos, pullRequests, actions, deployments := c.GitScope(42); len(repos) != 3 || !pullRequests || !actions || !deployments {
		t.Errorf("GitScope = %v %v %v %v", repos, pullRequests, actions, deployments)
	}
	for name, doc := range map[string]string{
		"grant on a git entry":        strings.Replace(gitEntry, `"access":"write"`, `"access":"write","labels":["preview"]`, 1),
		"prefix without a slash":      strings.Replace(apiEntry, `"access":"write"`, `"access":"write","pullRequestPrefixes":["factory"]`, 1),
		"prefix with refs/heads":      strings.Replace(apiEntry, `"access":"write"`, `"access":"write","pullRequestPrefixes":["refs/heads/factory/"]`, 1),
		"prefix escaping":             strings.Replace(apiEntry, `"access":"write"`, `"access":"write","pullRequestPrefixes":["../"]`, 1),
		"duplicate label":             strings.Replace(apiEntry, `"access":"write"`, `"access":"write","labels":["a","A"]`, 1),
		"label with a control":        strings.Replace(apiEntry, `"access":"write"`, `"access":"write","labels":["a\n"]`, 1),
		"dispatch event with a space": strings.Replace(apiEntry, `"access":"write"`, `"access":"write","dispatchEvents":["a b"]`, 1),
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
