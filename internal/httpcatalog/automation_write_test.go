package httpcatalog

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// writeGrantCatalog is an Automation pool with a git entry (repo-git), a
// github-api entry (repo-api) on the same repository and a header entry
// (tracker), and the Automation blocks given. The pool may push factory/ and
// use every operation the repository lists.
func writeGrantCatalog(automations string) string {
	tracker := strings.Replace(entryNamed("tracker", "tracker.example.com"), `"pools":["pool-a"]`, `"pools":["automations"]`, 1)
	return `{"pools":[{"name":"automations","namespace":"n","serviceAccount":"automations","identity":"cursor-automation"}],
	 "entries":[
	  {"name":"repo-git","host":"github.com","kind":"git","pools":["automations"],"git":{"appID":7,"installationID":42,"repos":[
	   {"repo":"example-org/example-app","access":"write","refPrefixes":["refs/heads/factory/"]}]}},
	  {"name":"repo-api","host":"api.github.com","kind":"github-api","pools":["automations"],"git":{"appID":7,"installationID":42,"repos":[
	   {"repo":"example-org/example-app","access":"write",
	    "operations":["pr.open","pr.read","pr.list","pr.comment","pr.update_branch"],
	    "poolOperations":{"automations":["pr.open","pr.read","pr.list","pr.comment","pr.update_branch"]}}]}},
	  ` + tracker + `],
	 "automations":[` + automations + `]}`
}

const (
	readerBlock = `{"id":"auto-reader","name":"reader","owner":"platform-team","entries":["repo-git","repo-api","tracker"]}`
	writerBlock = `{"id":"auto-writer","name":"writer","owner":"platform-team","entries":["repo-git","repo-api","tracker"],"write":["repo-git","repo-api"]}`
)

// An Automation's write list names git and github-api entries among its own.
// It is kept sorted, so a lookup is a binary search, and an Automation that
// has none holds no write grant anywhere.
func TestAutomationWriteGrantsLoad(t *testing.T) {
	c, err := Parse([]byte(writeGrantCatalog(readerBlock + `,` + writerBlock)))
	if err != nil {
		t.Fatal(err)
	}
	reader, _ := c.Automation("auto-reader")
	writer, _ := c.Automation("auto-writer")
	for _, entry := range []string{"repo-git", "repo-api", "tracker", "unknown"} {
		if reader.Writes(entry) {
			t.Errorf("an Automation with no write list writes %s", entry)
		}
		if want := entry == "repo-git" || entry == "repo-api"; writer.Writes(entry) != want {
			t.Errorf("writer on %s: %v, want %v", entry, writer.Writes(entry), want)
		}
	}
	// Order in the file decides nothing.
	reordered := strings.Replace(writerBlock, `"write":["repo-git","repo-api"]`, `"write":["repo-api","repo-git"]`, 1)
	c, err = Parse([]byte(writeGrantCatalog(reordered)))
	if err != nil {
		t.Fatal(err)
	}
	if w, _ := c.Automation("auto-writer"); !w.Writes("repo-git") || !w.Writes("repo-api") || !slices.IsSorted(w.Write) {
		t.Errorf("write %v not sorted or not found", w.Write)
	}
	// Only the Automation pool decides per Automation.
	if a, ok := c.Automation("auto-writer"); !ok || !a.Writes("repo-git") {
		t.Error("the catalog does not return the Automation")
	}
}

// A write list that names anything but a git or github-api entry the
// Automation lists is refused at load, and a tolerant load drops that
// Automation only: its runs are refused, never served with a wider grant.
func TestAutomationWriteRefusals(t *testing.T) {
	for name, block := range map[string]string{
		"an entry the Automation does not list": `{"id":"bad","name":"bad","owner":"platform-team","entries":["repo-api"],"write":["repo-git"]}`,
		"an entry the catalog lacks":            `{"id":"bad","name":"bad","owner":"platform-team","entries":["repo-api"],"write":["nowhere"]}`,
		"a header entry":                        `{"id":"bad","name":"bad","owner":"platform-team","entries":["repo-api","tracker"],"write":["tracker"]}`,
		"a repeated entry":                      `{"id":"bad","name":"bad","owner":"platform-team","entries":["repo-api"],"write":["repo-api","repo-api"]}`,
		"an entry that is not a name":           `{"id":"bad","name":"bad","owner":"platform-team","entries":["repo-api"],"write":["repo api"]}`,
		"an entry that is not a string":         `{"id":"bad","name":"bad","owner":"platform-team","entries":["repo-api"],"write":[7]}`,
		"a string, not a list":                  `{"id":"bad","name":"bad","owner":"platform-team","entries":["repo-api"],"write":"repo-api"}`,
	} {
		doc := writeGrantCatalog(readerBlock + `,` + block)
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
		c, dropped, err := ParseTolerant([]byte(doc))
		if err != nil || droppedNames(dropped) != "automation:bad" || c.Automations() != 1 {
			t.Errorf("%s: tolerant load kept %d, dropped %q, %v", name, c.Automations(), droppedNames(dropped), err)
		}
		if _, ok := c.Automation("bad"); ok {
			t.Errorf("%s: the bad Automation is in force", name)
		}
	}
	// An empty list and null name nothing.
	for _, field := range []string{`,"write":[]`, `,"write":null`} {
		block := strings.Replace(readerBlock, `}`, field+`}`, 1)
		if _, err := Parse([]byte(writeGrantCatalog(block))); err != nil {
			t.Errorf("%s: %v", field, err)
		}
	}
	// A write entry the catalog drops takes its Automation with it.
	broken := strings.Replace(writeGrantCatalog(writerBlock), `"operations":["pr.open"`, `"operations":["pr.merge"`, 1)
	c, dropped, err := ParseTolerant([]byte(broken))
	if err != nil || c.Automations() != 0 || !strings.Contains(droppedNames(dropped), "automation:auto-writer") {
		t.Errorf("an Automation naming a dropped write entry: kept %d, dropped %q, %v", c.Automations(), droppedNames(dropped), err)
	}
}

// Every GitHub operation is classified on purpose: the reads an Automation
// without a write grant may use are exactly the four read operations and
// graphql, and an operation added later, or one this broker does not know, is
// a write until someone lists it as a read.
func TestGitHubOperationWritesClassifiesEveryOperation(t *testing.T) {
	reads := []string{"actions.read", "deployments.read", "graphql", "pr.list", "pr.read"}
	for op := range githubOperations {
		if want := !slices.Contains(reads, op); GitHubOperationWrites(op) != want {
			t.Errorf("%s: writes %v, want %v", op, GitHubOperationWrites(op), want)
		}
	}
	for _, op := range reads {
		if _, ok := githubOperations[op]; !ok {
			t.Errorf("the read operation %s is not a GitHub operation", op)
		}
	}
	if len(githubReadOperations) != len(reads) {
		t.Errorf("%d read operations, want %d", len(githubReadOperations), len(reads))
	}
	for _, op := range []string{"", "pr.merge", "pr.review", "PR.READ"} {
		if !GitHubOperationWrites(op) {
			t.Errorf("%q counts as a read", op)
		}
	}
}

// WriteEntries is what a matched request needs the Automation's write grant
// for: a push and each write operation need their entry, a CI restart needs
// the git entry its branch relies on as well, and a fetch or read needs none.
func TestWriteEntriesNameTheGrantsARequestNeeds(t *testing.T) {
	c, err := Parse([]byte(writeGrantCatalog(readerBlock)))
	if err != nil {
		t.Fatal(err)
	}
	const repo = "/example-org/example-app"
	for _, tc := range []struct {
		name, method, path, query, want string
		api                             bool
	}{
		{"clone", "POST", repo + ".git/git-upload-pack", "", "", false},
		{"fetch advertisement", "GET", repo + ".git/info/refs", "service=git-upload-pack", "", false},
		{"push advertisement", "GET", repo + ".git/info/refs", "service=git-receive-pack", "repo-git", false},
		{"push", "POST", repo + ".git/git-receive-pack", "", "repo-git", false},
		{"read a pull request", "GET", "/repos/example-org/example-app/pulls/1", "", "", true},
		{"list pull requests", "GET", "/repos/example-org/example-app/pulls", "", "", true},
		{"open a pull request", "POST", "/repos/example-org/example-app/pulls", "", "repo-api", true},
		{"comment", "POST", "/repos/example-org/example-app/issues/1/comments", "", "repo-api", true},
		{"update a branch", "PUT", "/repos/example-org/example-app/pulls/1/update-branch", "", "repo-api,repo-git", true},
	} {
		var g GitRequest
		var matchErr error
		if tc.api {
			g, _, matchErr = c.GitHubAPIMatch("api.github.com", 443, tc.method, tc.path, tc.query, "automations")
		} else {
			g, _, matchErr = c.GitMatch("github.com", 443, tc.method, tc.path, tc.query, "automations")
		}
		if matchErr != nil {
			t.Errorf("%s: %v", tc.name, matchErr)
			continue
		}
		if got := strings.Join(g.WriteEntries(), ","); got != tc.want {
			t.Errorf("%s needs write on %q, want %q", tc.name, got, tc.want)
		}
	}
	// A request built outside the routes names no operation, and is held as a
	// write rather than skipped; one with no entry needs nothing.
	held := GitRequest{Entry: &Entry{Name: "repo-api", Kind: "github-api"}}
	if got := held.WriteEntries(); len(got) != 1 || got[0] != "repo-api" {
		t.Errorf("a github-api request with no operation needs %v", got)
	}
	if got := (GitRequest{}).WriteEntries(); got != nil {
		t.Errorf("an empty request needs %v", got)
	}
	if !errors.Is(ErrAutomationReadOnly, ErrAutomationReadOnly) || errors.Is(ErrAutomationReadOnly, ErrReadOnly) {
		t.Error("ErrAutomationReadOnly is its own error")
	}
}
