package httpcatalog

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// ghFixture is one gh command's requests, recorded from gh 2.89.0 against a
// local mock server with no GitHub token. {{PR}} and {{LABEL}} stand for the
// node IDs gh had just read.
type ghFixture struct {
	Requests []struct {
		Method  string            `json:"method"`
		Path    string            `json:"path"`
		Headers map[string]string `json:"headers"`
		Body    string            `json:"body"`
	} `json:"requests"`
}

func readGhFixture(t *testing.T, name string) ghFixture {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "gh", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var f ghFixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

const (
	fixturePR    = "PR_kwDNA-jNB9A" // [0, 1000, 2000]
	fixtureLabel = "LA_kwDNA-jNB9E" // [0, 1000, 2001]
)

// Every GraphQL request gh sends for the supported commands maps to the
// operations it needs, and GitHub would receive it rebuilt.
func TestGraphQLMapsEveryGhRequest(t *testing.T) {
	const repo = "example-org/example-repo"
	read := []string{"pr.read"}
	list := []string{"pr.list", "pr.read"} // every query also needs pr.read
	for _, tc := range []struct {
		fixture string
		want    [][]string // per GraphQL request: its operations; nil for the broker's own answer
		targets [][]GraphQLTarget
	}{
		{"pr-view-number", [][]string{read, read}, nil},
		{"pr-view-url", [][]string{read, read}, nil},
		{"pr-view-comments", [][]string{read, read}, nil},
		{"pr-view-json", [][]string{read}, nil},
		{"pr-view-branch", [][]string{list, read}, nil},
		{"pr-list", [][]string{list}, nil},
		{"pr-list-all-json", [][]string{list}, nil},
		{"pr-list-head", [][]string{list}, nil},
		{"pr-list-limit-200", [][]string{list}, nil},
		{"pr-status", [][]string{list}, nil},
		{"pr-comment", [][]string{read, {"pr.comment", "pr.read"}}, [][]GraphQLTarget{nil, {{fixturePR, TargetPullRequestWrite}}}},
		{"pr-edit-body", [][]string{read, read, {"pr.edit"}}, [][]GraphQLTarget{nil, nil, {{fixturePR, TargetPullRequestWrite}}}},
		{"pr-edit-add-label", [][]string{read, read, {"pr.label", "pr.read"}, {"pr.label"}},
			[][]GraphQLTarget{nil, nil, nil, {{fixturePR, TargetPullRequestWrite}, {fixtureLabel, TargetLabel}}}},
		{"pr-ready", [][]string{read, {"pr.read", "pr.ready"}}, [][]GraphQLTarget{nil, {{fixturePR, TargetPullRequestWrite}}}},
		{"pr-ready-undo", [][]string{read, {"pr.read", "pr.ready"}}, [][]GraphQLTarget{nil, {{fixturePR, TargetPullRequestWrite}}}},
		{"pr-checks", [][]string{read, nil, nil, read}, [][]GraphQLTarget{nil, nil, nil, {{fixturePR, TargetPullRequest}}}},
		{"pr-checks-json", [][]string{read, read}, [][]GraphQLTarget{nil, {{fixturePR, TargetPullRequest}}}},
	} {
		i := 0
		for _, r := range readGhFixture(t, tc.fixture).Requests {
			if r.Path != "/graphql" {
				continue
			}
			body := strings.NewReplacer("{{PR}}", fixturePR, "{{LABEL}}", fixtureLabel).Replace(r.Body)
			got, err := ParseGitHubGraphQL([]byte(body))
			if err != nil {
				t.Fatalf("%s request %d: %v", tc.fixture, i, err)
			}
			want := tc.want[i]
			switch {
			case want == nil:
				if got.Answer == nil || got.Body != nil {
					t.Errorf("%s request %d: not answered by the broker", tc.fixture, i)
				}
			case !reflect.DeepEqual(got.Operations, want):
				t.Errorf("%s request %d: operations %v, want %v", tc.fixture, i, got.Operations, want)
			case len(got.Targets) == 0 && got.Repo != repo:
				t.Errorf("%s request %d: repository %q", tc.fixture, i, got.Repo)
			}
			var targets []GraphQLTarget
			if tc.targets != nil {
				targets = tc.targets[i]
			}
			if !reflect.DeepEqual(got.Targets, targets) {
				t.Errorf("%s request %d: targets %v, want %v", tc.fixture, i, got.Targets, targets)
			}
			// Only gh pr ready's mutation needs contents write.
			if wantContents := tc.fixture == "pr-ready" && i == 1; got.ContentsWrite != wantContents {
				t.Errorf("%s request %d: contents write %v, want %v", tc.fixture, i, got.ContentsWrite, wantContents)
			}
			if want != nil {
				// The rebuilt request parses to the same result.
				again, err := ParseGitHubGraphQL(got.Body)
				if err != nil || !reflect.DeepEqual(again.Operations, got.Operations) || !reflect.DeepEqual(again.Targets, got.Targets) ||
					string(again.Body) != string(got.Body) {
					t.Errorf("%s request %d: rebuilt body reads differently: %v", tc.fixture, i, err)
				}
			}
			i++
		}
		if i != len(tc.want) {
			t.Errorf("%s: %d GraphQL requests, want %d", tc.fixture, i, len(tc.want))
		}
	}
}

// The ready mutation's token carries contents write, so its payload may read
// back the pull request's id, number and draft state and nothing more; every
// other request's token has no contents.
func TestGraphQLReadyNeedsContentsWrite(t *testing.T) {
	ready := `mutation($input: MarkPullRequestReadyForReviewInput!) { markPullRequestReadyForReview(input: $input) { __typename clientMutationId pullRequest { __typename id number isDraft } } }`
	got, err := ParseGitHubGraphQL(graphqlBody(ready, map[string]any{"input": map[string]any{"pullRequestId": fixturePR}}))
	if err != nil || !got.ContentsWrite || got.Write != "pr.ready" {
		t.Fatalf("ready: %+v %v", got, err)
	}
	comment := `mutation($input: AddCommentInput!) { addComment(input: $input) { clientMutationId } }`
	got, err = ParseGitHubGraphQL(graphqlBody(comment, map[string]any{"input": map[string]any{"subjectId": fixturePR, "body": "x"}}))
	if err != nil || got.ContentsWrite {
		t.Fatalf("comment: %+v %v", got, err)
	}
}

func graphqlBody(query string, variables map[string]any) []byte {
	b, _ := json.Marshal(map[string]any{"query": query, "variables": variables})
	return b
}

func TestGraphQLRefusals(t *testing.T) {
	repoVars := map[string]any{"owner": "example-org", "repo": "example-repo"}
	repoQuery := func(inner string) string {
		return `query($owner: String!, $repo: String!) { repository(owner: $owner, name: $repo) { ` + inner + ` } }`
	}
	comment := func(input map[string]any) []byte {
		return graphqlBody(`mutation($input: AddCommentInput!) { addComment(input: $input) { clientMutationId } }`, map[string]any{"input": input})
	}
	ready := func(payload string) []byte {
		return graphqlBody(`mutation($input: MarkPullRequestReadyForReviewInput!) { markPullRequestReadyForReview(input: $input) { `+payload+` } }`,
			map[string]any{"input": map[string]any{"pullRequestId": "PR_kwDNA-jNB9A"}})
	}
	deep := "pullRequest(number: 1) { " + strings.Repeat("author { ", 25) + "login" + strings.Repeat(" }", 25) + " }"
	aliases := ""
	for i := range 11 {
		aliases += "a" + string(rune('a'+i)) + ": pullRequest(number: 1) { id } "
	}
	for _, tc := range []struct {
		name string
		body []byte
		want *GraphQLError
	}{
		{"not JSON", []byte(`query { x }`), ErrGraphQLShape},
		{"unknown key", []byte(`{"query":"query { x }","extensions":{}}`), ErrGraphQLShape},
		{"no query", []byte(`{"variables":{}}`), ErrGraphQLShape},
		{"trailing data", []byte(`{"query":"query { x }"} {}`), ErrGraphQLShape},
		{"parse error", graphqlBody(`query {`, nil), ErrGraphQLShape},
		{"two operations", graphqlBody(`query a { viewer { login } } query b { viewer { login } }`, nil), ErrGraphQLShape},
		{"wrong operation name", []byte(`{"query":"query a { repository(owner: \"o\", name: \"r\") { pullRequest(number: 1) { id } } }","operationName":"b"}`), ErrGraphQLShape},
		{"duplicate argument", graphqlBody(`query { repository(owner: "o", owner: "x", name: "r") { pullRequest(number: 1) { id } } }`, nil), ErrGraphQLShape},
		{"duplicate input field", graphqlBody(`query { repository(owner: "o", name: "r") { pullRequests(orderBy: {field: CREATED_AT, field: UPDATED_AT}, first: 1) { totalCount } } }`, nil), ErrGraphQLShape},
		{"fragment cycle", graphqlBody(repoQuery(`pullRequest(number: 1) { ...a }`)+` fragment a on PullRequest { author { ...a } }`, repoVars), ErrGraphQLShape},
		{"unknown fragment", graphqlBody(repoQuery(`pullRequest(number: 1) { ...missing }`), repoVars), ErrGraphQLShape},
		{"duplicate fragment", graphqlBody(repoQuery(`pullRequest(number: 1) { ...f }`)+` fragment f on PullRequest { id } fragment f on PullRequest { title }`, repoVars), ErrGraphQLShape},
		// The printer drops a variable definition's directives, so GitHub would
		// read something other than what was checked.
		{"directive on a variable", graphqlBody(`query($owner: String! @deprecated, $repo: String!) { repository(owner: $owner, name: $repo) { pullRequest(number: 1) { id } } }`, repoVars), ErrGraphQLShape},
		{"too many tokens", graphqlBody(repoQuery(`pullRequest(number: 1) { `+strings.Repeat("id ", maxGraphQLTokens)+`}`), repoVars), ErrGraphQLLimit},
		{"oversized document", graphqlBody(repoQuery(`pullRequest(number: 1) { id }`)+strings.Repeat(" ", maxGraphQLDocument), repoVars), ErrGraphQLLimit},

		{"subscription", graphqlBody(`subscription { repository(owner: "o", name: "r") { id } }`, nil), ErrGraphQLUnmapped},
		{"viewer", graphqlBody(`query { viewer { login } }`, nil), ErrGraphQLUnmapped},
		{"organization", graphqlBody(`query { organization(login: "o") { repositories(first: 5) { nodes { name } } } }`, nil), ErrGraphQLUnmapped},
		{"another repository field", graphqlBody(repoQuery(`collaborators(first: 5) { nodes { login } }`), repoVars), ErrGraphQLUnmapped},
		{"repository object", graphqlBody(repoQuery(`object(expression: "main:secrets.txt") { id }`), repoVars), ErrGraphQLUnmapped},
		// History, blame and compare read a branch's commits and code, which
		// only a git entry grants, at any depth.
		{"history", graphqlBody(repoQuery(`pullRequest(number: 1) { commits(first: 1) { nodes { commit { history(first: 100) { nodes { message } } } } } }`), repoVars), ErrGraphQLUnmapped},
		{"blame", graphqlBody(repoQuery(`pullRequest(number: 1) { commits(first: 1) { nodes { commit { blame(path: "main.go") { ranges { startingLine } } } } } }`), repoVars), ErrGraphQLUnmapped},
		{"compare", graphqlBody(repoQuery(`pullRequest(number: 1) { headRef { compare(headRef: "main") { aheadBy } } }`), repoVars), ErrGraphQLUnmapped},
		{"history in a fragment", graphqlBody(repoQuery(`pullRequest(number: 1) { headRef { target { ...c } } }`)+` fragment c on Commit { history(first: 1) { totalCount } }`, repoVars), ErrGraphQLUnmapped},
		{"fragment at the root", graphqlBody(`query { ...q } fragment q on Query { viewer { login } }`, nil), ErrGraphQLUnmapped},
		{"fragment under repository", graphqlBody(repoQuery(`...r`)+` fragment r on Repository { collaborators(first: 1) { totalCount } }`, repoVars), ErrGraphQLUnmapped},
		{"directive", graphqlBody(repoQuery(`pullRequest(number: 1) @include(if: true) { id }`), repoVars), ErrGraphQLUnmapped},
		{"directive on the operation", graphqlBody(`query($owner: String!, $repo: String!) @include(if: true) { repository(owner: $owner, name: $repo) { pullRequest(number: 1) { id } } }`, repoVars), ErrGraphQLUnmapped},
		{"directive on a fragment", graphqlBody(repoQuery(`pullRequest(number: 1) { ...f }`)+` fragment f on PullRequest @include(if: true) { id }`, repoVars), ErrGraphQLUnmapped},
		{"repository name with ..", graphqlBody(`query { repository(owner: "o", name: "r..s") { pullRequest(number: 1) { id } } }`, nil), ErrGraphQLUnmapped},
		{"search with ..", graphqlBody(`query { search(query: "repo:o/r..s", type: ISSUE, first: 5) { issueCount } }`, nil), ErrGraphQLUnmapped},
		{"search with a quoted term", graphqlBody(`query { search(query: "repo:o/r \"org:x\"", type: ISSUE, first: 5) { issueCount } }`, nil), ErrGraphQLUnmapped},
		{"node of another type", graphqlBody(`query { node(id: "R_kgDNA-g") { ... on Repository { collaborators(first: 1) { totalCount } } } }`, nil), ErrGraphQLUnmapped},
		{"nodes", graphqlBody(`query { nodes(ids: ["PR_kwDNA-jNB9A"]) { id } }`, nil), ErrGraphQLUnmapped},
		{"empty node ID", graphqlBody(`query { node(id: "") { id } }`, nil), ErrGraphQLUnmapped},
		{"search without a repository", graphqlBody(`query { search(query: "is:pr author:@me", type: ISSUE, first: 5) { issueCount } }`, nil), ErrGraphQLUnmapped},
		{"search across an organization", graphqlBody(`query { search(query: "repo:o/r org:o", type: ISSUE, first: 5) { issueCount } }`, nil), ErrGraphQLUnmapped},
		{"search with a grouped qualifier", graphqlBody(`query { search(query: "repo:o/r (org:p)", type: ISSUE, first: 5) { issueCount } }`, nil), ErrGraphQLUnmapped},
		{"search with a grouped repository", graphqlBody(`query { search(query: "repo:o/r (repo:p/s)", type: ISSUE, first: 5) { issueCount } }`, nil), ErrGraphQLUnmapped},
		{"search excluding a repository", graphqlBody(`query { search(query: "is:pr -repo:o/r", type: ISSUE, first: 5) { issueCount } }`, nil), ErrGraphQLUnmapped},
		{"search two repositories", graphqlBody(`query { search(query: "repo:o/r repo:o/s", type: ISSUE, first: 5) { issueCount } }`, nil), ErrGraphQLUnmapped},
		{"search code", graphqlBody(`query { search(query: "repo:o/r token", type: REPOSITORY, first: 5) { issueCount } }`, nil), ErrGraphQLUnmapped},
		{"merge", graphqlBody(`mutation($input: MergePullRequestInput!) { mergePullRequest(input: $input) { clientMutationId } }`,
			map[string]any{"input": map[string]any{"pullRequestId": "PR_kwDNA-jNB9A"}}), ErrGraphQLUnmapped},
		{"approve", graphqlBody(`mutation($input: AddPullRequestReviewInput!) { addPullRequestReview(input: $input) { clientMutationId } }`,
			map[string]any{"input": map[string]any{"pullRequestId": "PR_kwDNA-jNB9A", "event": "APPROVE"}}), ErrGraphQLUnmapped},
		{"two mutations", graphqlBody(`mutation($input: AddCommentInput!) { a: addComment(input: $input) { clientMutationId } b: addComment(input: $input) { clientMutationId } }`,
			map[string]any{"input": map[string]any{"subjectId": "PR_kwDNA-jNB9A", "body": "x"}}), ErrGraphQLUnmapped},
		{"aliased mutation", graphqlBody(`mutation($input: AddCommentInput!) { c: addComment(input: $input) { clientMutationId } }`,
			map[string]any{"input": map[string]any{"subjectId": "PR_kwDNA-jNB9A", "body": "x"}}), ErrGraphQLUnmapped},
		// Only the first field is mapped, so a second, unaliased one would be
		// printed and sent unchecked.
		{"an allowed mutation, then another", graphqlBody(`mutation($input: AddCommentInput!, $merge: MergePullRequestInput!) { addComment(input: $input) { clientMutationId } mergePullRequest(input: $merge) { clientMutationId } }`,
			map[string]any{"input": map[string]any{"subjectId": "PR_kwDNA-jNB9A", "body": "x"}, "merge": map[string]any{"pullRequestId": "PR_kwDNA-jNB9A"}}), ErrGraphQLUnmapped},
		// pr.ready's token carries contents write: its payload reads back the
		// pull request's id, number and draft state, and nothing more.
		{"ready reading the body", ready(`pullRequest { body }`), ErrGraphQLUnmapped},
		{"ready reading the head's commits", ready(`pullRequest { headRef { target { ... on Commit { message } } } }`), ErrGraphQLUnmapped},
		{"ready with an aliased field", ready(`pullRequest { n: number }`), ErrGraphQLUnmapped},
		{"ready with an inline fragment", ready(`pullRequest { ... on PullRequest { number } }`), ErrGraphQLUnmapped},
		{"ready with a fragment", graphqlBody(`mutation($input: MarkPullRequestReadyForReviewInput!) { markPullRequestReadyForReview(input: $input) { pullRequest { ...f } } } fragment f on PullRequest { number }`,
			map[string]any{"input": map[string]any{"pullRequestId": "PR_kwDNA-jNB9A"}}), ErrGraphQLUnmapped},
		{"ready with an unused fragment", graphqlBody(`mutation($input: MarkPullRequestReadyForReviewInput!) { markPullRequestReadyForReview(input: $input) { clientMutationId } } fragment f on PullRequest { number }`,
			map[string]any{"input": map[string]any{"pullRequestId": "PR_kwDNA-jNB9A"}}), ErrGraphQLUnmapped},
		{"ready reading another payload field", ready(`pullRequest { id } clientMutationId __typename actor { login }`), ErrGraphQLUnmapped},
		{"comment with an empty target", comment(map[string]any{"subjectId": "", "body": "x"}), ErrGraphQLUnmapped},
		{"literal input", graphqlBody(`mutation { addComment(input: {subjectId: "PR_kwDNA-jNB9A", body: "x"}) { clientMutationId } }`, nil), ErrGraphQLUnmapped},
		{"edit the title", graphqlBody(`mutation($input: UpdatePullRequestInput!) { updatePullRequest(input: $input) { clientMutationId } }`,
			map[string]any{"input": map[string]any{"pullRequestId": "PR_kwDNA-jNB9A", "title": "x"}}), ErrGraphQLUnmapped},
		{"edit the state", graphqlBody(`mutation($input: UpdatePullRequestInput!) { updatePullRequest(input: $input) { clientMutationId } }`,
			map[string]any{"input": map[string]any{"pullRequestId": "PR_kwDNA-jNB9A", "body": "x", "state": "CLOSED"}}), ErrGraphQLUnmapped},
		{"comment without a target", comment(map[string]any{"body": "x"}), ErrGraphQLUnmapped},
		{"comment with a number target", comment(map[string]any{"subjectId": 12, "body": "x"}), ErrGraphQLUnmapped},
		{"comment input not an object", graphqlBody(`mutation($input: AddCommentInput!) { addComment(input: $input) { clientMutationId } }`, map[string]any{"input": "x"}), ErrGraphQLUnmapped},
		{"too many labels", graphqlBody(`mutation($input: AddLabelsToLabelableInput!) { addLabelsToLabelable(input: $input) { clientMutationId } }`,
			map[string]any{"input": map[string]any{"labelableId": "PR_kwDNA-jNB9A", "labelIds": func() []any {
				out := make([]any, 100)
				for i := range out {
					out[i] = "LA_kwDNA-jNB9E"
				}
				return out
			}()}}), ErrGraphQLUnmapped},
		{"label without labels", graphqlBody(`mutation($input: AddLabelsToLabelableInput!) { addLabelsToLabelable(input: $input) { clientMutationId } }`,
			map[string]any{"input": map[string]any{"labelableId": "PR_kwDNA-jNB9A", "labelIds": []any{}}}), ErrGraphQLUnmapped},
		{"label ID not a list", graphqlBody(`mutation($input: AddLabelsToLabelableInput!) { addLabelsToLabelable(input: $input) { clientMutationId } }`,
			map[string]any{"input": map[string]any{"labelableId": "PR_kwDNA-jNB9A", "labelIds": "LA_kwDNA-jNB9E"}}), ErrGraphQLUnmapped},

		{"too many aliases", graphqlBody(repoQuery(aliases), repoVars), ErrGraphQLLimit},
		{"too deep", graphqlBody(repoQuery(deep), repoVars), ErrGraphQLLimit},
		{"first above 100", graphqlBody(repoQuery(`pullRequests(first: 101) { totalCount }`), repoVars), ErrGraphQLLimit},
		{"last above 100 deep down", graphqlBody(repoQuery(`pullRequest(number: 1) { commits(last: 1000) { totalCount } }`), repoVars), ErrGraphQLLimit},
		{"first from a variable", graphqlBody(`query($owner: String!, $repo: String!, $n: Int) { repository(owner: $owner, name: $repo) { pullRequests(first: $n) { totalCount } } }`,
			map[string]any{"owner": "o", "repo": "r", "n": 5000}), ErrGraphQLLimit},
		{"first from a default", graphqlBody(`query($owner: String!, $repo: String!, $n: Int = 5000) { repository(owner: $owner, name: $repo) { pullRequests(first: $n) { totalCount } } }`,
			repoVars), ErrGraphQLLimit},
		{"first not a number", graphqlBody(repoQuery(`pullRequests(first: "5") { totalCount }`), repoVars), ErrGraphQLLimit},
		{"negative first", graphqlBody(repoQuery(`pullRequests(first: -1) { totalCount }`), repoVars), ErrGraphQLLimit},
		{"fragment fan-out", graphqlBody(repoQuery(`pullRequests(first: 1) { nodes { ...f1 } }`)+
			` fragment f1 on PullRequest { `+strings.Repeat(`author { ...f2 } `, 10)+`}`+
			` fragment f2 on Actor { `+strings.Repeat(`...f3 `, 10)+`}`+
			` fragment f3 on Actor { login url resourcePath avatarUrl login url resourcePath avatarUrl login url }`, repoVars), ErrGraphQLLimit},

		{"request fan-out", graphqlBody(repoQuery(`pullRequests(first: 100) { nodes { reviews(first: 100) { totalCount } `+
			`commits(first: 100) { nodes { commit { a: associatedPullRequests(first: 1) { totalCount } b: comments(first: 1) { totalCount } } } } `+
			`comments(first: 100) { totalCount } } }`), repoVars), ErrGraphQLLimit},

		{"schema introspection", graphqlBody(`query { __schema { types { name } } }`, nil), ErrGraphQLIntrospection},
		{"type of another name", graphqlBody(`query { __type(name: "Repository") { fields(includeDeprecated: true) { name } } }`, nil), ErrGraphQLIntrospection},
		{"type with more fields", graphqlBody(`query { __type(name: "PullRequest") { fields(includeDeprecated: true) { name args { name } } } }`, nil), ErrGraphQLIntrospection},
		{"type beside a repository", graphqlBody(`query { repository(owner: "o", name: "r") { pullRequest(number: 1) { id } } __type(name: "PullRequest") { name } }`, nil), ErrGraphQLIntrospection},
		{"nested introspection", graphqlBody(repoQuery(`pullRequest(number: 1) { __type(name: "User") { name } }`), repoVars), ErrGraphQLIntrospection},

		{"two repositories", graphqlBody(`query { a: repository(owner: "o", name: "r") { pullRequest(number: 1) { id } } b: repository(owner: "o", name: "s") { pullRequest(number: 1) { id } } }`, nil), ErrGraphQLRepository},
		{"repository and another search", graphqlBody(`query { repository(owner: "o", name: "r") { pullRequest(number: 1) { id } } search(query: "repo:o/s", type: ISSUE, first: 1) { issueCount } }`, nil), ErrGraphQLRepository},
		{"no repository", graphqlBody(`query { __typename }`, nil), ErrGraphQLRepository},
	} {
		_, err := ParseGitHubGraphQL(tc.body)
		var got *GraphQLError
		if !errors.As(err, &got) || got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
}

// A variable the document does not declare never reaches GitHub, nor do
// comments or the operation name; the repository is read case-insensitively.
func TestGraphQLRebuildsTheRequest(t *testing.T) {
	body := []byte(`{"query":"query Q($owner: String!, $repo: String!) {\n  repository(owner: $owner, name: $repo) { pullRequest(number: 1) { id } } # comment\n}",` +
		`"variables":{"owner":"Example-Org","repo":"example-repo","extra":"dropped"},"operationName":"Q"}`)
	got, err := ParseGitHubGraphQL(body)
	if err != nil {
		t.Fatal(err)
	}
	if got.Repo != "example-org/example-repo" || strings.Contains(string(got.Body), "extra") || strings.Contains(string(got.Body), "comment") ||
		strings.Contains(string(got.Body), "operationName") {
		t.Fatalf("rebuilt: repo %q body %s", got.Repo, got.Body)
	}
	answer, err := ParseGitHubGraphQL(graphqlBody(`query PullRequest_fields2{WorkflowRun: __type(name: "WorkflowRun"){fields(includeDeprecated: true){name}}}`, nil))
	if err != nil || string(answer.Answer) != `{"data":{"WorkflowRun":{"fields":[{"name":"event"}]}}}` {
		t.Fatalf("feature detection: %v %s", err, answer.Answer)
	}
}

// Below a mapped field any selection is allowed, so every query needs
// pr.read, whatever else it needs.
func TestGraphQLQueriesNeedPullRequestRead(t *testing.T) {
	vars := map[string]any{"owner": "example-org", "repo": "example-repo"}
	for _, inner := range []string{
		`labels(first: 100) { nodes { pullRequests(first: 100) { nodes { body } } } }`,
		`defaultBranchRef { target { ... on Commit { associatedPullRequests(first: 5) { nodes { body } } } } }`,
	} {
		got, err := ParseGitHubGraphQL(graphqlBody(`query($owner: String!, $repo: String!) { repository(owner: $owner, name: $repo) { `+inner+` } }`, vars))
		if err != nil || !strings.Contains(strings.Join(got.Operations, " "), "pr.read") {
			t.Errorf("%s: %v %v", inner, got.Operations, err)
		}
	}
}

// Files are a git entry's grant: every field or type that reads them is
// refused at any depth (and the GraphQL token has no contents permission).
func TestGraphQLRefusesRepositoryContents(t *testing.T) {
	vars := map[string]any{"owner": "example-org", "repo": "example-repo"}
	for _, inner := range []string{
		`defaultBranchRef { target { ... on Commit { file(path: "secrets.env") { object { ... on Blob { text } } } } } }`,
		`pullRequest(number: 1) { repository { object(expression: "HEAD:main.go") { ... on Blob { text } } } }`,
		`pullRequest(number: 1) { headRef { target { ... on Commit { tree { entries { name } } } } } }`,
		`pullRequest(number: 1) { mergeCommit { tree { id } } }`,
		`pullRequest(number: 1) { baseRepository { readme: object(expression: "HEAD:README.md") { id } } }`,
		`pullRequest(number: 1) { headRef { target { ...b } } }`,
		`pullRequest(number: 1) { headRef { target { ... on Tree { id } } } }`,
		`pullRequest(number: 1) { repository { contributingGuidelines { body } } }`,
		`pullRequest(number: 1) { repository { codeOfConduct { body } } }`,
		`pullRequest(number: 1) { repository { pullRequestTemplates { body } } }`,
		`pullRequest(number: 1) { repository { issueTemplates { body } } }`,
		`pullRequest(number: 1) { reviewThreads(first: 10) { nodes { comments(first: 10) { nodes { diffHunk } } } } }`,
	} {
		query := `query($owner: String!, $repo: String!) { repository(owner: $owner, name: $repo) { ` + inner + ` } }`
		if strings.Contains(inner, "...b") {
			query += ` fragment b on Blob { text }`
		}
		_, err := ParseGitHubGraphQL(graphqlBody(query, vars))
		if !errors.Is(err, ErrGraphQLUnmapped) {
			t.Errorf("%s: %v, want graphql_unmapped", inner, err)
		}
	}
}

// A mutation's payload is read like a query: anything beyond __typename and
// clientMutationId needs pr.read, so a write grant alone reads nothing.
func TestGraphQLMutationPayloadNeedsPullRequestRead(t *testing.T) {
	input := map[string]any{"input": map[string]any{"subjectId": "PR_kwDNA-jNB9A", "body": "x"}}
	for payload, want := range map[string]string{
		`clientMutationId`:             "pr.comment",
		`__typename clientMutationId`:  "pr.comment",
		`commentEdge { node { url } }`: "pr.comment pr.read",
		`subject { ... on PullRequest { number comments(first: 1) { nodes { body } } } }`: "pr.comment pr.read",
		// A repository reached from the payload is mapped as at the root.
		`subject { ... on PullRequest { repository { pullRequests(first: 1) { nodes { body comments(first: 1) { nodes { body } } } } } } }`: "pr.comment pr.list pr.read",
	} {
		got, err := ParseGitHubGraphQL(graphqlBody(`mutation($input: AddCommentInput!) { addComment(input: $input) { `+payload+` } }`, input))
		if err != nil || strings.Join(got.Operations, " ") != want {
			t.Errorf("%s: %v %v, want %s", payload, got.Operations, err, want)
		}
	}
}

// GitHub receives the parsed document printed again, and only when that
// print reads back as itself: a string the printer cannot write faithfully
// (a control character) is refused rather than sent changed.
func TestGraphQLRefusesWhatCannotBePrintedFaithfully(t *testing.T) {
	body := []byte(`{"query":"query { repository(owner: \"o\", name: \"r\") { pullRequests(headRefName: \"x\\u0007\", first: 1) { totalCount } } }"}`)
	if _, err := ParseGitHubGraphQL(body); !errors.Is(err, ErrGraphQLShape) {
		t.Fatalf("control character: %v, want graphql_shape", err)
	}
}

// An audit row names one operation: the write a mutation makes, or graphql
// for a read, never the read a payload adds.
func TestGraphQLAuditOperation(t *testing.T) {
	for fixture, want := range map[string][]string{
		"pr-comment":        {"graphql", "pr.comment"},
		"pr-edit-body":      {"graphql", "graphql", "pr.edit"},
		"pr-edit-add-label": {"graphql", "graphql", "graphql", "pr.label"},
		"pr-ready":          {"graphql", "pr.ready"},
		"pr-ready-undo":     {"graphql", "pr.ready"},
		"pr-list":           {"graphql"},
	} {
		var got []string
		for _, r := range readGhFixture(t, fixture).Requests {
			body := strings.NewReplacer("{{PR}}", fixturePR, "{{LABEL}}", fixtureLabel).Replace(r.Body)
			req, err := ParseGitHubGraphQL([]byte(body))
			if err != nil {
				t.Fatalf("%s: %v", fixture, err)
			}
			got = append(got, req.AuditOperation())
		}
		if strings.Join(got, " ") != strings.Join(want, " ") {
			t.Errorf("%s: %v, want %v", fixture, got, want)
		}
	}
}

// A request that reads which files a pull request changes is marked Code,
// for the clone grant REST asks for the same list; gh's default commands
// read none.
func TestGraphQLMarksFileListsAsCode(t *testing.T) {
	vars := map[string]any{"owner": "example-org", "repo": "example-repo"}
	for inner, want := range map[string]bool{
		`pullRequest(number: 1) { files(first: 100) { nodes { path additions deletions } } }`: true,
		`pullRequest(number: 1) { reviewThreads(first: 10) { nodes { path } } }`:              true,
		`pullRequest(number: 1) { ...f }`:                                                     true,
		`pullRequest(number: 1) { changedFiles additions deletions title }`:                   false,
		`pullRequests(first: 5) { nodes { number headRefName } }`:                             false,
	} {
		query := `query($owner: String!, $repo: String!) { repository(owner: $owner, name: $repo) { ` + inner + ` } }`
		if strings.Contains(inner, "...f") {
			query += ` fragment f on PullRequest { files(first: 1) { nodes { path } } }`
		}
		got, err := ParseGitHubGraphQL(graphqlBody(query, vars))
		if err != nil || got.Code != want {
			t.Errorf("%s: code %v err %v, want %v", inner, got.Code, err, want)
		}
	}
	files, _ := filepath.Glob("testdata/gh/*.json")
	for _, f := range files {
		var fx ghFixture
		data, _ := os.ReadFile(f)
		_ = json.Unmarshal(data, &fx)
		for _, r := range fx.Requests {
			if r.Path != "/graphql" {
				continue
			}
			body := strings.NewReplacer("{{PR}}", fixturePR, "{{LABEL}}", fixtureLabel).Replace(r.Body)
			if got, err := ParseGitHubGraphQL([]byte(body)); err == nil && got.Code {
				t.Errorf("%s: a gh default command reads file lists", filepath.Base(f))
			}
		}
	}
}

// A request reading check status is marked Checks, for the checks and
// statuses scopes, and one reading a check suite's workflow run is marked
// Actions, for the actions scope; gh's default view and checks read both,
// status reads check status only, list and the mutations read neither.
func TestGraphQLMarksCheckStatusReads(t *testing.T) {
	for fixture, want := range map[string][]string{ // per request: Checks/Actions
		"pr-view-number": {"true/true", "false/false"},
		"pr-view-branch": {"true/true", "false/false"},
		"pr-status":      {"true/false"},
		"pr-checks":      {"false/false", "false/false", "false/false", "true/true"},
		"pr-checks-json": {"false/false", "true/true"},
		"pr-list":        {"false/false"},
		"pr-comment":     {"false/false", "false/false"},
	} {
		var got []string
		for _, r := range readGhFixture(t, fixture).Requests {
			body := strings.NewReplacer("{{PR}}", fixturePR, "{{LABEL}}", fixtureLabel).Replace(r.Body)
			req, err := ParseGitHubGraphQL([]byte(body))
			if err != nil {
				t.Fatalf("%s: %v", fixture, err)
			}
			got = append(got, fmt.Sprintf("%v/%v", req.Checks, req.Actions))
		}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("%s: %v, want %v", fixture, got, want)
		}
	}
}

// A repository reached below the root is checked as the root one is: its
// pull request list and default branch need pr.list and its labels pr.label
// however it is reached, any other field with arguments or a selection is
// refused, and lists of repositories are refused outright. gh's own nested
// reads (a pull request's headRepository name) need nothing more.
func TestGraphQLNestedRepositoryNeedsTheSameOperations(t *testing.T) {
	vars := map[string]any{"owner": "example-org", "repo": "example-repo"}
	const pr = `repository(owner: $owner, name: $repo) { pullRequest(number: 12) { `
	const prEnd = ` } }`
	listed := "pr.list pr.read"
	for _, tc := range []struct {
		name, query, want string // want: the operations, or the refusal
		fragments         string
	}{
		{"a pull request's repository", pr + `repository { pullRequests(first: 100) { nodes { number body } } defaultBranchRef { name } labels(first: 100) { nodes { id name } } }` + prEnd,
			"pr.label pr.list pr.read", ""},
		{"baseRepository", pr + `baseRepository { defaultBranchRef { name } }` + prEnd, listed, ""},
		{"headRepository", pr + `headRepository { labels(first: 1) { nodes { id } } }` + prEnd, "pr.label pr.read", ""},
		{"a label's repository", pr + `labels(first: 1) { nodes { repository { pullRequests(first: 1) { totalCount } } } }` + prEnd, listed, ""},
		{"an event's fromRepository", pr + `timelineItems(first: 1) { nodes { ... on TransferredEvent { fromRepository { pullRequests(first: 1) { totalCount } } } } }` + prEnd, listed, ""},
		{"... on Repository in a union", pr + `author { ... on User { pinnedItems(first: 1) { nodes { ... on Repository { pullRequests(first: 1) { totalCount } } } } } }` + prEnd, listed, ""},
		{"a fragment on Repository", pr + `author { ... on User { pinnedItems(first: 1) { nodes { ...r } } } }` + prEnd, listed,
			`fragment r on Repository { pullRequests(first: 1) { totalCount } }`},
		// defaultBranchRef and labels need their operations only through the
		// repository check, inline and in a fragment definition alike.
		{"... on Repository, default branch and labels", pr + `author { ... on User { pinnedItems(first: 5) { nodes { ... on Repository { defaultBranchRef { name } labels(first: 5) { nodes { name } } } } } } }` + prEnd,
			"pr.label pr.list pr.read", ""},
		{"a fragment on Repository, default branch and labels", pr + `author { ... on User { pinnedItems(first: 5) { nodes { ...F } } } }` + prEnd,
			"pr.label pr.list pr.read", `fragment F on Repository { defaultBranchRef { name } labels(first: 5) { nodes { name } } }`},
		{"an inline fragment inside a repository", pr + `repository { ... on Repository { pullRequests(first: 1) { totalCount } } }` + prEnd, listed, ""},
		{"two levels down", pr + `repository { pullRequest(number: 2) { repository { defaultBranchRef { name } } } }` + prEnd, listed, ""},
		{"gh's own headRepository read", pr + `headRepository { __typename id name nameWithOwner } isCrossRepository` + prEnd, "pr.read", ""},

		{"another field of a nested repository", pr + `repository { issues(first: 1) { totalCount } }` + prEnd, "graphql_unmapped", ""},
		{"a nested repository's owner", pr + `baseRepository { owner { login } }` + prEnd, "graphql_unmapped", ""},
		{"an interface fragment inside a repository", pr + `repository { ... on RepositoryInfo { owner { login } } }` + prEnd, "graphql_unmapped", ""},
		{"a fragment spread inside a repository", pr + `repository { ...r }` + prEnd, "graphql_unmapped", `fragment r on Repository { name }`},
		{"a user's repositories", pr + `author { ... on User { repositories(first: 1) { nodes { name } } } }` + prEnd, "graphql_unmapped", ""},
		{"a user's watched repositories", pr + `author { ... on User { watching(first: 1) { nodes { name } } } }` + prEnd, "graphql_unmapped", ""},
		{"a user's starred repositories", pr + `author { ... on User { starredRepositories(first: 1) { nodes { name } } } }` + prEnd, "graphql_unmapped", ""},
		{"... on Repository, another field", pr + `author { ... on User { pinnedItems(first: 5) { nodes { ... on Repository { issues(first: 5) { nodes { title } } } } } } }` + prEnd,
			"graphql_unmapped", ""},
		{"a fragment on Repository, another field", pr + `author { ... on User { pinnedItems(first: 5) { nodes { ...F } } } }` + prEnd,
			"graphql_unmapped", `fragment F on Repository { issues(first: 5) { nodes { title } } }`},
		// A repository or owner looked up by name below the root could be
		// any repository; only ones related to the root's are read.
		{"a user's repository by name", pr + `author { ... on User { repository(name: "other") { pullRequest(number: 3) { body } } } }` + prEnd, "graphql_unmapped", ""},
		{"an owner's repository by name", pr + `headRepositoryOwner { repository(name: "other") { pullRequest(number: 3) { body } } }` + prEnd, "graphql_unmapped", ""},
		{"a user's organization by login", pr + `author { ... on User { organization(login: "other") { name } } }` + prEnd, "graphql_unmapped", ""},
		{"a repository by name in a fragment", pr + `author { ...u }` + prEnd, "graphql_unmapped", `fragment u on User { repository(name: "other") { pullRequest(number: 3) { body } } }`},
	} {
		query := `query($owner: String!, $repo: String!) { ` + tc.query + ` } ` + tc.fragments
		got, err := ParseGitHubGraphQL(graphqlBody(query, vars))
		var refusal *GraphQLError
		switch {
		case errors.As(err, &refusal):
			if refusal.Outcome != tc.want {
				t.Errorf("%s: refused %s, want %s", tc.name, refusal.Outcome, tc.want)
			}
		case err != nil:
			t.Errorf("%s: %v", tc.name, err)
		case strings.Join(got.Operations, " ") != tc.want:
			t.Errorf("%s: %v, want %s", tc.name, got.Operations, tc.want)
		}
	}
	// The same holds where the root is a node ID, a search or a mutation.
	for _, tc := range []struct {
		name string
		body []byte
		want string
	}{
		{"node", graphqlBody(`query($id: ID!) { node(id: $id) { ... on PullRequest { repository { pullRequests(first: 1) { totalCount } } } } }`,
			map[string]any{"id": fixturePR}), listed},
		{"search", graphqlBody(`query { search(query: "repo:example-org/example-repo is:pr", type: ISSUE, first: 1) { nodes { ... on PullRequest { repository { labels(first: 1) { totalCount } } } } } }`, nil),
			"pr.label pr.list pr.read"},
		{"mutation payload", graphqlBody(`mutation($input: AddCommentInput!) { addComment(input: $input) { subject { ... on PullRequest { baseRepository { defaultBranchRef { name } } } } } }`,
			map[string]any{"input": map[string]any{"subjectId": fixturePR, "body": "x"}}), "pr.comment pr.list pr.read"},
	} {
		got, err := ParseGitHubGraphQL(tc.body)
		if err != nil || strings.Join(got.Operations, " ") != tc.want {
			t.Errorf("%s: %v %v, want %s", tc.name, got.Operations, err, tc.want)
		}
	}
}

// Every list of pull requests needs pr.list wherever it is read, as a
// repository's pullRequests does: these are all the fields GitHub's schema
// has that list pull requests.
func TestGraphQLPullRequestListsNeedList(t *testing.T) {
	vars := map[string]any{"owner": "example-org", "repo": "example-repo"}
	for _, inner := range []string{
		`labels(first: 1) { nodes { pullRequests(first: 1) { totalCount } } }`,
		`milestone { pullRequests(first: 1) { totalCount } }`,
		`author { ... on User { pullRequests(first: 1) { nodes { body } } } }`,
		`headRef { associatedPullRequests(first: 1) { nodes { body } } }`,
		`commits(last: 1) { nodes { commit { associatedPullRequests(first: 1) { totalCount } } } }`,
		`commits(last: 1) { nodes { commit { checkSuites(first: 1) { nodes { matchingPullRequests(first: 1) { totalCount } } } } } }`,
		`closingIssuesReferences(first: 1) { nodes { closedByPullRequestsReferences(first: 1) { totalCount } } }`,
		`author { ... on User { contributionsCollection { pullRequestContributions(first: 1) { totalCount } } } }`,
		`author { ... on User { contributionsCollection { pullRequestReviewContributions(first: 1) { totalCount } } } }`,
		`author { ... on User { contributionsCollection { popularPullRequestContribution { pullRequest { body } } } } }`,
	} {
		query := `query($owner: String!, $repo: String!) { repository(owner: $owner, name: $repo) { pullRequest(number: 1) { ` + inner + ` } } }`
		got, err := ParseGitHubGraphQL(graphqlBody(query, vars))
		if err != nil || strings.Join(got.Operations, " ") != "pr.list pr.read" {
			t.Errorf("%s: %v %v, want pr.list pr.read", inner, got.Operations, err)
		}
	}
}
