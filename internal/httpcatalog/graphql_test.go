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
		{"too many tokens", graphqlBody(repoQuery(`pullRequest(number: 1) { `+strings.Repeat("id ", maxGraphQLTokens)+`}`), repoVars), ErrGraphQLLimit},
		{"oversized document", graphqlBody(repoQuery(`pullRequest(number: 1) { id }`)+strings.Repeat(" ", maxGraphQLDocument), repoVars), ErrGraphQLLimit},

		{"subscription", graphqlBody(`subscription { repository(owner: "o", name: "r") { id } }`, nil), ErrGraphQLUnmapped},
		{"viewer", graphqlBody(`query { viewer { login } }`, nil), ErrGraphQLUnmapped},
		{"organization", graphqlBody(`query { organization(login: "o") { repositories(first: 5) { nodes { name } } } }`, nil), ErrGraphQLUnmapped},
		{"another repository field", graphqlBody(repoQuery(`collaborators(first: 5) { nodes { login } }`), repoVars), ErrGraphQLUnmapped},
		{"repository object", graphqlBody(repoQuery(`object(expression: "main:secrets.txt") { id }`), repoVars), ErrGraphQLUnmapped},
		{"fragment at the root", graphqlBody(`query { ...q } fragment q on Query { viewer { login } }`, nil), ErrGraphQLUnmapped},
		{"fragment under repository", graphqlBody(repoQuery(`...r`)+` fragment r on Repository { collaborators(first: 1) { totalCount } }`, repoVars), ErrGraphQLUnmapped},
		{"directive", graphqlBody(repoQuery(`pullRequest(number: 1) @include(if: true) { id }`), repoVars), ErrGraphQLUnmapped},
		{"node of another type", graphqlBody(`query { node(id: "R_kgDNA-g") { ... on Repository { collaborators(first: 1) { totalCount } } } }`, nil), ErrGraphQLUnmapped},
		{"nodes", graphqlBody(`query { nodes(ids: ["PR_kwDNA-jNB9A"]) { id } }`, nil), ErrGraphQLUnmapped},
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
			`commits(first: 100) { nodes { commit { a: associatedPullRequests(first: 1) { totalCount } b: history(first: 1) { totalCount } } } } `+
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
// pr.read: pull requests can be read from a label or a commit.
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
		`subject { ... on PullRequest { repository { pullRequests(first: 1) { nodes { body comments(first: 1) { nodes { body } } } } } } }`: "pr.comment pr.read",
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
// statuses scopes; gh's default view, status and checks read it, list and
// the mutations do not.
func TestGraphQLMarksCheckStatusReads(t *testing.T) {
	for fixture, want := range map[string][]bool{
		"pr-view-number": {true, false},
		"pr-status":      {true},
		"pr-checks":      {false, false, false, true},
		"pr-list":        {false},
		"pr-comment":     {false, false},
	} {
		var got []bool
		for _, r := range readGhFixture(t, fixture).Requests {
			body := strings.NewReplacer("{{PR}}", fixturePR, "{{LABEL}}", fixtureLabel).Replace(r.Body)
			req, err := ParseGitHubGraphQL([]byte(body))
			if err != nil {
				t.Fatalf("%s: %v", fixture, err)
			}
			got = append(got, req.Checks)
		}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("%s: %v, want %v", fixture, got, want)
		}
	}
}
