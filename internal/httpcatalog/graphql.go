package httpcatalog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strings"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/formatter"
	"github.com/vektah/gqlparser/v2/parser"
)

// GitHub's GraphQL API (POST /graphql) is served the same way as its REST
// routes, for repositories that list the graphql operation: never passed
// through. Each request is parsed, every top-level field or mutation must map
// to a repository operation (githubOperations), and
// GitHub receives the parsed document printed again with its variables
// re-encoded, so GitHub executes exactly what was checked. The fields mapped
// are the ones gh 2.x sends for pr view, list (with --search too), status,
// checks, comment, edit (body and labels), ready, ready --undo and create:
//
//	repository(owner, name) { pullRequest }      pr.read
//	repository(owner, name) { pullRequests }     pr.list
//	repository(owner, name) { defaultBranchRef } pr.list
//	repository(owner, name) { labels }           pr.label (to find a label's ID)
//	search(query: "repo:owner/name ...", type: ISSUE or ISSUE_ADVANCED)  pr.list
//	node(id) { ... on PullRequest }              pr.read
//	addComment(input: $input)                    pr.comment
//	updatePullRequest(input: $input)             pr.edit (body only)
//	addLabelsToLabelable(input: $input)          pr.label
//	markPullRequestReadyForReview(input: $input) pr.ready
//	convertPullRequestToDraft(input: $input)     pr.ready (back to draft)
//	createPullRequest(input: $input)             pr.open (head under the pool's push prefixes)
//
// Every query also needs pr.read, as does a mutation whose payload selects
// more than __typename or clientMutationId, since below those fields any
// selection is allowed within the limits here and pull requests are reachable
// from most of them. A repository reached below the root (a pull request's
// repository, baseRepository or headRepository, a label's repository, ... on
// Repository) is checked as the root one is: pullRequests, defaultBranchRef
// and labels need the same operations there, and any other field with
// arguments or a selection is refused. Lists of repositories are refused at
// any depth (graphqlRepositoryList), and every list of pull requests needs
// pr.list wherever it is read (graphqlPullRequestList). Below the root no
// repository or owner is looked up by name (graphqlLookupField), so a nested
// repository is one the root's is related to, and the fields that read files
// and history are refused at any depth (graphqlContentFields). The token
// GitHub sees is minted for the one repository with pull requests and no
// contents, except for the two mutations GitHub refuses without it
// (GitHubGraphQL.Contents), so a nested field reaches no other private
// repository either. Node IDs (a
// mutation's target, node's id) do not name their repository; the broker
// resolves each one before sending (GraphQLTarget).

// Limits on one GraphQL request. gh's largest document (pr view) is about 3
// KiB, 13 levels deep, with about 150 fields once fragments are expanded.
// The request limit bounds what one GraphQL request costs the App
// installation's hourly budget (GitHub charges a point per 100), which every
// pool shares.
const (
	maxGraphQLDocument = 64 << 10
	maxGraphQLTokens   = 10000
	maxGraphQLAliases  = 10
	maxGraphQLDepth    = 20
	maxGraphQLFields   = 1000
	maxGraphQLRequests = 2000 // GitHub's cost estimate, in its own unit: gh's largest (pr view by branch) is about 210
	maxGraphQLPage     = 100  // first and last, GitHub's own maximum
	maxGraphQLLabels   = 99   // with the pull request, at most 100 IDs: nodes(ids) takes no more
)

// GraphQL refusals, each with the audit outcome and status it answers with.
var (
	ErrGraphQLShape         = &GraphQLError{"graphql_shape", http.StatusBadRequest}
	ErrGraphQLUnmapped      = &GraphQLError{"graphql_unmapped", http.StatusForbidden}
	ErrGraphQLLimit         = &GraphQLError{"graphql_limit", http.StatusForbidden}
	ErrGraphQLIntrospection = &GraphQLError{"graphql_introspection", http.StatusForbidden}
	ErrGraphQLRepository    = &GraphQLError{"graphql_repository", http.StatusForbidden}
)

// GraphQLError is a refused GraphQL request.
type GraphQLError struct {
	Outcome string
	Status  int
}

func (e *GraphQLError) Error() string { return "github graphql: " + e.Outcome }

// GitHubGraphQL is a checked GraphQL request.
type GitHubGraphQL struct {
	// Repo is the repository ("owner/name", lower case) that repository() or
	// a search's repo: qualifier names; empty when only node IDs name it.
	// Every request reaches exactly one repository.
	Repo string
	// Operations are the repository operations the request needs, sorted.
	Operations []string
	// Targets are the node IDs the broker resolves before it sends.
	Targets []GraphQLTarget
	// Body is what GitHub receives: the parsed document printed again and the
	// declared variables re-encoded.
	Body []byte
	// Answer, when set, is the broker's own reply to gh's schema feature
	// detection; nothing reaches GitHub.
	Answer []byte
	// Write is the mutation's operation (pr.comment and so on); empty for a
	// query.
	Write string
	// Checks marks a request that reads check status (graphqlCheckFields):
	// its token also carries checks and statuses read where the repository
	// grants them (actions.read), as REST's check run and status routes.
	Checks bool
	// Actions marks a request that reads workflow runs (graphqlActionsFields:
	// default gh pr view and gh pr checks read a check run's workflowRun): its
	// token also carries actions read where the repository grants it
	// (actions.read), as REST's workflow run routes.
	Actions bool
	// Contents is the contents permission the request's token needs, for the
	// two mutations GitHub refuses without it: "write" for
	// markPullRequestReadyForReview and "read" for createPullRequest (GitHub
	// reads the head and base refs), as REST's pr.ready and pr.open tokens
	// carry. Their payload may read back only the pull request's id, URL,
	// number and draft state (fixedPayload), so the wider token reaches
	// nothing else. Empty for every other request.
	Contents string
	// Head and Base are createPullRequest's branch names. The caller holds
	// the head to the pool's own push prefixes, as REST's pr.open does.
	Head, Base string
	// Code marks a request that reads which files a pull request changes
	// (graphqlPathFields): as for REST's pull request files, it is served only
	// to a pool whose git entry may clone the repository, for a requester that
	// entry authorizes.
	Code bool
}

// AuditOperation is the one operation an audit row names for the request:
// the write a mutation makes, or "graphql" for a read, so an alert on
// writes matches a GraphQL write exactly as the same REST write.
func (g GitHubGraphQL) AuditOperation() string {
	if g.Write != "" {
		return g.Write
	}
	return "graphql"
}

// GraphQLTarget is a node ID the request acts on, and what it must be.
type GraphQLTarget struct {
	ID string
	// Kind is TargetPullRequest (in the repository), TargetPullRequestWrite
	// (in the repository, its head in the pool's reach, as for a REST write),
	// TargetLabel (one of the repository's labels) or TargetRepository (the
	// repository itself).
	Kind string
}

const (
	TargetPullRequest      = "pull-request"
	TargetPullRequestWrite = "pull-request-write"
	TargetLabel            = "label"
	// TargetRepository is the repository createPullRequest names by ID.
	TargetRepository = "repository"
)

// githubSchemaFeatures answers gh's pull request feature detection, the only
// introspection it sends to github.com: two queries, covering the three types
// below, of __type(name) { fields(includeDeprecated: true) { name } }. The broker replies itself with
// the fields gh looks for, all present on github.com, so introspection never
// reaches GitHub.
var githubSchemaFeatures = map[string][]string{
	"PullRequest":                        {"isInMergeQueue", "isMergeQueueEnabled"},
	"StatusCheckRollupContextConnection": {"checkRunCount", "checkRunCountsByState", "statusContextCount", "statusContextCountsByState"},
	"WorkflowRun":                        {"event"},
}

// githubSchemaEnums answers gh pr list --search's own detection, of
// __type(name: "SearchType") { enumValues(includeDeprecated: true) { name } },
// the same way: with the pull request search types github.com has.
var githubSchemaEnums = map[string][]string{
	"SearchType": {"ISSUE", "ISSUE_ADVANCED"},
}

// graphqlRepositoryFields are the fields allowed directly under
// repository(owner, name), and the operation each needs. The same fields need
// the same operations under a repository reached anywhere below the root
// (graphqlCheck.repository).
var graphqlRepositoryFields = map[string]string{
	"pullRequest":      "pr.read",
	"pullRequests":     "pr.list",
	"defaultBranchRef": "pr.list",
	"labels":           "pr.label",
}

// graphqlRepositoryField reports a field whose value is a repository: a
// pull request's, label's or commit's repository, a pull request's
// baseRepository and headRepository, an event's fromRepository, a fork's
// parent (an issue's parent is checked the same way, which only refuses
// more). Named by
// convention, since the parser has no schema; isCrossRepository matches too,
// a plain value with nothing below it to check.
func graphqlRepositoryField(name string) bool {
	return name == "repository" || strings.HasSuffix(name, "Repository") || name == "parent"
}

// graphqlLookupField reports a field that, given arguments, looks a
// repository or an owner up by name (an owner's repository(name:), a user's
// organization(login:)). Below the root it is refused with any argument, so a
// nested repository is only ever one the root's is related to; gh sends none.
func graphqlLookupField(name string) bool {
	return graphqlRepositoryField(name) || name == "organization" || name == "user" || name == "repositoryOwner"
}

// graphqlPullRequestList reports a field whose value is a list of pull
// requests, which needs pr.list at any depth as a repository's pullRequests
// does: a label's, milestone's, user's or project field's pullRequests, a
// commit's or branch's associatedPullRequests, a check suite's
// matchingPullRequests, an issue's closedByPullRequestsReferences, and a
// user's pull request (review) contributions. These are every field
// GitHub's schema has whose type is a list of pull requests; gh reads none
// of them below the root. A pull request reached through a list of
// something else (a user's comments, timeline events) is read under
// pr.read, which reads any pull request by number anyway.
func graphqlPullRequestList(name string) bool {
	n := strings.ToLower(name)
	return strings.Contains(n, "pullrequests") || strings.Contains(n, "pullrequestcontribution") || strings.Contains(n, "pullrequestreviewcontribution")
}

// graphqlRepositoryList reports a field whose value is a list of
// repositories (an owner's repositories, a user's starred or watched ones,
// a repository's forks). Each item would be a repository the mapping never
// sees, so these are refused at any depth; gh reads none of them. Lists of
// mixed items (pinned items) reach a repository only through ... on
// Repository, which graphqlCheck.repository checks.
func graphqlRepositoryList(name string) bool {
	return strings.Contains(strings.ToLower(name), "repositories") || name == "watching" || name == "forks"
}

// graphqlMutation is one allowed mutation: its operation, the fields its input
// may carry (true: required), and which of them are node IDs to resolve.
type graphqlMutation struct {
	op     string
	fields map[string]bool
	target string // the field naming the pull request
	labels bool   // labelIds lists labels to resolve
	// contents is the contents permission GitHub refuses the mutation
	// without (GitHubGraphQL.Contents); its payload is held to fixedPayload.
	contents string
	// flags are input fields that take a boolean; every other is a string.
	flags map[string]bool
}

var graphqlMutations = map[string]graphqlMutation{
	"addComment": {op: "pr.comment", fields: map[string]bool{"subjectId": true, "body": true, "clientMutationId": false}, target: "subjectId"},
	// Only the body, as PATCH /pulls/{n}: never the title, base or state.
	"updatePullRequest": {op: "pr.edit", fields: map[string]bool{"pullRequestId": true, "body": true, "clientMutationId": false}, target: "pullRequestId"},
	"addLabelsToLabelable": {op: "pr.label", fields: map[string]bool{"labelableId": true, "labelIds": true, "clientMutationId": false},
		target: "labelableId", labels: true},
	"markPullRequestReadyForReview": {op: "pr.ready", fields: map[string]bool{"pullRequestId": true, "clientMutationId": false}, target: "pullRequestId",
		contents: "write"},
	// gh pr ready --undo: the same draft state, the other way, under the same
	// operation, reach and contents write.
	"convertPullRequestToDraft": {op: "pr.ready", fields: map[string]bool{"pullRequestId": true, "clientMutationId": false}, target: "pullRequestId",
		contents: "write"},
	// gh pr create: a pull request in this repository (never headRepositoryId,
	// a fork), from a head the caller holds to the pool's push prefixes.
	"createPullRequest": {op: "pr.open", fields: map[string]bool{"repositoryId": true, "baseRefName": true, "headRefName": true, "title": true,
		"body": false, "draft": false, "maintainerCanModify": false, "clientMutationId": false}, target: "repositoryId",
		contents: "read", flags: map[string]bool{"draft": true, "maintainerCanModify": true}},
}

// ParseGitHubGraphQL checks one GraphQL request body against the mapping
// above. It does not consult the catalog: the caller checks Operations
// against the repository and resolves Targets.
func ParseGitHubGraphQL(body []byte) (GitHubGraphQL, error) {
	var req struct {
		Query         string                     `json:"query"`
		Variables     map[string]json.RawMessage `json:"variables"`
		OperationName *string                    `json:"operationName"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || dec.More() || req.Query == "" {
		return GitHubGraphQL{}, ErrGraphQLShape
	}
	if len(req.Query) > maxGraphQLDocument {
		return GitHubGraphQL{}, ErrGraphQLLimit
	}
	doc, err := parser.ParseQueryWithTokenLimit(&ast.Source{Input: req.Query}, maxGraphQLTokens)
	if err != nil {
		if strings.Contains(err.Error(), "token limit") {
			return GitHubGraphQL{}, ErrGraphQLLimit
		}
		return GitHubGraphQL{}, ErrGraphQLShape
	}
	if len(doc.Operations) != 1 {
		return GitHubGraphQL{}, ErrGraphQLShape
	}
	op := doc.Operations[0]
	if req.OperationName != nil && *req.OperationName != "" && *req.OperationName != op.Name {
		return GitHubGraphQL{}, ErrGraphQLShape
	}
	vars, err := graphqlVariables(op, req.Variables)
	if err != nil {
		return GitHubGraphQL{}, err
	}
	frags := map[string]*ast.FragmentDefinition{}
	for _, f := range doc.Fragments {
		if frags[f.Name] != nil || len(f.VariableDefinition) > 0 {
			return GitHubGraphQL{}, ErrGraphQLShape
		}
		frags[f.Name] = f
	}
	if answer, ok, err := featureDetection(op, vars); ok || err != nil {
		return GitHubGraphQL{Answer: answer}, err
	}
	// Every definition is checked as written, so a fragment counts once
	// however often it is spread; the expanded tree is measured after.
	defaults := func(name string) *ast.Value {
		if d := op.VariableDefinitions.ForName(name); d != nil {
			return d.DefaultValue
		}
		return nil
	}
	c := &graphqlCheck{vars: vars, defaults: defaults, ops: map[string]bool{}, frags: frags}
	c.selections(op.SelectionSet)
	// A fragment is spread only below the root (queryRoot and mutationRoot
	// refuse one at the root), so its fields are checked as nested ones.
	c.depth = 1
	for _, f := range doc.Fragments {
		if len(f.Directives) > 0 || graphqlContentTypes[f.TypeCondition] {
			c.fail(ErrGraphQLUnmapped)
		}
		if f.TypeCondition == "Repository" {
			c.repository(f.SelectionSet)
		}
		c.selections(f.SelectionSet)
	}
	if len(op.Directives) > 0 {
		c.fail(ErrGraphQLUnmapped)
	}
	if c.err != nil {
		return GitHubGraphQL{}, c.err
	}
	if c.aliases > maxGraphQLAliases {
		return GitHubGraphQL{}, ErrGraphQLLimit
	}
	m := &graphqlMeasure{frags: frags, memo: map[string]graphqlShape{}, open: map[string]bool{}, page: func(f *ast.Field) int64 {
		var n int64 = 1
		for _, a := range f.Arguments {
			if a.Name == "first" || a.Name == "last" {
				if v, err := value(a.Value, vars, defaults); err == nil {
					if num, ok := v.(json.Number); ok {
						i, _ := num.Int64() // checked above: a whole number up to maxGraphQLPage
						n = max(n, i)       // both given: count the larger, never less
					}
				}
			}
		}
		return n
	}}
	shape, err := m.set(op.SelectionSet)
	if err != nil {
		return GitHubGraphQL{}, err
	}
	if shape.depth > maxGraphQLDepth || shape.fields > maxGraphQLFields || shape.requests > maxGraphQLRequests {
		return GitHubGraphQL{}, ErrGraphQLLimit
	}

	out := GitHubGraphQL{Code: c.code, Checks: c.checks, Actions: c.actions}
	ops := c.ops // what repositories reached at any depth need
	repos := map[string]bool{}
	switch op.Operation {
	case ast.Query:
		// Below a mapped field any selection is allowed, and from many of
		// them a pull request can be read (a comment's subject, an event's
		// source), so every query also needs pr.read.
		ops["pr.read"] = true
		if err := queryRoot(op.SelectionSet, vars, defaults, ops, repos, &out.Targets); err != nil {
			return GitHubGraphQL{}, err
		}
	case ast.Mutation:
		if err := mutationRoot(op.SelectionSet, vars, ops, &out); err != nil {
			return GitHubGraphQL{}, err
		}
		// Its token carries contents, so nothing but its fixed payload
		// (fixedPayload) may be in the document.
		if out.Contents != "" && len(doc.Fragments) > 0 {
			return GitHubGraphQL{}, ErrGraphQLUnmapped
		}
	default: // subscriptions
		return GitHubGraphQL{}, ErrGraphQLUnmapped
	}
	if len(repos) > 1 {
		return GitHubGraphQL{}, ErrGraphQLRepository
	}
	for repo := range repos {
		out.Repo = repo
	}
	if out.Repo == "" && len(out.Targets) == 0 {
		return GitHubGraphQL{}, ErrGraphQLRepository
	}
	for o := range ops {
		out.Operations = append(out.Operations, o)
	}
	sort.Strings(out.Operations)

	var printed strings.Builder
	formatter.NewFormatter(&printed).FormatQueryDocument(doc)
	// The printed document must read back as itself, or GitHub could be
	// reading something other than what was checked.
	again, err := parser.ParseQuery(&ast.Source{Input: printed.String()})
	if err != nil {
		return GitHubGraphQL{}, ErrGraphQLShape
	}
	var reprinted strings.Builder
	formatter.NewFormatter(&reprinted).FormatQueryDocument(again)
	if reprinted.String() != printed.String() {
		return GitHubGraphQL{}, ErrGraphQLShape
	}
	rebuilt := struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables,omitempty"`
	}{Query: printed.String(), Variables: vars}
	if out.Body, err = json.Marshal(rebuilt); err != nil {
		return GitHubGraphQL{}, ErrGraphQLShape
	}
	return out, nil
}

// graphqlVariables decodes the request's declared variables. One the document
// does not declare is dropped (gh pr status sends one; GitHub ignores it). A
// declared one left out takes its default, if any, for checking only: GitHub
// applies the same default itself.
func graphqlVariables(op *ast.OperationDefinition, raw map[string]json.RawMessage) (map[string]any, error) {
	declared := map[string]*ast.VariableDefinition{}
	for _, d := range op.VariableDefinitions {
		if declared[d.Variable] != nil || len(d.Directives) > 0 {
			return nil, ErrGraphQLShape
		}
		declared[d.Variable] = d
	}
	vars := map[string]any{}
	for name, value := range raw {
		if declared[name] == nil {
			continue
		}
		dec := json.NewDecoder(bytes.NewReader(value))
		dec.UseNumber()
		var v any
		if err := dec.Decode(&v); err != nil {
			return nil, ErrGraphQLShape
		}
		vars[name] = v
	}
	return vars, nil
}

// value evaluates an argument: literals, and variables from the request or
// their declared defaults. An object literal naming a field twice is refused,
// since GitHub might keep the other one.
func value(v *ast.Value, vars map[string]any, defaults func(string) *ast.Value) (any, error) {
	if v == nil {
		return nil, nil
	}
	switch v.Kind {
	case ast.Variable:
		if x, ok := vars[v.Raw]; ok {
			return x, nil
		}
		if d := defaults(v.Raw); d != nil {
			return value(d, nil, func(string) *ast.Value { return nil })
		}
		return nil, nil
	case ast.IntValue:
		return json.Number(v.Raw), nil
	case ast.StringValue, ast.BlockValue, ast.EnumValue:
		return v.Raw, nil
	case ast.BooleanValue:
		return v.Raw == "true", nil
	case ast.NullValue:
		return nil, nil
	case ast.ListValue:
		out := []any{}
		for _, child := range v.Children {
			x, err := value(child.Value, vars, defaults)
			if err != nil {
				return nil, err
			}
			out = append(out, x)
		}
		return out, nil
	case ast.ObjectValue:
		out := map[string]any{}
		for _, child := range v.Children {
			if _, dup := out[child.Name]; dup {
				return nil, ErrGraphQLShape
			}
			x, err := value(child.Value, vars, defaults)
			if err != nil {
				return nil, err
			}
			out[child.Name] = x
		}
		return out, nil
	}
	return nil, ErrGraphQLShape // floats: no allowed argument takes one
}

// graphqlContentFields and graphqlContentTypes are the main ways to a
// repository's files and history, which only a git entry grants. Every
// GraphQL token but pr.ready's and pr.open's has no contents permission, so GitHub refuses
// these reads anyway; they are refused here too, at any depth, so the parser
// holds them whatever the token. gh reads none of them.
var (
	graphqlContentFields = map[string]bool{"object": true, "file": true, "entries": true, "tree": true, "readme": true,
		"contributingGuidelines": true, "codeOfConduct": true, "pullRequestTemplates": true, "issueTemplates": true,
		"diffHunk": true, // a review comment's code context, which REST serves only with a clone grant
		// A commit's history and blame, and a ref's compare (its commits and diff).
		"history": true, "blame": true, "compare": true}
	graphqlContentTypes = map[string]bool{"Blob": true, "Tree": true, "TreeEntry": true}
)

// graphqlPathFields name the files a pull request changes (its file list, a
// review comment's or thread's path). They are allowed, but only with the
// clone grant REST asks for the same list (GitHubGraphQL.Code). The type
// PullRequestChangedFile is reached only through files.
var graphqlPathFields = map[string]bool{"files": true, "path": true}

// graphqlCheckFields read a commit's check runs and statuses (gh pr view,
// status and checks read statusCheckRollup), which GitHub serves only to a
// token with checks and statuses read (GitHubGraphQL.Checks).
var graphqlCheckFields = map[string]bool{"statusCheckRollup": true, "checkSuites": true, "checkRuns": true}

// graphqlActionsFields read a check suite's workflow run, which GitHub serves
// only to a token with actions read (GitHubGraphQL.Actions).
var graphqlActionsFields = map[string]bool{"workflowRun": true}

// graphqlCheck walks every selection as written: no directives, no
// introspection beyond __typename, no argument named twice, aliases counted,
// every first or last at most maxGraphQLPage, and every repository reached
// checked as the root one is.
type graphqlCheck struct {
	vars     map[string]any
	defaults func(string) *ast.Value
	aliases  int
	depth    int // 0 for the root's fields
	frags    map[string]*ast.FragmentDefinition
	ops      map[string]bool // operations fields below the root need (repository, graphqlPullRequestList)
	code     bool            // a field of graphqlPathFields appears
	checks   bool            // a field of graphqlCheckFields appears
	actions  bool            // a field of graphqlActionsFields appears
	err      error
}

func (c *graphqlCheck) fail(err error) {
	if c.err == nil {
		c.err = err
	}
}

func (c *graphqlCheck) selections(set ast.SelectionSet) {
	for _, s := range set {
		switch s := s.(type) {
		case *ast.Field:
			if len(s.Directives) > 0 {
				c.fail(ErrGraphQLUnmapped)
			}
			if strings.HasPrefix(s.Name, "__") && s.Name != "__typename" {
				c.fail(ErrGraphQLIntrospection)
			}
			if graphqlContentFields[s.Name] {
				c.fail(ErrGraphQLUnmapped)
			}
			if graphqlPathFields[s.Name] {
				c.code = true
			}
			if graphqlCheckFields[s.Name] {
				c.checks = true
			}
			if graphqlActionsFields[s.Name] {
				c.actions = true
			}
			if graphqlRepositoryList(s.Name) {
				c.fail(ErrGraphQLUnmapped)
			}
			if graphqlPullRequestList(s.Name) {
				c.ops["pr.list"] = true
			}
			if graphqlRepositoryField(s.Name) {
				c.repository(s.SelectionSet)
			}
			if c.depth > 0 && len(s.Arguments) > 0 && graphqlLookupField(s.Name) {
				c.fail(ErrGraphQLUnmapped)
			}
			if s.Alias != "" && s.Alias != s.Name {
				c.aliases++
			}
			seen := map[string]bool{}
			for _, a := range s.Arguments {
				if seen[a.Name] {
					c.fail(ErrGraphQLShape)
				}
				seen[a.Name] = true
				// Every argument must evaluate (no object naming a field
				// twice); first and last must also be a page GitHub allows.
				n, err := value(a.Value, c.vars, c.defaults)
				switch {
				case err != nil:
					c.fail(err)
				case (a.Name == "first" || a.Name == "last") && n != nil && !pageSize(n):
					c.fail(ErrGraphQLLimit)
				}
			}
			c.depth++
			c.selections(s.SelectionSet)
			c.depth--
		case *ast.InlineFragment:
			if len(s.Directives) > 0 || graphqlContentTypes[s.TypeCondition] {
				c.fail(ErrGraphQLUnmapped)
			}
			if s.TypeCondition == "Repository" {
				c.repository(s.SelectionSet)
			}
			c.selections(s.SelectionSet)
		case *ast.FragmentSpread:
			if len(s.Directives) > 0 {
				c.fail(ErrGraphQLUnmapped)
			}
		}
	}
}

// repository checks a selection on a repository reached anywhere, the root
// one included: a field of graphqlRepositoryFields needs its operation; a
// plain value (no arguments, no selection, such as name or id), the owner's
// plain values (owner { login }) and a repository it leads to (a fork's
// parent, checked in turn) are allowed; a fragment spread only of a fragment
// on Repository, whose definition is checked the same way; and anything else
// is refused, so nothing below a repository goes unmapped. gh pr create reads
// the repository's id, owner, settings and parent this way. selections still
// walks it all for the other checks.
func (c *graphqlCheck) repository(set ast.SelectionSet) {
	for _, s := range set {
		switch s := s.(type) {
		case *ast.Field:
			op, mapped := graphqlRepositoryFields[s.Name]
			switch {
			case mapped:
				c.ops[op] = true
			case len(s.Arguments) > 0:
				c.fail(ErrGraphQLUnmapped)
			case len(s.SelectionSet) == 0, graphqlRepositoryField(s.Name):
			case s.Name == "owner" && plainFields(s.SelectionSet):
			default:
				c.fail(ErrGraphQLUnmapped)
			}
		case *ast.InlineFragment:
			c.repository(s.SelectionSet)
		case *ast.FragmentSpread:
			if f := c.frags[s.Name]; f == nil || f.TypeCondition != "Repository" {
				c.fail(ErrGraphQLUnmapped)
			}
		}
	}
}

// plainFields reports a selection of plain values only: fields with no
// alias, arguments, directives or selection, and no fragments.
func plainFields(set ast.SelectionSet) bool {
	for _, s := range set {
		f, ok := s.(*ast.Field)
		if !ok || f.Alias != "" && f.Alias != f.Name || len(f.Arguments) > 0 || len(f.Directives) > 0 || len(f.SelectionSet) > 0 {
			return false
		}
	}
	return len(set) > 0
}

// pageSize reports whether a first or last value is a whole number GitHub
// accepts, 0 to maxGraphQLPage.
func pageSize(v any) bool {
	n, ok := v.(json.Number)
	if !ok {
		return false
	}
	i, err := n.Int64()
	return err == nil && i >= 0 && i <= maxGraphQLPage
}

// graphqlShape is a selection's depth, its field count, and GitHub's rate
// limit estimate in requests: each connection (a field with first or last)
// is one request per parent it is read under, and a page of n multiplies
// everything below it by n.
type graphqlShape struct{ depth, fields, requests int }

// graphqlMeasure measures the selection tree with every fragment expanded,
// each fragment once (memo), refusing a fragment that spreads itself or is
// not defined. page is a field's first or last, 1 without either.
type graphqlMeasure struct {
	frags map[string]*ast.FragmentDefinition
	memo  map[string]graphqlShape
	open  map[string]bool
	page  func(*ast.Field) int64
}

func (m *graphqlMeasure) set(set ast.SelectionSet) (graphqlShape, error) {
	var out graphqlShape
	add := func(s graphqlShape) {
		out.depth = max(out.depth, s.depth)
		out.fields = min(out.fields+s.fields, math.MaxInt32) // saturates; any total past the limit is refused
		out.requests = min(out.requests+s.requests, math.MaxInt32)
	}
	for _, s := range set {
		switch s := s.(type) {
		case *ast.Field:
			inner, err := m.set(s.SelectionSet)
			if err != nil {
				return out, err
			}
			requests := int64(inner.requests)
			if hasPage(s) {
				requests = 1 + m.page(s)*requests
			}
			add(graphqlShape{depth: inner.depth + 1, fields: inner.fields + 1, requests: int(min(requests, math.MaxInt32))})
		case *ast.InlineFragment:
			inner, err := m.set(s.SelectionSet)
			if err != nil {
				return out, err
			}
			add(inner)
		case *ast.FragmentSpread:
			if shape, ok := m.memo[s.Name]; ok {
				add(shape)
				continue
			}
			f := m.frags[s.Name]
			if f == nil || m.open[s.Name] {
				return out, ErrGraphQLShape
			}
			m.open[s.Name] = true
			inner, err := m.set(f.SelectionSet)
			if err != nil {
				return out, err
			}
			m.open[s.Name] = false
			m.memo[s.Name] = inner
			add(inner)
		}
	}
	return out, nil
}

func hasPage(f *ast.Field) bool {
	return f.Arguments.ForName("first") != nil || f.Arguments.ForName("last") != nil
}

// featureDetection recognizes gh's schema feature detection: a query of
// only __type(name: "<known type>") { fields(includeDeprecated: true) { name } }
// fields, or enumValues in place of fields for a known enum. ok reports that
// it is one, answered with the broker's own reply.
func featureDetection(op *ast.OperationDefinition, vars map[string]any) ([]byte, bool, error) {
	if op.Operation != ast.Query || len(op.SelectionSet) == 0 {
		return nil, false, nil
	}
	data := map[string]any{}
	for _, s := range op.SelectionSet {
		f, ok := s.(*ast.Field)
		if !ok || f.Name != "__type" {
			return nil, false, nil
		}
		var fields []string
		kind := "fields"
		if len(f.Arguments) == 1 && f.Arguments[0].Name == "name" && f.Arguments[0].Value.Kind == ast.StringValue {
			if fields = githubSchemaFeatures[f.Arguments[0].Value.Raw]; fields == nil {
				fields, kind = githubSchemaEnums[f.Arguments[0].Value.Raw], "enumValues"
			}
		}
		if fields == nil || len(f.Directives) > 0 || len(f.SelectionSet) != 1 || len(vars) > 0 || len(op.VariableDefinitions) > 0 || len(op.Directives) > 0 {
			return nil, true, ErrGraphQLIntrospection
		}
		inner, ok := f.SelectionSet[0].(*ast.Field)
		if !ok || inner.Name != kind || inner.Alias != kind && inner.Alias != "" || len(inner.Directives) > 0 ||
			len(inner.Arguments) != 1 || inner.Arguments[0].Name != "includeDeprecated" || inner.Arguments[0].Value.Kind != ast.BooleanValue ||
			inner.Arguments[0].Value.Raw != "true" || len(inner.SelectionSet) != 1 {
			return nil, true, ErrGraphQLIntrospection
		}
		name, ok := inner.SelectionSet[0].(*ast.Field)
		if !ok || name.Name != "name" || name.Alias != "" && name.Alias != "name" || len(name.Arguments) > 0 || len(name.Directives) > 0 || len(name.SelectionSet) > 0 {
			return nil, true, ErrGraphQLIntrospection
		}
		key := f.Alias
		if key == "" {
			key = f.Name
		}
		if _, dup := data[key]; dup {
			return nil, true, ErrGraphQLIntrospection
		}
		list := make([]map[string]string, 0, len(fields))
		for _, n := range fields {
			list = append(list, map[string]string{"name": n})
		}
		data[key] = map[string]any{kind: list}
	}
	answer, err := json.Marshal(map[string]any{"data": data})
	return answer, true, err
}

// queryRoot maps each top-level query field to its operations and repository.
func queryRoot(set ast.SelectionSet, vars map[string]any, defaults func(string) *ast.Value, ops, repos map[string]bool, targets *[]GraphQLTarget) error {
	for _, s := range set {
		f, ok := s.(*ast.Field)
		if !ok {
			return ErrGraphQLUnmapped // no fragments at the root: each field is mapped as written
		}
		args := map[string]any{}
		for _, a := range f.Arguments {
			v, err := value(a.Value, vars, defaults)
			if err != nil {
				return err
			}
			args[a.Name] = v
		}
		switch f.Name {
		case "__typename":
		case "repository":
			repo, ok := repositoryArgs(args)
			if !ok {
				return ErrGraphQLUnmapped
			}
			repos[repo] = true
			// Its selection is checked as every repository's is
			// (graphqlCheck.repository), which adds the operations it needs.
			if len(f.SelectionSet) == 0 {
				return ErrGraphQLUnmapped
			}
		case "search":
			repo, ok := searchArgs(args)
			if !ok {
				return ErrGraphQLUnmapped
			}
			repos[repo] = true
			ops["pr.list"] = true
		case "node":
			id, ok := args["id"].(string)
			if len(args) != 1 || !ok || id == "" || len(f.SelectionSet) == 0 {
				return ErrGraphQLUnmapped
			}
			for _, sub := range f.SelectionSet {
				switch sub := sub.(type) {
				case *ast.Field:
					if sub.Name != "__typename" && sub.Name != "id" {
						return ErrGraphQLUnmapped
					}
				case *ast.InlineFragment:
					if sub.TypeCondition != "PullRequest" {
						return ErrGraphQLUnmapped
					}
				default:
					return ErrGraphQLUnmapped
				}
			}
			ops["pr.read"] = true
			*targets = append(*targets, GraphQLTarget{ID: id, Kind: TargetPullRequest})
		default:
			return ErrGraphQLUnmapped
		}
	}
	return nil
}

// repositoryArgs reads repository(owner, name) as "owner/name".
func repositoryArgs(args map[string]any) (string, bool) {
	owner, ok1 := args["owner"].(string)
	name, ok2 := args["name"].(string)
	if len(args) != 2 || !ok1 || !ok2 {
		return "", false
	}
	repo := strings.ToLower(owner + "/" + name)
	return repo, repoPattern.MatchString(repo) && !strings.Contains(repo, "..")
}

// searchArgs reads a pull request search: type ISSUE or ISSUE_ADVANCED, and
// a query naming exactly one repository with repo: and no other owner,
// organization or repository qualifier. Advanced search reads AND, OR and
// parentheses, so the query has no AND, OR or NOT, and parentheses only as gh
// writes them, alone around the --search terms ("( text ) is:merged
// repo:owner/name type:pr") with no repo: inside: every term is then ANDed
// with the one repo:, read either way. Printable ASCII only, so GitHub splits
// the terms where this reading does.
func searchArgs(args map[string]any) (string, bool) {
	query, ok := args["query"].(string)
	if !ok || args["type"] != "ISSUE" && args["type"] != "ISSUE_ADVANCED" {
		return "", false
	}
	for _, r := range query {
		if r < ' ' || r > '~' {
			return "", false
		}
	}
	for key := range args {
		switch key {
		case "query", "type", "first", "last", "after", "before":
		default:
			return "", false
		}
	}
	repo, depth := "", 0
	for _, term := range strings.Fields(query) {
		switch {
		case term == "(":
			if depth++; depth > 1 {
				return "", false
			}
			continue
		case term == ")":
			if depth--; depth < 0 {
				return "", false
			}
			continue
		case strings.ContainsAny(term, "()"):
			return "", false // grouping could hide a qualifier from this reading
		}
		switch strings.ToUpper(term) {
		case "AND", "OR", "NOT":
			return "", false
		}
		negated := strings.HasPrefix(term, "-")
		key, v, found := strings.Cut(strings.TrimLeft(strings.ToLower(term), "-"), ":")
		switch {
		case !found:
		case negated && (key == "repo" || key == "org" || key == "user" || key == "owner"):
			return "", false
		case key == "repo":
			if repo != "" || depth > 0 {
				return "", false
			}
			repo = v
		case key == "org", key == "user", key == "owner":
			return "", false
		}
		if strings.ContainsAny(term, `"'`) {
			return "", false
		}
	}
	return repo, depth == 0 && repo != "" && repoPattern.MatchString(repo) && !strings.Contains(repo, "..")
}

// mutationRoot maps the one mutation to its operation and node IDs. Its input
// must be a variable: GitHub then reads the very JSON value checked here, not
// a literal its own lexer might read differently.
func mutationRoot(set ast.SelectionSet, vars map[string]any, ops map[string]bool, out *GitHubGraphQL) error {
	if len(set) != 1 {
		return ErrGraphQLUnmapped
	}
	f, ok := set[0].(*ast.Field)
	if !ok || f.Alias != "" && f.Alias != f.Name {
		return ErrGraphQLUnmapped
	}
	m, ok := graphqlMutations[f.Name]
	if !ok || len(f.Arguments) != 1 || f.Arguments[0].Name != "input" || f.Arguments[0].Value.Kind != ast.Variable {
		return ErrGraphQLUnmapped
	}
	input, ok := vars[f.Arguments[0].Value.Raw].(map[string]any)
	if !ok {
		return ErrGraphQLUnmapped
	}
	for key, v := range input {
		if _, allowed := m.fields[key]; !allowed {
			return ErrGraphQLUnmapped
		}
		if key == "labelIds" {
			continue
		}
		if m.flags[key] {
			if _, ok := v.(bool); !ok {
				return ErrGraphQLUnmapped
			}
			continue
		}
		if s, ok := v.(string); !ok || s == "" && key != "body" && key != "clientMutationId" {
			return ErrGraphQLUnmapped
		}
	}
	for key, required := range m.fields {
		if _, present := input[key]; required && !present {
			return ErrGraphQLUnmapped
		}
	}
	if m.contents != "" && !fixedPayload(f.SelectionSet) {
		return ErrGraphQLUnmapped
	}
	ops[m.op] = true
	out.Write, out.Contents = m.op, m.contents
	// A mutation's payload is a selection like any query's: from it a pull
	// request, its comments or the repository's other pull requests can be
	// read. Anything beyond __typename and clientMutationId needs pr.read.
	for _, sel := range f.SelectionSet {
		if field, ok := sel.(*ast.Field); !ok || field.Name != "__typename" && field.Name != "clientMutationId" {
			ops["pr.read"] = true
		}
	}
	if m.op == "pr.open" {
		out.Head, out.Base = input["headRefName"].(string), input["baseRefName"].(string)
		out.Targets = append(out.Targets, GraphQLTarget{ID: input[m.target].(string), Kind: TargetRepository})
		return nil
	}
	out.Targets = append(out.Targets, GraphQLTarget{ID: input[m.target].(string), Kind: TargetPullRequestWrite})
	if m.labels {
		labels, ok := input["labelIds"].([]any)
		if !ok || len(labels) == 0 || len(labels) > maxGraphQLLabels {
			return ErrGraphQLUnmapped
		}
		for _, l := range labels {
			id, ok := l.(string)
			if !ok || id == "" {
				return ErrGraphQLUnmapped
			}
			out.Targets = append(out.Targets, GraphQLTarget{ID: id, Kind: TargetLabel})
		}
	}
	return nil
}

// fixedPayload reports whether the payload of a mutation whose token carries
// contents (GitHubGraphQL.Contents) reads back no more than gh pr ready and
// gh pr create do: __typename, clientMutationId, and the pull request's
// __typename, id, url, number and isDraft, each a plain field with no alias,
// argument, directive or fragment. Nothing else may be read with that token.
func fixedPayload(set ast.SelectionSet) bool {
	plain := func(sel ast.Selection, names ...string) (*ast.Field, bool) {
		f, ok := sel.(*ast.Field)
		if !ok || f.Alias != "" && f.Alias != f.Name || len(f.Arguments) > 0 || len(f.Directives) > 0 {
			return nil, false
		}
		for _, n := range names {
			if f.Name == n {
				return f, true
			}
		}
		return nil, false
	}
	for _, sel := range set {
		f, ok := plain(sel, "__typename", "clientMutationId", "pullRequest")
		switch {
		case !ok:
			return false
		case f.Name != "pullRequest":
			if len(f.SelectionSet) > 0 {
				return false
			}
		case len(f.SelectionSet) == 0:
			return false
		default:
			for _, sub := range f.SelectionSet {
				if g, ok := plain(sub, "__typename", "id", "url", "number", "isDraft"); !ok || len(g.SelectionSet) > 0 {
					return false
				}
			}
		}
	}
	return true
}

// String names a target for errors and tests.
func (t GraphQLTarget) String() string { return fmt.Sprintf("%s %s", t.Kind, t.ID) }
