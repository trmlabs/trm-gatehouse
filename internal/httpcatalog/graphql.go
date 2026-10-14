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
// routes: never passed through. Each request is parsed, every top-level field
// or mutation must map to a repository operation (githubOperations), and
// GitHub receives the parsed document printed again with its variables
// re-encoded, so GitHub executes exactly what was checked. The fields mapped
// are the ones gh 2.x sends for pr view, list, status, checks, comment, edit
// (body and labels) and ready:
//
//	repository(owner, name) { pullRequest }      pr.read
//	repository(owner, name) { pullRequests }     pr.list
//	repository(owner, name) { defaultBranchRef } pr.list
//	repository(owner, name) { labels }           pr.label (to find a label's ID)
//	search(query: "repo:owner/name ...", type: ISSUE)  pr.list
//	node(id) { ... on PullRequest }              pr.read
//	addComment(input: $input)                    pr.comment
//	updatePullRequest(input: $input)             pr.edit (body only)
//	addLabelsToLabelable(input: $input)          pr.label
//	markPullRequestReadyForReview(input: $input) pr.ready
//
// Every query also needs pr.read, since below those fields any selection is
// allowed within the limits here and pull requests are reachable from most
// of them. The token GitHub sees is minted for the one repository with pull
// requests and no contents, so a nested field reaches neither another private
// repository nor files and history (a git entry's grant). Node IDs (a
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
}

// GraphQLTarget is a node ID the request acts on, and what it must be.
type GraphQLTarget struct {
	ID string
	// Kind is TargetPullRequest (in the repository), TargetPullRequestWrite
	// (in the repository, its head in the pool's reach, as for a REST write)
	// or TargetLabel (one of the repository's labels).
	Kind string
}

const (
	TargetPullRequest      = "pull-request"
	TargetPullRequestWrite = "pull-request-write"
	TargetLabel            = "label"
)

// githubSchemaFeatures answers gh's pull request feature detection, the only
// introspection it sends to github.com (two queries of __type(name)
// { fields(includeDeprecated: true) { name } }). The broker replies itself with
// the fields gh looks for, all present on github.com, so introspection never
// reaches GitHub.
var githubSchemaFeatures = map[string][]string{
	"PullRequest":                        {"isInMergeQueue", "isMergeQueueEnabled"},
	"StatusCheckRollupContextConnection": {"checkRunCount", "checkRunCountsByState", "statusContextCount", "statusContextCountsByState"},
	"WorkflowRun":                        {"event"},
}

// graphqlRepositoryFields are the fields allowed directly under
// repository(owner, name), and the operation each needs.
var graphqlRepositoryFields = map[string]string{
	"pullRequest":      "pr.read",
	"pullRequests":     "pr.list",
	"defaultBranchRef": "pr.list",
	"labels":           "pr.label",
}

// graphqlMutation is one allowed mutation: its operation, the fields its input
// may carry (true: required), and which of them are node IDs to resolve.
type graphqlMutation struct {
	op     string
	fields map[string]bool
	target string // the field naming the pull request
	labels bool   // labelIds lists labels to resolve
}

var graphqlMutations = map[string]graphqlMutation{
	"addComment": {op: "pr.comment", fields: map[string]bool{"subjectId": true, "body": true, "clientMutationId": false}, target: "subjectId"},
	// Only the body, as PATCH /pulls/{n}: never the title, base or state.
	"updatePullRequest": {op: "pr.edit", fields: map[string]bool{"pullRequestId": true, "body": true, "clientMutationId": false}, target: "pullRequestId"},
	"addLabelsToLabelable": {op: "pr.label", fields: map[string]bool{"labelableId": true, "labelIds": true, "clientMutationId": false},
		target: "labelableId", labels: true},
	"markPullRequestReadyForReview": {op: "pr.ready", fields: map[string]bool{"pullRequestId": true, "clientMutationId": false}, target: "pullRequestId"},
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
	c := &graphqlCheck{vars: vars, defaults: defaults}
	c.selections(op.SelectionSet)
	for _, f := range doc.Fragments {
		if len(f.Directives) > 0 || graphqlContentTypes[f.TypeCondition] {
			c.fail(ErrGraphQLUnmapped)
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

	out := GitHubGraphQL{}
	ops := map[string]bool{}
	repos := map[string]bool{}
	switch op.Operation {
	case ast.Query:
		// Below a mapped field any selection is allowed, and from any of them
		// a pull request can be read (a label's pullRequests, a commit's
		// associatedPullRequests), so every query also needs pr.read.
		ops["pr.read"] = true
		if err := queryRoot(op.SelectionSet, vars, defaults, ops, repos, &out.Targets); err != nil {
			return GitHubGraphQL{}, err
		}
	case ast.Mutation:
		if err := mutationRoot(op.SelectionSet, vars, ops, &out.Targets); err != nil {
			return GitHubGraphQL{}, err
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
// repository's files, which only a git entry grants. The control is the
// token: the broker's GraphQL token has no contents permission, so GitHub
// refuses file reads anyway. These are refused here too, at any depth, as
// defense in depth should the token's scope ever widen. gh reads none of them.
var (
	graphqlContentFields = map[string]bool{"object": true, "file": true, "entries": true, "tree": true, "readme": true,
		"contributingGuidelines": true, "codeOfConduct": true, "pullRequestTemplates": true, "issueTemplates": true}
	graphqlContentTypes  = map[string]bool{"Blob": true, "Tree": true, "TreeEntry": true}
)

// graphqlCheck walks every selection as written: no directives, no
// introspection beyond __typename, no argument named twice, aliases counted,
// and every first or last at most maxGraphQLPage.
type graphqlCheck struct {
	vars     map[string]any
	defaults func(string) *ast.Value
	aliases  int
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
			c.selections(s.SelectionSet)
		case *ast.InlineFragment:
			if len(s.Directives) > 0 || graphqlContentTypes[s.TypeCondition] {
				c.fail(ErrGraphQLUnmapped)
			}
			c.selections(s.SelectionSet)
		case *ast.FragmentSpread:
			if len(s.Directives) > 0 {
				c.fail(ErrGraphQLUnmapped)
			}
		}
	}
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
// fields. ok reports that it is one, answered with the broker's own reply.
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
		if len(f.Arguments) == 1 && f.Arguments[0].Name == "name" && f.Arguments[0].Value.Kind == ast.StringValue {
			fields = githubSchemaFeatures[f.Arguments[0].Value.Raw]
		}
		if fields == nil || len(f.Directives) > 0 || len(f.SelectionSet) != 1 || len(vars) > 0 || len(op.VariableDefinitions) > 0 || len(op.Directives) > 0 {
			return nil, true, ErrGraphQLIntrospection
		}
		inner, ok := f.SelectionSet[0].(*ast.Field)
		if !ok || inner.Name != "fields" || inner.Alias != "fields" && inner.Alias != "" || len(inner.Directives) > 0 ||
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
		data[key] = map[string]any{"fields": list}
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
			if len(f.SelectionSet) == 0 {
				return ErrGraphQLUnmapped
			}
			for _, sub := range f.SelectionSet {
				field, ok := sub.(*ast.Field)
				if !ok {
					return ErrGraphQLUnmapped
				}
				if field.Name == "__typename" {
					continue
				}
				op, ok := graphqlRepositoryFields[field.Name]
				if !ok {
					return ErrGraphQLUnmapped
				}
				ops[op] = true
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

// searchArgs reads a pull request search: type ISSUE, and a query naming
// exactly one repository with repo: and no other owner, organization or
// repository qualifier.
func searchArgs(args map[string]any) (string, bool) {
	query, ok := args["query"].(string)
	if !ok || args["type"] != "ISSUE" {
		return "", false
	}
	for key := range args {
		switch key {
		case "query", "type", "first", "last", "after", "before":
		default:
			return "", false
		}
	}
	repo := ""
	for _, term := range strings.Fields(query) {
		if strings.ContainsAny(term, "()") {
			return "", false // grouping could hide a qualifier from this reading
		}
		negated := strings.HasPrefix(term, "-")
		key, v, found := strings.Cut(strings.TrimLeft(strings.ToLower(term), "-"), ":")
		switch {
		case !found:
		case negated && (key == "repo" || key == "org" || key == "user" || key == "owner"):
			return "", false
		case key == "repo":
			if repo != "" {
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
	return repo, repo != "" && repoPattern.MatchString(repo) && !strings.Contains(repo, "..")
}

// mutationRoot maps the one mutation to its operation and node IDs. Its input
// must be a variable: GitHub then reads the very JSON value checked here, not
// a literal its own lexer might read differently.
func mutationRoot(set ast.SelectionSet, vars map[string]any, ops map[string]bool, targets *[]GraphQLTarget) error {
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
		if s, ok := v.(string); !ok || s == "" && key != "body" && key != "clientMutationId" {
			return ErrGraphQLUnmapped
		}
	}
	for key, required := range m.fields {
		if _, present := input[key]; required && !present {
			return ErrGraphQLUnmapped
		}
	}
	ops[m.op] = true
	*targets = append(*targets, GraphQLTarget{ID: input[m.target].(string), Kind: TargetPullRequestWrite})
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
			*targets = append(*targets, GraphQLTarget{ID: id, Kind: TargetLabel})
		}
	}
	return nil
}

// String names a target for errors and tests.
func (t GraphQLTarget) String() string { return fmt.Sprintf("%s %s", t.Kind, t.ID) }
