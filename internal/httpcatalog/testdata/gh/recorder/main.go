// Command recorder stands in for GitHub so the fixtures in testdata/gh can
// be recorded from a real gh without any token. It logs every request gh
// sends (method, path, the headers the fixtures keep, body) as one JSON line,
// and answers each GraphQL query with data shaped exactly by its selection,
// so gh carries on to its next call. See ../README.md.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"
)

const prID = "PR_kwDNA-jNB9A" // [0, 1000, 2000]

// scalar is a plausible value for a leaf field, by name.
func scalar(name, parent string) any {
	l := strings.ToLower(name)
	switch {
	case l == "id":
		return prID
	case l == "number" || l == "databaseid" || strings.HasSuffix(l, "count") || l == "additions" || l == "deletions":
		return 12
	case l == "isdraft":
		return os.Getenv("RECORDER_NOT_DRAFT") == "" // set it to record gh pr ready --undo
	case l == "viewerpermission":
		return "WRITE"
	case strings.HasPrefix(l, "requires") || strings.HasSuffix(l, "allowed") || strings.HasPrefix(l, "is") || strings.HasPrefix(l, "has") ||
		strings.HasPrefix(l, "viewer") || strings.HasPrefix(l, "maintainer") || l == "includescreatededit" || l == "locked":
		return false
	case l == "state":
		return "OPEN"
	case l == "status":
		return "COMPLETED"
	case l == "conclusion":
		return "SUCCESS"
	case strings.HasSuffix(l, "at") || l == "dueon":
		return "2026-10-01T00:00:00Z"
	case l == "headrefname":
		return "cursor/pool-agent/x"
	case l == "baserefname":
		return "main"
	case l == "endcursor":
		return ""
	case l == "mergeable":
		return "MERGEABLE"
	case l == "login":
		return "example-org"
	case l == "name" && parent == "labels":
		return "preview"
	case l == "name":
		return "example-repo"
	case l == "namewithowner":
		return "example-org/example-repo"
	case strings.HasSuffix(l, "url") || l == "permalink":
		return "https://github.localhost/example-org/example-repo/pull/12"
	case l == "oid":
		return "0123456789abcdef0123456789abcdef01234567"
	}
	return "x"
}

var lists = map[string]bool{"nodes": true, "edges": true, "reactionGroups": true, "checkRunCountsByState": true, "statusContextCountsByState": true, "files": true}

func build(set ast.SelectionSet, frags map[string]*ast.FragmentDefinition, typ, parent string) map[string]any {
	out := map[string]any{}
	for _, s := range set {
		switch s := s.(type) {
		case *ast.Field:
			key := s.Alias
			if key == "" {
				key = s.Name
			}
			switch {
			case s.Name == "__typename":
				out[key] = typ
			case s.Name == "fields": // feature detection: report every feature gh looks for
				out[key] = []any{map[string]any{"name": "isInMergeQueue"}, map[string]any{"name": "checkRunCount"}, map[string]any{"name": "event"}}
			case s.Name == "enumValues": // gh pr list --search asks which search types exist: set RECORDER_SEARCH_TYPES
				values := []any{}
				for _, v := range strings.Split(os.Getenv("RECORDER_SEARCH_TYPES"), ",") {
					values = append(values, map[string]any{"name": v})
				}
				out[key] = values
			case len(s.SelectionSet) == 0:
				out[key] = scalar(s.Name, parent)
			case s.Name == "milestone" || s.Name == "autoMergeRequest" || s.Name == "parent":
				out[key] = nil
			default:
				t := ""
				for _, sub := range s.SelectionSet {
					if f, ok := sub.(*ast.InlineFragment); ok && t == "" {
						t = f.TypeCondition
					}
				}
				p := parent
				if s.Name != "nodes" && s.Name != "edges" && s.Name != "node" {
					p = s.Name
				}
				obj := build(s.SelectionSet, frags, t, p)
				switch {
				case lists[s.Name] && parent == "pullRequests" && os.Getenv("RECORDER_NO_PULL_REQUESTS") != "":
					out[key] = []any{} // set it to record gh pr create, which stops on an open pull request
				case lists[s.Name]:
					out[key] = []any{obj}
				default:
					out[key] = obj
				}
			}
		case *ast.InlineFragment:
			if s.TypeCondition == "" || s.TypeCondition == typ || typ == "" {
				for k, v := range build(s.SelectionSet, frags, typ, parent) {
					out[k] = v
				}
			}
		case *ast.FragmentSpread:
			if f := frags[s.Name]; f != nil {
				for k, v := range build(f.SelectionSet, frags, typ, parent) {
					out[k] = v
				}
			}
		}
	}
	return out
}

func main() {
	if len(os.Args) != 3 {
		log.Fatal("usage: recorder ADDRESS LOGFILE")
	}
	out, err := os.OpenFile(os.Args[2], os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		log.Fatal(err)
	}
	var mu sync.Mutex
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		headers := map[string]string{}
		for _, k := range []string{"Accept", "Content-Type", "Graphql-Features", "X-Github-Api-Version"} {
			if v := r.Header.Get(k); v != "" {
				headers[k] = v
			}
		}
		line, _ := json.Marshal(map[string]any{"method": r.Method, "path": r.URL.Path, "headers": headers, "body": string(body)})
		mu.Lock()
		fmt.Fprintln(out, string(line))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/graphql" {
			_, _ = w.Write([]byte(`{}`))
			return
		}
		var req struct {
			Query string `json:"query"`
		}
		_ = json.Unmarshal(body, &req)
		doc, err := parser.ParseQuery(&ast.Source{Input: req.Query})
		if err != nil || len(doc.Operations) != 1 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		frags := map[string]*ast.FragmentDefinition{}
		for _, f := range doc.Fragments {
			frags[f.Name] = f
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": build(doc.Operations[0].SelectionSet, frags, "", "")})
	})
	log.Fatal(http.ListenAndServe(os.Args[1], nil))
}
