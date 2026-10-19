package pgproxy

import (
	"strings"
	"unicode"
)

// A graph login cannot be made read-only on Memgraph's Community edition: it
// has no roles, any user may create users, and a session's read access mode
// does not stop writes. Rolling every transaction back is not enough either:
// periodic.iterate and USING PERIODIC COMMIT commit on their own, and
// procedures such as export_util write files on the server. So the broker
// decides each query itself before it runs, from Memgraph's own plan for it
// (EXPLAIN), and refuses unless every step of the plan is one that only
// reads. A procedure call is one step, refused unless the entry lists the
// procedure. Functions never show in a plan, and a module function can reach
// the network (llm.complete), so a call to any module function is refused
// unless the entry lists it. Transactions still open in read mode and are
// rolled back, so a mistake in this list cannot commit.

// readPlanSteps are the plan operators that only read the graph. Anything
// else, including an operator a later Memgraph adds, is refused.
var readPlanSteps = map[string]bool{
	"Once": true, "Produce": true, "Limit": true, "Skip": true, "OrderBy": true,
	"Aggregate": true, "Distinct": true, "Optional": true, "Filter": true,
	"EvaluatePatternFilter": true, "EdgeUniquenessFilter": true, "Unwind": true,
	"Union": true, "Apply": true, "RollUpApply": true, "Cartesian": true,
	"IndexedJoin": true, "HashJoin": true, "ConstructNamedPath": true,
	"Expand": true, "ExpandVariable": true, "BFSExpand": true, "DFSExpand": true,
	"WeightedShortestPath": true, "AllShortestPaths": true, "KShortestPaths": true,
}

// planVerdict checks the lines EXPLAIN returned. It returns "" when every step
// reads, or the step that does not (a procedure as "CALL name"), naming the
// write itself rather than the steps that only wrap a write.
func planVerdict(lines []string, procedures []string) string {
	if len(lines) == 0 {
		return "empty plan"
	}
	verdict := ""
	for _, line := range lines {
		step := planStep(line, procedures)
		if step == "" {
			continue
		}
		if step == "unrecognized plan line" {
			return step
		}
		if verdict == "" || wrapsWrite[verdict] && !wrapsWrite[step] {
			verdict = step
		}
	}
	return verdict
}

// wrapsWrite are steps that appear around a write and say less than it does.
var wrapsWrite = map[string]bool{"EmptyResult": true, "Accumulate": true}

// planStep returns "" for a line that reads, or the step it refuses.
func planStep(line string, procedures []string) string {
	rest := strings.TrimLeft(line, " |\\")
	switch {
	case rest == "", rest == "On Match", rest == "On Create":
		// Branch markers. Merge, the only step that has these, is refused.
		return ""
	case !strings.HasPrefix(rest, "* "):
		return "unrecognized plan line"
	}
	rest = rest[2:]
	end := strings.IndexFunc(rest, func(r rune) bool { return (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') })
	step := rest
	if end >= 0 {
		step = rest[:end]
	}
	switch {
	case step == "CallProcedure":
		name, ok := strings.CutPrefix(rest[len(step):], "<")
		if i := strings.IndexByte(name, '>'); ok && i > 0 && contains(procedures, name[:i]) {
			return ""
		}
		if i := strings.IndexByte(name, '>'); ok && i > 0 {
			return "CALL " + name[:i]
		}
		return "CALL"
	case strings.HasPrefix(step, "ScanAll"), readPlanSteps[step]:
		return ""
	}
	if step == "" {
		return "unrecognized plan line"
	}
	return step
}

func contains(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

// moduleCalls returns every call in query to a function whose name has a
// namespace (module.function), so built-in functions such as count() pass.
// It reads Cypher the way Memgraph's lexer does: strings, comments and
// backquoted names are tokens, so a name split by spaces, comments or
// backquotes is still one name. ok is false when the text cannot be read
// (an unterminated string, comment or name): the query is then refused.
func moduleCalls(query string) (calls []string, ok bool) {
	type token struct {
		kind byte // 'n' name, 'q' backquoted name, 'p' punctuation, 'o' other
		text string
	}
	isName := func(k byte) bool { return k == 'n' || k == 'q' }
	var tokens []token
	rs := []rune(query)
	for i := 0; i < len(rs); {
		r := rs[i]
		switch {
		case unicode.IsSpace(r):
			i++
		case r == '/' && i+1 < len(rs) && rs[i+1] == '/':
			for i < len(rs) && rs[i] != '\n' && rs[i] != '\r' {
				i++
			}
		case r == '/' && i+1 < len(rs) && rs[i+1] == '*':
			end := -1
			for j := i + 2; j+1 < len(rs); j++ {
				if rs[j] == '*' && rs[j+1] == '/' {
					end = j + 2
					break
				}
			}
			if end < 0 {
				return nil, false
			}
			i = end
		case r == '\'' || r == '"':
			j := i + 1
			for ; j < len(rs) && rs[j] != r; j++ {
				if rs[j] == '\\' {
					j++
				}
			}
			if j >= len(rs) {
				return nil, false
			}
			tokens = append(tokens, token{'o', ""})
			i = j + 1
		case r == '`':
			var name []rune
			j := i + 1
			for {
				if j >= len(rs) {
					return nil, false
				}
				if rs[j] == '`' {
					if j+1 < len(rs) && rs[j+1] == '`' {
						name = append(name, '`')
						j += 2
						continue
					}
					break
				}
				name = append(name, rs[j])
				j++
			}
			tokens = append(tokens, token{'q', string(name)})
			i = j + 1
		case unicode.IsDigit(r):
			// A number, including 1.5 and 1e3, is never part of a name.
			j := i
			for j < len(rs) && (unicode.IsLetter(rs[j]) || unicode.IsDigit(rs[j]) || rs[j] == '.' || rs[j] == '_') {
				j++
			}
			tokens = append(tokens, token{'o', ""})
			i = j
		case unicode.IsLetter(r) || r == '_' || r == '$':
			j := i + 1
			for j < len(rs) && (unicode.IsLetter(rs[j]) || unicode.IsDigit(rs[j]) || rs[j] == '_') {
				j++
			}
			tokens = append(tokens, token{'n', string(rs[i:j])})
			i = j
		default:
			tokens = append(tokens, token{'p', string(r)})
			i++
		}
	}
	for i, t := range tokens {
		if t.kind != 'p' || t.text != "(" || i == 0 || !isName(tokens[i-1].kind) {
			continue
		}
		// Walk back over name.name.name to the start of the call's name.
		parts := []string{tokens[i-1].text}
		j := i - 1
		for j >= 2 && tokens[j-1].kind == 'p' && tokens[j-1].text == "." && isName(tokens[j-2].kind) {
			parts = append([]string{tokens[j-2].text}, parts...)
			j -= 2
		}
		name := strings.Join(parts, ".")
		// After CALL the name is a procedure's, which the plan shows and
		// checks; Memgraph never runs a function there.
		if j >= 1 && tokens[j-1].kind == 'n' && strings.EqualFold(tokens[j-1].text, "CALL") {
			continue
		}
		if strings.Contains(name, ".") {
			calls = append(calls, name)
		}
	}
	return calls, true
}

// refusedFunction is the first module function query calls that the entry
// does not list, "" when there is none, or a reason when query cannot be read.
func refusedFunction(query string, functions []string) string {
	calls, ok := moduleCalls(query)
	if !ok {
		return "unreadable query text"
	}
	for _, name := range calls {
		if !contains(functions, name) {
			return name
		}
	}
	return ""
}
