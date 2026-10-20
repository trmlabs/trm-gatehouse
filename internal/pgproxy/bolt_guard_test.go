package pgproxy

import (
	"strings"
	"testing"
)

// The plans below are Memgraph 3.11's EXPLAIN output, verbatim.
func TestPlanVerdict(t *testing.T) {
	plan := func(lines ...string) []string { return lines }
	reads := map[string][]string{
		"scan":      plan(" * Limit", " * Produce {n}", " * ScanAll (n)", " * Once"),
		"index":     plan(" * Produce {a, r, b}", " * Expand (a)-[r:R]->(b)", " * ScanAllByLabelProperties (a :A {x})", " * Once"),
		"variable":  plan(" * Produce {p}", " * ConstructNamedPath", " * ExpandVariable (a)-[anon1]->(b)", " * ScanAll (a)", " * Once"),
		"bfs":       plan(" * Produce {p}", " * ConstructNamedPath", " * BFSExpand (a)-[anon1]->(b)", " * ScanAll (a)", " * Once"),
		"weighted":  plan(" * Produce {p}", " * ConstructNamedPath", " * WeightedShortestPath (a)-[anon1]->(b)", " * ScanAll (a)", " * Once"),
		"all paths": plan(" * Produce {p}", " * ConstructNamedPath", " * AllShortestPaths (a)-[anon1]->(b)", " * ScanAll (a)", " * Once"),
		"optional": plan(" * Limit", " * Skip", " * OrderBy {a, count(c)}", " * Produce {a, count(c)}", " * Aggregate {COUNT-1} {a}", " * Optional",
			" |\\ ", " | * Expand (a)-[anon2]->(c)", " | * Once", " * Produce {a}", " * Filter (a :A)", " * ScanAll (a)", " * Once"),
		"union":            plan(" * Distinct", " * Union {x : x}", " |\\ ", " | * Produce {x}", " | * Once", " * Distinct", " * Produce {x}", " * Unwind", " * Once"),
		"subquery":         plan(" * Produce {a, b}", " * Apply", " |\\ ", " | * Produce {b}", " | * Expand (a)-[anon2]->(b)", " | * Produce {a}", " | * Once", " * ScanAll (a)", " * Once"),
		"pattern":          plan(" * Produce {a}", " * Filter Pattern", " |\\ ", " | * EvaluatePatternFilter", " | * Limit", " | * Expand (a)-[anon1]->(anon2)", " | * Once", " * ScanAll (a)", " * Once"),
		"rollup":           plan(" * Produce {ys}", " * RollUpApply", " |\\ ", " | * Produce {anon2}", " | * Expand (a)-[anon2]->(b)", " | * Once", " * ScanAll (a)", " * Once"),
		"joins":            plan(" * Produce {a}", " * HashJoin {a : b}", " |\\ ", " | * ScanAll (b)", " | * Once", " * IndexedJoin", " * Cartesian {a : b}", " * ScanAllById (a)", " * Once"),
		"listed procedure": plan(" * Produce {name}", " * CallProcedure<schema.node_type_properties> {name}", " * Once"),
	}
	for name, lines := range reads {
		for _, write := range []bool{false, true} {
			if got := planVerdict(lines, []string{"schema.node_type_properties"}, write); got != "" {
				t.Errorf("%s (write %v): refused at %q", name, write, got)
			}
		}
	}
	// Each refused on a read entry; graph writes (writes true) run on a write
	// entry, and everything else stays refused there too.
	refused := map[string]struct {
		lines  []string
		want   string
		writes bool
	}{
		"create":           {plan(" * EmptyResult", " * CreateNode", " * Once"), "CreateNode", true},
		"create edge":      {plan(" * EmptyResult", " * CreateExpand (a)-[anon1:R]->(b)", " * CreateNode", " * Once"), "CreateExpand", true},
		"set":              {plan(" * SetProperty", " * ScanAll (a)", " * Once"), "SetProperty", true},
		"set map":          {plan(" * EmptyResult", " * SetProperties", " * ScanAll (a)", " * Once"), "SetProperties", true},
		"set nested":       {plan(" * EmptyResult", " * SetNestedProperty", " * ScanAll (a)", " * Once"), "SetNestedProperty", true},
		"set labels":       {plan(" * EmptyResult", " * SetLabels", " * ScanAll (a)", " * Once"), "SetLabels", true},
		"delete":           {plan(" * Delete", " * ScanAll (a)", " * Once"), "Delete", true},
		"merge":            {plan(" * Produce {a}", " * Accumulate", " * Merge", " |\\ On Match", " | * ScanAllByLabelProperties (a :A {x})", " | * Once", " |\\ On Create", " | * CreateNode", " | * Once", " * Once"), "Merge", true},
		"remove":           {plan(" * RemoveLabels", " * ScanAll (a)", " * Once"), "RemoveLabels", true},
		"remove nested":    {plan(" * EmptyResult", " * RemoveNestedProperty", " * ScanAll (a)", " * Once"), "RemoveNestedProperty", true},
		"foreach":          {plan(" * Foreach", " |\\ ", " | * SetProperty", " | * Once", " * ScanAll (a)", " * Once"), "Foreach", true},
		"periodic.iterate": {plan(" * Produce {success}", " * CallProcedure<periodic.iterate> {success}", " * Once"), "CALL periodic.iterate", false},
		"periodic commit":  {plan(" * PeriodicCommit", " * EmptyResult", " * CreateNode", " * Unwind", " * Once"), "PeriodicCommit", false},
		"in transactions": {plan(" * Produce {i}", " * PeriodicSubquery", " |\\ ", " | * EmptyResult", " | * CreateNode", " | * Once", " * Unwind", " * Once"),
			"PeriodicSubquery", false},
		"write then load": {plan(" * EmptyResult", " * CreateNode", " * LoadCsv {row}", " * Once"), "CreateNode", false},
		"load csv":        {plan(" * Produce {row}", " * LoadCsv {row}", " * Once"), "LoadCsv", false},
		"load parquet":    {plan(" * Produce {row}", " * LoadParquet {row}", " * Once"), "LoadParquet", false},
		"load jsonl":      {plan(" * Produce {row}", " * LoadJsonl {row}", " * Once"), "LoadJsonl", false},
		"unlisted step":   {plan(" * Produce {n}", " * SomethingNew", " * Once"), "SomethingNew", false},
		"empty":           {nil, "empty plan", false},
		"unknown format":  {plan("CreateNode"), "unrecognized plan line", false},
		"no step name":    {plan(" * {x}"), "unrecognized plan line", false},
	}
	for name, c := range refused {
		if got := planVerdict(c.lines, []string{"schema.node_type_properties"}, false); got != c.want {
			t.Errorf("%s: read verdict %q, want %q", name, got, c.want)
		}
		got := planVerdict(c.lines, []string{"schema.node_type_properties"}, true)
		if c.writes && got != "" || !c.writes && got == "" {
			t.Errorf("%s: write verdict %q", name, got)
		}
	}
}

func TestModuleCalls(t *testing.T) {
	cases := map[string][]string{
		"MATCH (n) RETURN count(n), toUpper(n.name)":                     nil,
		"RETURN llm.complete('x')":                                       {"llm.complete"},
		"RETURN llm . complete ('x')":                                    {"llm.complete"},
		"RETURN llm/* c */./* c */complete/* c */('x')":                  {"llm.complete"},
		"RETURN `llm`.`complete`('x')":                                   {"llm.complete"},
		"RETURN `llm.complete`('x')":                                     {"llm.complete"},
		"RETURN a.b.c(1)":                                                {"a.b.c"},
		"RETURN 'llm.complete(' AS s, \"x.y(\" AS t":                     nil,
		"RETURN 'it\\'s llm.complete(' AS s":                             nil,
		"// llm.complete(\nRETURN 1":                                     nil,
		"CALL schema.node_type_properties() YIELD * RETURN *":            nil,
		"CALL /* x */ periodic.iterate('a','b',{}) YIELD success":        nil,
		"MATCH (n) WHERE n.x IN [1.5, 2] RETURN n.x, n {.name}":          nil,
		"MATCH (n) RETURN date.add(n.d, 1, 'day'), json_util.to_json(n)": {"date.add", "json_util.to_json"},
		"MATCH (`CALL`) RETURN `CALL` llm.complete('x')":                 {"llm.complete"},
	}
	// Every separator Memgraph 3.11's lexer skips, measured against a real
	// Memgraph: it runs date.add with each of these between the name's parts
	// and before the parenthesis. Go's unicode.IsSpace misses U+001C to
	// U+001F and U+180E.
	for _, sep := range []string{"\t", "\n", "\v", "\f", "\r", "\x1c", "\x1d", "\x1e", "\x1f", "\u00a0", "\u1680", "\u180e",
		"\u2000", "\u2005", "\u200a", "\u2028", "\u2029", "\u202f", "\u205f", "\u3000"} {
		for _, q := range []string{"RETURN llm" + sep + ".complete('x')", "RETURN llm." + sep + "complete('x')", "RETURN llm.complete" + sep + "('x')"} {
			cases[q] = []string{"llm.complete"}
		}
	}
	// A number never swallows what follows it: a list slice's range runs
	// straight into a call.
	cases["RETURN [1,2,3][1..llm.complete('x')]"] = []string{"llm.complete"}
	cases["RETURN [1,2,3][0..1.5e3+llm.complete('x')]"] = []string{"llm.complete"}
	cases["RETURN 0x1F + llm.complete('x'), 1.5e-3, 0o17"] = []string{"llm.complete"}
	// Another case or a lookalike letter is another name, refused unless
	// listed under that exact name.
	cases["RETURN LLM.Complete('x')"] = []string{"LLM.Complete"}
	cases["RETURN ll\u043c.complete('x')"] = []string{"ll\u043c.complete"}
	for query, want := range cases {
		got, ok := moduleCalls(query)
		if !ok {
			t.Errorf("%q: unreadable", query)
			continue
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%q: calls %v, want %v", query, got, want)
		}
	}
	for _, query := range []string{"RETURN 'open", "RETURN /* open", "RETURN `open", "RETURN 1llm.complete('x')", "RETURN 0xZZ"} {
		if refusedFunction(query, nil) != "unreadable query text" {
			t.Errorf("%q: not refused as unreadable", query)
		}
	}
	if got := refusedFunction("RETURN date.add(1,2,'day'), llm.complete('x')", []string{"date.add"}); got != "llm.complete" {
		t.Errorf("listed functions: refused %q", got)
	}
	if got := refusedFunction("RETURN date.add(1,2,'day')", []string{"date.add"}); got != "" {
		t.Errorf("listed function refused: %q", got)
	}
}
