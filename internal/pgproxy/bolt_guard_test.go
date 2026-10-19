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
		if got := planVerdict(lines, []string{"schema.node_type_properties"}); got != "" {
			t.Errorf("%s: refused at %q", name, got)
		}
	}
	writes := map[string]struct {
		lines []string
		want  string
	}{
		"create":           {plan(" * EmptyResult", " * CreateNode", " * Once"), "CreateNode"},
		"set":              {plan(" * SetProperty", " * ScanAll (a)", " * Once"), "SetProperty"},
		"delete":           {plan(" * Delete", " * ScanAll (a)", " * Once"), "Delete"},
		"merge":            {plan(" * Produce {a}", " * Accumulate", " * Merge", " |\\ On Match", " | * ScanAllByLabelProperties (a :A {x})", " | * Once", " |\\ On Create", " | * CreateNode", " | * Once", " * Once"), "Merge"},
		"remove":           {plan(" * RemoveLabels", " * ScanAll (a)", " * Once"), "RemoveLabels"},
		"foreach":          {plan(" * Foreach", " |\\ ", " | * SetProperty", " | * Once", " * ScanAll (a)", " * Once"), "Foreach"},
		"periodic.iterate": {plan(" * Produce {success}", " * CallProcedure<periodic.iterate> {success}", " * Once"), "CALL periodic.iterate"},
		"periodic commit":  {plan(" * PeriodicCommit", " * Unwind", " * Once"), "PeriodicCommit"},
		"in transactions":  {plan(" * Produce {n}", " * PeriodicSubquery", " * Once"), "PeriodicSubquery"},
		"load csv":         {plan(" * Produce {row}", " * LoadCsv {row}", " * Once"), "LoadCsv"},
		"load parquet":     {plan(" * Produce {row}", " * LoadParquet {row}", " * Once"), "LoadParquet"},
		"empty":            {nil, "empty plan"},
		"unknown format":   {plan("CreateNode"), "unrecognized plan line"},
		"no step name":     {plan(" * {x}"), "unrecognized plan line"},
	}
	for name, c := range writes {
		if got := planVerdict(c.lines, []string{"schema.node_type_properties"}); got != c.want {
			t.Errorf("%s: verdict %q, want %q", name, got, c.want)
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
	for _, query := range []string{"RETURN 'open", "RETURN /* open", "RETURN `open"} {
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
