package httpcatalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// entryNamed is validEntry under another name, host and path, so it conflicts
// with nothing.
func entryNamed(name, host string) string {
	e := strings.Replace(validEntry, `"name":"serpapi"`, `"name":"`+name+`"`, 1)
	return strings.Replace(e, `"host":"serpapi.com"`, `"host":"`+host+`"`, 1)
}

func droppedNames(d []Dropped) string {
	var names []string
	for _, x := range d {
		names = append(names, x.Kind+":"+x.Name)
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

func entryNames(c Catalog) string {
	var names []string
	for _, e := range c.Entries() {
		names = append(names, e.Name)
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

func TestTolerantDropsOnlyTheBadEntries(t *testing.T) {
	newer := strings.Replace(entryNamed("newer", "newer.example.com"), `"pools"`, `"futureSetting":{"x":1},"pools"`, 1)
	wild := entryNamed("wild", "*.wild.example.com")
	doc := `{"entries":[` + validEntry + `,` + newer + `,` + wild + `]}`
	if _, err := Parse([]byte(doc)); err == nil {
		t.Fatal("strict parse accepted a bad entry")
	}
	c, dropped, err := ParseTolerant([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if got := entryNames(c); got != "serpapi" {
		t.Fatalf("kept %q, want serpapi", got)
	}
	if got := droppedNames(dropped); got != "entry:newer,entry:wild" {
		t.Fatalf("dropped %q", got)
	}
	for _, d := range dropped {
		if d.Reason == "" {
			t.Fatalf("no reason for %s", d.Name)
		}
	}
}

func TestTolerantDropsEveryPartOfAConflict(t *testing.T) {
	sameRoute := entryNamed("copycat", "serpapi.com")
	dupA, dupB := entryNamed("twin", "a.example.com"), entryNamed("twin", "b.example.com")
	other := entryNamed("other", "other.example.com")
	doc := `{"entries":[` + strings.Join([]string{validEntry, sameRoute, dupA, dupB, other}, ",") + `]}`
	c, dropped, err := ParseTolerant([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if got := entryNames(c); got != "other" {
		t.Fatalf("kept %q, want only the entry in no conflict", got)
	}
	if got := droppedNames(dropped); got != "entry:copycat,entry:serpapi,entry:twin,entry:twin" {
		t.Fatalf("dropped %q", got)
	}
	// Two browser-session entries sharing a test user both go.
	browserA := browserEntryJSON("")
	browserB := strings.NewReplacer(`"name":"staging-app"`, `"name":"staging-app-2"`, `"host":"api.example.com"`, `"host":"api2.example.com"`,
		`"appHost":"app.example.com"`, `"appHost":"app2.example.com"`).Replace(browserA)
	c, dropped, err = ParseTolerant([]byte(`{"entries":[` + browserA + `,` + browserB + `,` + other + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	if entryNames(c) != "other" || droppedNames(dropped) != "entry:staging-app,entry:staging-app-2" {
		t.Fatalf("shared test user: kept %q, dropped %q", entryNames(c), droppedNames(dropped))
	}
	// Plain entries may share a host on different paths, as before.
	shared := strings.Replace(entryNamed("account", "serpapi.com"), `"pathPrefixes":["/search","/account/"]`, `"pathPrefixes":["/v2/"]`, 1)
	c, dropped, err = ParseTolerant([]byte(`{"entries":[` + validEntry + `,` + shared + `]}`))
	if err != nil || entryNames(c) != "account,serpapi" || len(dropped) != 0 {
		t.Fatalf("shared host: kept %q dropped %q err %v", entryNames(c), droppedNames(dropped), err)
	}
}

func TestTolerantPoolsTakeTheirEntriesWithThem(t *testing.T) {
	grant := func(name, host, pool string) string {
		return strings.Replace(entryNamed(name, host), `"pools":["pool-a"]`, `"pools":["`+pool+`"]`, 1)
	}
	doc := `{"pools":[{"name":"pool-a","namespace":"a","serviceAccount":"w"},{"name":"pool-b","namespace":"b","serviceAccount":"w","ceiling":"T9"}],
		"entries":[` + grant("kept", "kept.example.com", "pool-a") + `,` + grant("on-b", "b.example.com", "pool-b") + `,` +
		grant("on-missing", "m.example.com", "pool-zz") + `]}`
	c, dropped, err := ParseTolerant([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if entryNames(c) != "kept" || droppedNames(dropped) != "entry:on-b,entry:on-missing,pool:pool-b" {
		t.Fatalf("kept %q, dropped %q", entryNames(c), droppedNames(dropped))
	}
	if len(c.Pools()) != 1 {
		t.Fatalf("pools in force %d, want 1", len(c.Pools()))
	}
}

func TestTolerantHarnessesNeverFailOpen(t *testing.T) {
	cat := harnessCatalog()
	sandboxOnly := json.RawMessage(`{` + strings.NewReplacer(`"name":"vendor"`, `"name":"sandbox-only"`, `"host":"api.vendor.example"`, `"host":"sandbox.vendor.example"`,
		`"pools":["p"]`, `"pools":["sandboxes"]`).Replace(entryBase) + `}`)
	cat["entries"] = append(cat["entries"].([]any), sandboxOnly)
	harnessAt(cat, 0)["futureSetting"] = true // the cursor harness, in a newer format
	data, err := json.Marshal(cat)
	if err != nil {
		t.Fatal(err)
	}
	c, dropped, err := ParseTolerant(data)
	if err != nil {
		t.Fatal(err)
	}
	// The cursor pool loses its harness, so it goes, and so does the entry
	// that grants it; the entry on the sandbox pool alone stays.
	if entryNames(c) != "sandbox-only" || droppedNames(dropped) != "entry:vendor,harness:cursor,pool:example-workers" {
		t.Fatalf("kept %q, dropped %q", entryNames(c), droppedNames(dropped))
	}
	if hs := c.Harnesses(); len(hs) != 2 || len(c.Pools()) != 2 {
		t.Fatalf("harnesses %d pools %d in force, want the two intact pairs", len(hs), len(c.Pools()))
	}
	// With every harness dropped, every pool and entry goes: dropping
	// harnesses never turns the harness check off.
	for i := range 3 {
		harnessAt(cat, i)["futureSetting"] = true
	}
	data, _ = json.Marshal(cat)
	c, dropped, err = ParseTolerant(data)
	if err != nil || len(c.Entries()) != 0 || len(c.Pools()) != 0 {
		t.Fatalf("all harnesses dropped: entries %d pools %d err %v dropped %q", len(c.Entries()), len(c.Pools()), err, droppedNames(dropped))
	}
}

func TestTolerantRefusesAnUndecodableDocument(t *testing.T) {
	for name, doc := range map[string]string{
		"truncated":        `{"entries":[` + validEntry,
		"new top section":  `{"futureSection":{},"entries":[` + validEntry + `]}`,
		"no entries":       `{"entries":[]}`,
		"trailing content": `{"entries":[` + validEntry + `]} {}`,
	} {
		if _, _, err := ParseTolerant([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestSourceDropsBadEntriesAndAppliesTheRest(t *testing.T) {
	two := `{"entries":[` + validEntry + `,` + entryNamed("other", "other.example.com") + `]}`
	loader := &scriptedLoader{doc: two, version: 1}
	var mu sync.Mutex
	var accepted []int
	source, err := Start(context.Background(), loader.load, nil, func(version int, _ []byte, _ []Dropped) {
		mu.Lock()
		accepted = append(accepted, version)
		mu.Unlock()
	})
	if err != nil || entryNames(source.Current()) != "other,serpapi" {
		t.Fatalf("start: %v %q", err, entryNames(source.Current()))
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go source.Watch(ctx, 5*time.Millisecond, loader.load, func(int, error) {})
	// Version 2 removes "other" and adds a broken entry: the removal applies,
	// the broken entry is left out.
	loader.set(`{"entries":[`+validEntry+`,`+entryNamed("broken", "*.broken.example.com")+`]}`, 2, nil)
	waitFor(t, "version 2", func() bool { return source.Version() == 2 })
	if entryNames(source.Current()) != "serpapi" || droppedNames(source.Dropped()) != "entry:broken" {
		t.Fatalf("in force %q, dropped %q", entryNames(source.Current()), droppedNames(source.Dropped()))
	}
	mu.Lock()
	defer mu.Unlock()
	if fmt.Sprint(accepted) != "[1 2]" {
		t.Fatalf("accepted versions %v", accepted)
	}
}

// Entries on one host that disagree on http2 conflict like any other pair:
// both are left out and the rest of the version, a removal included, takes
// effect. Parse refuses the disagreement, so without this the watcher would
// refuse the whole version and keep a removed grant in force.
func TestSourceDropsAnHTTP2DisagreementAndAppliesTheRest(t *testing.T) {
	rpc := func(name, prefix, h2 string) string {
		e := strings.Replace(entryNamed(name, "rpc.example.com"), `"/search","/account/"`, `"`+prefix+`"`, 1)
		return strings.Replace(e, `"pools":["pool-a"]`, `"pools":["pool-a"]`+h2, 1)
	}
	reads := rpc("reads", "/example.v1.Reads/", `,"http2":true`)
	loader := &scriptedLoader{doc: `{"entries":[` + validEntry + `,` + reads + `,` + entryNamed("retired", "retired.example.com") + `]}`, version: 1}
	source, err := Start(context.Background(), loader.load, nil, nil)
	if err != nil || entryNames(source.Current()) != "reads,retired,serpapi" {
		t.Fatalf("start: %v %q", err, entryNames(source.Current()))
	}
	if _, err := source.Current().Match("retired.example.com", 443, "GET", "/search", "pool-a"); err != nil {
		t.Fatalf("version 1 does not grant retired: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	var rejected []error
	go source.Watch(ctx, 5*time.Millisecond, loader.load, func(_ int, err error) {
		mu.Lock()
		rejected = append(rejected, err)
		mu.Unlock()
	})
	// Version 2 removes retired and adds a second rpc.example.com entry that
	// leaves http2 out.
	v2 := `{"entries":[` + validEntry + `,` + reads + `,` + rpc("writes", "/example.v1.Writes/", ``) + `]}`
	if _, err := Parse([]byte(v2)); err == nil {
		t.Fatal("strict parse accepted entries that disagree on http2")
	}
	loader.set(v2, 2, nil)
	waitFor(t, "version 2", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return source.Version() == 2 || len(rejected) > 0
	})
	mu.Lock()
	defer mu.Unlock()
	if len(rejected) > 0 {
		t.Fatalf("version 2 refused, so its removal never applied: %v", rejected[0])
	}
	c := source.Current()
	if entryNames(c) != "serpapi" || droppedNames(source.Dropped()) != "entry:reads,entry:writes" {
		t.Fatalf("in force %q, dropped %q", entryNames(c), droppedNames(source.Dropped()))
	}
	if _, err := c.Match("retired.example.com", 443, "GET", "/search", "pool-a"); !errors.Is(err, ErrUnlisted) || c.HasHost("retired.example.com", 443) {
		t.Fatalf("the removed entry is still reachable: %v", err)
	}
	if c.HasHost("rpc.example.com", 443) || c.HTTP2Host("rpc.example.com", 443) {
		t.Fatal("an entry in the disagreement is still reachable")
	}
	for _, d := range source.Dropped() {
		if !strings.Contains(d.Reason, "http2") {
			t.Fatalf("%s dropped for %q, which does not name http2", d.Name, d.Reason)
		}
	}
}

func TestSourceStartsFromTheStoredCatalogOrEmpty(t *testing.T) {
	down := &scriptedLoader{err: errors.New("sealed")}
	stored := &scriptedLoader{doc: `{"entries":[` + validEntry + `]}`, version: 4}
	source, err := Start(context.Background(), down.load, stored.load, nil)
	if err == nil || !source.Loaded() || entryNames(source.Current()) != "serpapi" {
		t.Fatalf("stored start: err %v loaded %v entries %q", err, source.Loaded(), entryNames(source.Current()))
	}
	if source.Version() != 0 {
		t.Fatal("a stored copy must not hide the primary's version from Watch")
	}
	// Nothing stored either: empty, not loaded, then Watch recovers.
	source, err = Start(context.Background(), down.load, (&scriptedLoader{err: errors.New("none stored")}).load, nil)
	if err == nil || source.Loaded() || len(source.Current().Entries()) != 0 {
		t.Fatalf("empty start: err %v loaded %v", err, source.Loaded())
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go source.Watch(ctx, 5*time.Millisecond, down.load, func(int, error) {})
	down.set(`{"entries":[`+validEntry+`]}`, 5, nil)
	waitFor(t, "recovery", func() bool { return source.Loaded() && source.Version() == 5 })
}

// Every cross-entry check Parse makes has a claim or crossing in
// ParseTolerant, so two entries that conflict are dropped and never refuse
// the version, and two entries Parse accepts together are both kept. Each
// ordered pair of entry kinds is tried as written, on one host, on one host
// with distinct paths, and on distinct hosts.
func TestTolerantMirrorsEveryCrossEntryCheck(t *testing.T) {
	pools := `"pools":[{"name":"pool-a","namespace":"a","serviceAccount":"w"},{"name":"pool-b","namespace":"b","serviceAccount":"w"},
		{"name":"pool-c","namespace":"c","serviceAccount":"w"},{"name":"database-developers","namespace":"d","serviceAccount":"w"},
		{"name":"people","namespace":"n","serviceAccount":"people","identity":"cursor-session"},
		{"name":"automations","namespace":"n","serviceAccount":"automations","identity":"cursor-automation"},
		{"name":"claude","namespace":"n","serviceAccount":"claude","identity":"claude-session","ccpoolID":"ccpool_abc","ceiling":"T1"}]`
	kinds := map[string]string{
		"header":                   validEntry,
		"header http2":             strings.Replace(validEntry, `"pools":["pool-a"]`, `"pools":["pool-a"],"http2":true`, 1),
		"request fields":           slackEntry,
		"gcp":                      bqEntry,
		"gcp http2":                strings.Replace(bqEntry, `"kind":"gcp",`, `"kind":"gcp","http2":true,`, 1),
		"git":                      gitEntry,
		"github-api":               apiEntry,
		"pool prefixes git":        poolsGitEntry,
		"pool prefixes github-api": poolsAPIEntry,
		"requester git": `{"name":"github","host":"github.com","kind":"git","pools":["people"],"git":{"appID":7,"installationID":42,
			"repos":[{"repo":"example-org/example-app","access":"write","poolRefPrefixes":{"people":["refs/heads/cursor/people/{requester}/"]}}]}}`,
		"browser session": browserEntryJSON(""),
		"automated auth":  automatedEntryJSON(automatedSettings),
		"memgraph":        graphEntry,
		"postgres":        `{"name":"core","kind":"postgres","host":"p.abc.db.postgresbridge.com","pools":["pool-a"],"postgres":{"database":"core","mount":"database","role":"r-readonly"}}`,
	}
	decode := func(t *testing.T, e string) map[string]any {
		t.Helper()
		var m map[string]any
		if err := json.Unmarshal([]byte(e), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	moves := map[string]func(a, b map[string]any){
		"as written": func(a, b map[string]any) {},
		"one host": func(a, b map[string]any) {
			b["host"], b["port"] = a["host"], a["port"]
		},
		"one host, distinct paths": func(a, b map[string]any) {
			b["host"], b["port"] = a["host"], a["port"]
			if prefixes, ok := b["pathPrefixes"].([]any); ok {
				for i, p := range prefixes {
					prefixes[i] = "/moved" + p.(string)
				}
			}
		},
		"distinct hosts": func(a, b map[string]any) { b["host"] = "moved." + b["host"].(string) },
	}
	for aName, aJSON := range kinds {
		if _, err := Parse([]byte(`{` + pools + `,"entries":[` + aJSON + `]}`)); err != nil {
			t.Fatalf("%s alone: %v", aName, err)
		}
		for bName, bJSON := range kinds {
			for move, apply := range moves {
				a, b := decode(t, aJSON), decode(t, bJSON)
				b["name"] = "moved-" + b["name"].(string)
				apply(a, b)
				if b["port"] == nil {
					delete(b, "port")
				}
				pair, _ := json.Marshal(map[string]any{"entries": []any{a, b}})
				doc := []byte(`{` + pools + `,` + string(pair[1:]))
				_, dropped, err := ParseTolerant(doc)
				if err != nil {
					t.Errorf("%s and %s, %s: the version is refused: %v", aName, bName, move, err)
					continue
				}
				if _, strict := Parse(doc); strict == nil && len(dropped) > 0 {
					t.Errorf("%s and %s, %s: Parse accepts the pair, but %q were dropped", aName, bName, move, droppedNames(dropped))
				}
			}
		}
	}
}
