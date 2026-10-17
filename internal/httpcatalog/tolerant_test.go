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
