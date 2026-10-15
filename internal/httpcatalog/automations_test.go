package httpcatalog

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"
)

// automationCatalog is harnessCatalog with its Cursor pool deciding per
// Automation, a second entry, and two Automations.
func automationCatalog() map[string]any {
	c := harnessCatalog()
	h := harnessAt(c, 0)
	h["identity"].(map[string]any)["kind"] = "session-jwt"
	h["identity"].(map[string]any)["requester"] = map[string]any{"kind": "cursor-oidc"}
	h["authorization"].(map[string]any)["mode"] = "automation"
	pool := c["pools"].([]any)[0].(map[string]any)
	pool["identity"], pool["ceiling"] = "cursor-automation", "T1"
	second := strings.NewReplacer(`"name":"vendor"`, `"name":"tracker"`, `api.vendor.example`, `api.tracker.example`).
		Replace(`{` + strings.Replace(entryBase, `"pools":["p"]`, `"pools":["cursor-workers"]`, 1) + `}`)
	c["entries"] = append(c["entries"].([]any), json.RawMessage(second))
	c["automations"] = []any{
		map[string]any{"id": "auto-1", "name": "explorer", "owner": "owner@example.com", "entries": []any{"vendor", "tracker"}},
		map[string]any{"id": "auto-2", "name": "auditor", "owner": "owner@example.com", "entries": []any{"tracker"}},
	}
	return c
}

func TestAutomationPoolProfile(t *testing.T) {
	c := automationCatalog()
	catalog, err := parseCatalog(t, c)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := catalog.Pool("cursor-workers")
	if profile := p.Profile(); profile.Authorization.Mode != AuthorizeAutomation || profile.RequesterKind() != RequesterCursorOIDC {
		t.Fatalf("%+v", profile)
	}
	delete(c, "harnesses")
	derived, err := parseCatalog(t, c)
	if err != nil {
		t.Fatal(err)
	}
	if p, _ := derived.Pool("cursor-workers"); p.Profile().Authorization.Mode != AuthorizeAutomation || p.Profile().RequesterKind() != RequesterCursorOIDC {
		t.Fatalf("derived: %+v", p.Profile())
	}
	for name, mutate := range map[string]func(c map[string]any){
		"automation harness on a person pool": func(c map[string]any) {
			c["pools"].([]any)[0].(map[string]any)["identity"] = "cursor-session"
		},
		"person harness on an automation pool": func(c map[string]any) {
			harnessAt(c, 0)["authorization"].(map[string]any)["mode"] = "person"
		},
		"automation harness with a Claude requester": func(c map[string]any) {
			harnessAt(c, 0)["identity"].(map[string]any)["requester"] = map[string]any{"kind": "session-jwt"}
		},
		"automation harness with a pod token": func(c map[string]any) {
			harnessAt(c, 0)["identity"].(map[string]any)["kind"] = "pod-token"
			delete(harnessAt(c, 0)["identity"].(map[string]any), "requester")
		},
		"automation mode on a shared proxy": func(c map[string]any) {
			harnessAt(c, 2)["authorization"].(map[string]any)["mode"] = "automation"
		},
		"automation pool with fixed groups": func(c map[string]any) {
			c["pools"].([]any)[0].(map[string]any)["entitlements"] = []any{"11111111-2222-3333-4444-555555555555"}
		},
	} {
		c := automationCatalog()
		mutate(c)
		if _, err := parseCatalog(t, c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestAutomationsAreIndexedById(t *testing.T) {
	catalog, err := parseCatalog(t, automationCatalog())
	if err != nil {
		t.Fatal(err)
	}
	if catalog.Automations() != 2 {
		t.Fatalf("automations: %d", catalog.Automations())
	}
	pool, _ := catalog.Pool("cursor-workers")
	a, ok := pool.Automation("auto-1")
	if !ok || a.Name != "explorer" || a.Owner != "owner@example.com" || !a.Uses("vendor") || !a.Uses("tracker") {
		t.Fatalf("auto-1: %+v %v", a, ok)
	}
	if a, _ := pool.Automation("auto-2"); a.Uses("vendor") || !a.Uses("tracker") {
		t.Fatalf("auto-2 uses %v", a.Entries)
	}
	if _, ok := pool.Automation("auto-3"); ok {
		t.Fatal("an unlisted automation was found")
	}
	if _, ok := pool.Automation(""); ok {
		t.Fatal("an empty automation id was found")
	}
	// Only a cursor-automation pool decides per Automation.
	if other, _ := catalog.Pool("claude-sessions"); other.Identity == IdentityCursorAutomation {
		t.Fatal("fixture")
	} else if _, ok := other.Automation("auto-1"); ok {
		t.Fatal("a person pool lists automations")
	}
	if _, ok := catalog.Automation("auto-2"); !ok {
		t.Fatal("catalog lookup")
	}
}

func TestAutomationsRefusedAtLoad(t *testing.T) {
	for name, a := range map[string]map[string]any{
		"unknown entry":    {"id": "auto-9", "name": "x", "owner": "owner@example.com", "entries": []any{"missing"}},
		"no entries":       {"id": "auto-9", "name": "x", "owner": "owner@example.com", "entries": []any{}},
		"repeated entry":   {"id": "auto-9", "name": "x", "owner": "owner@example.com", "entries": []any{"vendor", "vendor"}},
		"duplicate id":     {"id": "auto-1", "name": "x", "owner": "owner@example.com", "entries": []any{"vendor"}},
		"unsafe id":        {"id": "auto 9", "name": "x", "owner": "owner@example.com", "entries": []any{"vendor"}},
		"owner not email":  {"id": "auto-9", "name": "x", "owner": "user:42", "entries": []any{"vendor"}},
		"upper-case owner": {"id": "auto-9", "name": "x", "owner": "Owner@example.com", "entries": []any{"vendor"}},
		"unsafe name":      {"id": "auto-9", "name": "an \"x\"", "owner": "owner@example.com", "entries": []any{"vendor"}},
		"unknown field":    {"id": "auto-9", "name": "x", "owner": "owner@example.com", "entries": []any{"vendor"}, "pools": []any{"p"}},
	} {
		c := automationCatalog()
		c["automations"] = append(c["automations"].([]any), a)
		if _, err := parseCatalog(t, c); err == nil {
			t.Errorf("%s: accepted", name)
		}
		// The tolerant load drops only that Automation, never the others.
		data, _ := json.Marshal(c)
		catalog, dropped, err := ParseTolerant(data)
		if err != nil {
			t.Fatalf("%s: tolerant: %v", name, err)
		}
		want := 2
		if name == "duplicate id" {
			want = 1 // both auto-1s go: the loader never picks a winner
		}
		if catalog.Automations() != want || len(dropped) == 0 || dropped[len(dropped)-1].Kind != "automation" {
			t.Errorf("%s: kept %d, dropped %+v", name, catalog.Automations(), dropped)
		}
	}
}

// An Automation naming an entry the tolerant load dropped goes with it: it
// reaches nothing rather than part of what was reviewed.
func TestAutomationNamingADroppedEntryIsDropped(t *testing.T) {
	c := automationCatalog()
	entries := c["entries"].([]any)
	entries[1] = json.RawMessage(strings.Replace(string(entries[1].(json.RawMessage)), `"methods":["GET"]`, `"methods":["BREW"]`, 1))
	data, _ := json.Marshal(c)
	catalog, dropped, err := ParseTolerant(data)
	if err != nil {
		t.Fatal(err)
	}
	if catalog.Automations() != 0 {
		t.Fatalf("kept %d automations; dropped %+v", catalog.Automations(), dropped)
	}
	var names []string
	for _, d := range dropped {
		names = append(names, d.Kind+":"+d.Name)
	}
	if got := strings.Join(names, ","); got != "automation:auto-1,automation:auto-2,entry:tracker" {
		t.Fatalf("dropped %s", got)
	}
}

// scaledAutomations is the automation catalog with n Automations, each using
// both entries.
func scaledAutomations(n int) []byte {
	c := automationCatalog()
	list := make([]any, n)
	for i := range n {
		list[i] = json.RawMessage(fmt.Sprintf(`{"id":"automation-%06d","name":"automation-%06d","owner":"owner%d@example.com","entries":["tracker","vendor"]}`, i, i, i%5000))
	}
	c["automations"] = list
	data, _ := json.Marshal(c)
	return data
}

// 100,000 Automations load, through the tolerant path the broker uses, in
// seconds and well under a gigabyte, and each lookup is a map read. The race
// detector slows the load about fiftyfold, so it checks only memory there.
func TestOneHundredThousandAutomationsLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("scale test")
	}
	const n = 100_000
	data := scaledAutomations(n)
	// Twice: the encoder's pooled buffer survives one collection.
	runtime.GC()
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	catalog, dropped, err := ParseTolerant(data)
	took := time.Since(start)
	if err != nil || len(dropped) != 0 || catalog.Automations() != n {
		t.Fatalf("load: %v, dropped %d, automations %d", err, len(dropped), catalog.Automations())
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(data)
	retained := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	t.Logf("%d automations: document %d bytes, load %s, retained heap %d MiB", n, len(data), took, retained>>20)
	if took > 10*time.Second && !raceDetector {
		t.Fatalf("load took %s", took)
	}
	if retained > 128<<20 {
		t.Fatalf("retained heap %d MiB", retained>>20)
	}
	pool, _ := catalog.Pool("cursor-workers")
	start = time.Now()
	for i := range n {
		a, ok := pool.Automation(fmt.Sprintf("automation-%06d", i))
		if !ok || !a.Uses("vendor") {
			t.Fatalf("automation %d", i)
		}
	}
	if per := time.Since(start) / n; per > 50*time.Microsecond && !raceDetector {
		t.Fatalf("lookup %s each", per)
	}
	runtime.KeepAlive(catalog)
}

// Automations stored one secret each load through the per-entry loader, so
// the head stays small however many there are.
func TestPrefixLoaderReadsAutomationsOneSecretEach(t *testing.T) {
	v := newPrefixVault(2)
	v.automations = map[string]string{}
	for i := range 3 {
		id := fmt.Sprintf("auto-%d", i)
		v.automations[id] = fmt.Sprintf(`{"id":%q,"name":"a%d","owner":"owner@example.com","entries":["e00001"]}`, id, i)
	}
	v.head["automations_sha256"] = entriesDigest(v.automations)
	raw, _, err := VaultPrefixLoader(v, "gatehouse", "catalog")(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	c, dropped, err := ParseTolerant(raw)
	if err != nil || len(dropped) != 0 || c.Automations() != 3 {
		t.Fatalf("automations %d, dropped %+v, %v", c.Automations(), dropped, err)
	}

	// A half-written apply: the head has not caught up.
	v.automations["auto-3"] = `{"id":"auto-3","name":"a3","owner":"owner@example.com","entries":["e00001"]}`
	v.headVersion++
	if _, _, err := VaultPrefixLoader(v, "gatehouse", "catalog")(context.Background()); err == nil || !strings.Contains(err.Error(), "automations do not match") {
		t.Fatalf("mismatch accepted: %v", err)
	}
	// An Automation stored under another id.
	v.automations["auto-3"] = strings.Replace(v.automations["auto-3"], `"id":"auto-3"`, `"id":"auto-1"`, 1)
	v.head["automations_sha256"] = entriesDigest(v.automations)
	if _, _, err := VaultPrefixLoader(v, "gatehouse", "catalog")(context.Background()); err == nil || !strings.Contains(err.Error(), "another name") {
		t.Fatalf("misnamed automation accepted: %v", err)
	}
	// A head that both stores them and carries its own.
	delete(v.automations, "auto-3")
	v.head["automations_sha256"] = entriesDigest(v.automations)
	v.head["catalog"] = `{"automations":[]}`
	if _, _, err := VaultPrefixLoader(v, "gatehouse", "catalog")(context.Background()); err == nil || !strings.Contains(err.Error(), "must not carry automations") {
		t.Fatalf("head with automations accepted: %v", err)
	}
	// Names without a digest would load nothing the head vouches for.
	v.head["catalog"] = `{}`
	delete(v.head, "automations_sha256")
	v.head["automations_names"] = []interface{}{"auto-1"}
	if _, _, err := VaultPrefixLoader(v, "gatehouse", "catalog")(context.Background()); err == nil || !strings.Contains(err.Error(), "without their digest") {
		t.Fatalf("names without a digest accepted: %v", err)
	}
}
