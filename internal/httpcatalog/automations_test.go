package httpcatalog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"runtime"
	"sort"
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
		"bad runner group": {"id": "auto-9", "name": "x", "owner": "owner@example.com", "runnerGroup": "engineers", "entries": []any{"vendor"}},
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

// bucketed stores Automations in 256 buckets by the first byte of the
// SHA-256 of their id, and sets the head's bucket digests.
func bucketed(v *prefixVault, automations map[string]string) {
	lists := map[string][]string{}
	for id, a := range automations {
		sum := sha256.Sum256([]byte(id))
		name := fmt.Sprintf("b%02x", sum[0])
		lists[name] = append(lists[name], a)
	}
	v.automations = map[string]string{}
	digests := map[string]interface{}{}
	for name, list := range lists {
		sort.Strings(list)
		stored := "[" + strings.Join(list, ",") + "]"
		v.automations[name] = stored
		sum := sha256.Sum256([]byte(stored))
		digests[name] = hex.EncodeToString(sum[:])
	}
	v.head["automations_buckets"] = digests
	v.headVersion++
}

func automationDoc(id, entry string) string {
	return fmt.Sprintf(`{"id":%q,"name":"a","owner":"owner@example.com","entries":[%q]}`, id, entry)
}

// 100,000 Automations in 256 buckets: the first load reads every bucket, and
// a change to one Automation rereads only its bucket.
func TestPrefixLoaderRereadsOnlyChangedBuckets(t *testing.T) {
	v := newPrefixVault(2)
	automations := make(map[string]string, 100_000)
	for i := range 100_000 {
		id := fmt.Sprintf("automation-%06d", i)
		automations[id] = automationDoc(id, "e00001")
	}
	bucketed(v, automations)
	load := VaultPrefixLoader(v, "gatehouse", "catalog")
	ctx := context.Background()
	raw, _, err := load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if c, dropped, err := ParseTolerant(raw); err != nil || len(dropped) != 0 || c.Automations() != 100_000 {
		t.Fatalf("first load: %d automations, dropped %d, %v", c.Automations(), len(dropped), err)
	}
	if reads := v.reads.Load(); reads != 1+2+256 {
		t.Fatalf("first load read %d secrets, want the head, 2 entries and 256 buckets", reads)
	}
	// An unchanged head costs one read.
	v.reads.Store(0)
	if _, _, err := load(ctx); err != nil || v.reads.Load() != 1 {
		t.Fatalf("unchanged head: %d reads, %v", v.reads.Load(), err)
	}
	// One Automation changes: the head, the entries (reread on every change)
	// and that one bucket.
	automations["automation-000042"] = automationDoc("automation-000042", "e00000")
	bucketed(v, automations)
	v.reads.Store(0)
	raw, _, err = load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if reads := v.reads.Load(); reads != 1+2+1 {
		t.Fatalf("one change read %d secrets, want the head, 2 entries and 1 bucket", reads)
	}
	c, _, err := ParseTolerant(raw)
	if err != nil || c.Automations() != 100_000 {
		t.Fatalf("after one change: %d, %v", c.Automations(), err)
	}
	if a, _ := c.Automation("automation-000042"); !a.Uses("e00000") || a.Uses("e00001") {
		t.Fatalf("changed automation: %+v", a)
	}
}

func TestPrefixLoaderRefusesBadBuckets(t *testing.T) {
	ctx := context.Background()
	fresh := func() *prefixVault {
		v := newPrefixVault(2)
		bucketed(v, map[string]string{"auto-1": automationDoc("auto-1", "e00001"), "auto-2": automationDoc("auto-2", "e00000")})
		return v
	}
	v := fresh()
	raw, _, err := VaultPrefixLoader(v, "gatehouse", "catalog")(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if c, _, err := ParseTolerant(raw); err != nil || c.Automations() != 2 {
		t.Fatalf("automations %d, %v", c.Automations(), err)
	}
	for name, mutate := range map[string]func(v *prefixVault){
		"a bucket written after the head": func(v *prefixVault) {
			for b := range v.automations {
				v.automations[b] = "[]"
			}
		},
		"a bucket the head lists but Vault lacks": func(v *prefixVault) {
			v.head["automations_buckets"].(map[string]interface{})["bff"] = strings.Repeat("0", 64)
		},
		"a digest that is not SHA-256 hex": func(v *prefixVault) {
			for b := range v.head["automations_buckets"].(map[string]interface{}) {
				v.head["automations_buckets"].(map[string]interface{})[b] = "x"
			}
		},
		"a head that is not an object":         func(v *prefixVault) { v.head["automations_buckets"] = []interface{}{"b00"} },
		"a head that also carries automations": func(v *prefixVault) { v.head["catalog"] = `{"automations":[]}` },
		"a stale writer's per-id digest":       func(v *prefixVault) { v.head["automations_sha256"] = strings.Repeat("0", 64) },
		"a stale writer's per-id names":        func(v *prefixVault) { v.head["automations_names"] = []interface{}{"auto-1"} },
	} {
		v := fresh()
		mutate(v)
		if _, _, err := VaultPrefixLoader(v, "gatehouse", "catalog")(ctx); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// The bucket map may also arrive as a string holding the object.
	v = fresh()
	text, _ := json.Marshal(v.head["automations_buckets"])
	v.head["automations_buckets"] = string(text)
	if _, _, err := VaultPrefixLoader(v, "gatehouse", "catalog")(ctx); err != nil {
		t.Fatalf("string bucket map: %v", err)
	}
}
