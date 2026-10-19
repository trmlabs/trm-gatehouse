package httpcatalog

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/Infisical/agent-vault/internal/imagerule"
)

// Dropped names one part of a catalog version that a tolerant load left out,
// and why. Names are catalog identifiers, so they are safe to log; reasons
// never carry entry contents beyond what Parse's own errors name.
type Dropped struct {
	Kind   string // "entry", "pool", "harness" or "automation"
	Name   string
	Reason string
}

// ParseTolerant loads a catalog version one part at a time, so one bad part
// takes only itself, never the whole version, out of force. Every part it
// leaves out fails closed: a dropped entry is unreachable, and a dropped pool
// or harness takes the entries that grant it with it.
//
//   - An entry, pool or harness that fails its own validation (an unknown
//     field from a newer format, a bad grant or tier) is dropped.
//   - Parts that conflict (a duplicate name, a shared route, host, test user
//     or repository, overlapping harness images, a github-api entry's pull
//     request prefix reaching another pool's push prefix in a git entry) are
//     all dropped: the loader never picks a winner.
//   - When the version defines pools, an entry granting a dropped or unknown
//     pool is dropped. When it defines harnesses, a pool left with no harness
//     is dropped, so dropping a harness never removes the harness check.
//   - An Automation that fails its own validation, repeats another's id, or
//     names a dropped or unknown entry is dropped: it reaches nothing.
//
// The kept parts are then checked again by Parse, the strict validator, so
// the catalog returned is always one Parse accepts. A document that cannot be
// decoded at all, or that Parse still refuses, returns an error and the caller
// keeps its last good catalog. A version whose every entry is dropped loads as
// an empty catalog: nothing is reachable.
func ParseTolerant(data []byte) (Catalog, []Dropped, error) {
	var file struct {
		Harnesses   []json.RawMessage `json:"harnesses,omitempty"`
		Pools       []json.RawMessage `json:"pools,omitempty"`
		Entries     []json.RawMessage `json:"entries"`
		Automations []json.RawMessage `json:"automations,omitempty"`
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&file); err != nil {
		return Catalog{}, nil, fmt.Errorf("invalid HTTP catalog: %w", err)
	}
	if d.More() {
		return Catalog{}, nil, errors.New("trailing HTTP catalog data")
	}
	if len(file.Entries) == 0 {
		return Catalog{}, nil, errors.New("HTTP catalog has no entries")
	}
	var dropped []Dropped
	drop := func(kind, name string, err error) {
		dropped = append(dropped, Dropped{Kind: kind, Name: name, Reason: err.Error()})
	}

	// Pools, each on its own.
	type keptPool struct {
		raw  json.RawMessage
		pool Pool
	}
	var pools []keptPool
	for i, raw := range file.Pools {
		var p Pool
		err := strictDecode(raw, &p)
		if err == nil && (!idPattern.MatchString(p.Name) || !dnsLabel.MatchString(p.Namespace) || !dnsLabel.MatchString(p.ServiceAccount)) {
			err = errors.New("invalid pool name, namespace or service account")
		}
		if err == nil {
			err = p.validate()
		}
		if err != nil {
			drop("pool", partName(raw, i), err)
			continue
		}
		pools = append(pools, keptPool{raw, p})
	}
	pools = dropDuplicates(pools, func(p keptPool) string { return p.pool.Name }, func(p keptPool) {
		drop("pool", p.pool.Name, errors.New("duplicate pool"))
	})
	poolByName := make(map[string]Pool, len(pools))
	for _, p := range pools {
		poolByName[p.pool.Name] = p.pool
	}

	// Harnesses: each checked against its own pool, then against each other.
	type keptHarness struct {
		raw     json.RawMessage
		harness Harness
	}
	var harnesses []keptHarness
	for i, raw := range file.Harnesses {
		var h Harness
		err := strictDecode(raw, &h)
		if err == nil {
			pool, ok := poolByName[h.Authorization.PoolName]
			if !ok {
				err = fmt.Errorf("names undefined or dropped pool %q", h.Authorization.PoolName)
			} else {
				_, err = validateHarnesses([]Harness{h}, map[string]Pool{pool.Name: pool})
			}
		}
		if err != nil {
			drop("harness", partName(raw, i), err)
			continue
		}
		harnesses = append(harnesses, keptHarness{raw, h})
	}
	harnesses = dropDuplicates(harnesses, func(h keptHarness) string { return h.harness.Name }, func(h keptHarness) {
		drop("harness", h.harness.Name, errors.New("duplicate harness"))
	})
	harnesses = dropDuplicates(harnesses, func(h keptHarness) string { return h.harness.Authorization.PoolName }, func(h keptHarness) {
		drop("harness", h.harness.Name, fmt.Errorf("pool %q belongs to more than one harness", h.harness.Authorization.PoolName))
	})
	harnesses = dropConflicting(harnesses, func(a, b keptHarness) bool {
		ai, bi := a.harness.Identity, b.harness.Identity
		if ai.ImagePrefix != "" && bi.ImagePrefix != "" && imagerule.Overlap(ai.ImagePrefix, bi.ImagePrefix) {
			return true
		}
		return ai.Kind == IdentityProxyAttested && bi.Kind == IdentityProxyAttested &&
			a.harness.TrustDomain.Issuer == b.harness.TrustDomain.Issuer && ai.Namespaces[0] == bi.Namespaces[0]
	}, func(h keptHarness) {
		drop("harness", h.harness.Name, errors.New("claims an image prefix or namespace another harness claims"))
	})
	if len(file.Harnesses) > 0 {
		// Harnesses gate admission once any are listed: a pool whose harness
		// was dropped goes too, rather than being admitted with none.
		served := make(map[string]bool, len(harnesses))
		for _, h := range harnesses {
			served[h.harness.Authorization.PoolName] = true
		}
		kept := pools[:0]
		for _, p := range pools {
			if served[p.pool.Name] {
				kept = append(kept, p)
				continue
			}
			delete(poolByName, p.pool.Name)
			drop("pool", p.pool.Name, errors.New("has no harness"))
		}
		pools = kept
	}

	// Entries, each on its own against the kept pools.
	type keptEntry struct {
		raw   json.RawMessage
		entry Entry
	}
	definesPools := len(file.Pools) > 0
	var entries []keptEntry
	for i, raw := range file.Entries {
		var e Entry
		err := strictDecode(raw, &e)
		if err == nil {
			err = e.normalize()
		}
		if err == nil {
			err = e.validateTier()
		}
		if err == nil {
			for _, pool := range e.Pools {
				p, ok := poolByName[pool]
				if definesPools && !ok {
					err = fmt.Errorf("grants undefined or dropped pool %q", pool)
					break
				}
				if err = grantable(e, pool, p, definesPools); err != nil {
					err = fmt.Errorf("to pool %q: %w", pool, err)
					break
				}
			}
		}
		if err != nil {
			drop("entry", partName(raw, i), err)
			continue
		}
		entries = append(entries, keptEntry{raw, e})
	}
	entries = dropDuplicates(entries, func(e keptEntry) string { return e.entry.Name }, func(e keptEntry) {
		drop("entry", e.entry.Name, errors.New("duplicate entry name"))
	})
	entries = dropClaims(entries, func(e keptEntry) []claim { return entryClaims(e.entry) }, func(e keptEntry) {
		drop("entry", e.entry.Name, errors.New("shares a host, route, test user or repository with another entry"))
	})
	entries = dropPullRequestCrossings(entries, func(e keptEntry) Entry { return e.entry }, func(e keptEntry, err error) {
		drop("entry", e.entry.Name, err)
	})

	// Automations, each on its own against the kept entries. One naming a
	// dropped entry goes too, as an entry granting a dropped pool does.
	kept := make(map[string]bool, len(entries))
	for _, e := range entries {
		kept[e.entry.Name] = true
	}
	type keptAutomation struct {
		raw json.RawMessage
		id  string
	}
	var automations []keptAutomation
	for i, raw := range file.Automations {
		var a Automation
		err := strictDecode(raw, &a)
		if err == nil {
			err = a.validate()
		}
		for _, name := range a.Entries {
			if err == nil && !kept[name] {
				err = fmt.Errorf("names undefined or dropped entry %q", name)
			}
		}
		if err != nil {
			drop("automation", automationName(a.ID, i), err)
			continue
		}
		automations = append(automations, keptAutomation{raw, a.ID})
	}
	automations = dropDuplicates(automations, func(a keptAutomation) string { return a.id }, func(a keptAutomation) {
		drop("automation", a.id, errors.New("duplicate automation id"))
	})

	if len(entries) == 0 {
		return Catalog{}, dropped, nil
	}
	rawHarnesses := make([]json.RawMessage, len(harnesses))
	for i, h := range harnesses {
		rawHarnesses[i] = h.raw
	}
	rawPools := make([]json.RawMessage, len(pools))
	for i, p := range pools {
		rawPools[i] = p.raw
	}
	rawEntries := make([]json.RawMessage, len(entries))
	for i, e := range entries {
		rawEntries[i] = e.raw
	}
	rawAutomations := make([]json.RawMessage, len(automations))
	for i, a := range automations {
		rawAutomations[i] = a.raw
	}
	document, err := json.Marshal(struct {
		Harnesses   []json.RawMessage `json:"harnesses,omitempty"`
		Pools       []json.RawMessage `json:"pools,omitempty"`
		Entries     []json.RawMessage `json:"entries"`
		Automations []json.RawMessage `json:"automations,omitempty"`
	}{rawHarnesses, rawPools, rawEntries, rawAutomations})
	if err != nil {
		return Catalog{}, nil, err
	}
	c, err := Parse(document)
	if err != nil {
		return Catalog{}, nil, fmt.Errorf("catalog parts kept after dropping %d still fail validation: %w", len(dropped), err)
	}
	sort.SliceStable(dropped, func(i, j int) bool {
		if dropped[i].Kind != dropped[j].Kind {
			return dropped[i].Kind < dropped[j].Kind
		}
		return dropped[i].Name < dropped[j].Name
	})
	return c, dropped, nil
}

func strictDecode(raw json.RawMessage, v any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return fmt.Errorf("invalid: %w", err)
	}
	if d.More() {
		return errors.New("trailing data")
	}
	return nil
}

// partName is a part's name for a log line, or its position when it has no
// usable one.
func partName(raw json.RawMessage, i int) string {
	var named struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(raw, &named) == nil && idPattern.MatchString(named.Name) {
		return named.Name
	}
	return fmt.Sprintf("#%d", i)
}

// dropDuplicates drops every part whose key another part shares.
func dropDuplicates[T any](parts []T, key func(T) string, dropped func(T)) []T {
	count := map[string]int{}
	for _, p := range parts {
		count[key(p)]++
	}
	kept := parts[:0:0]
	for _, p := range parts {
		if count[key(p)] > 1 {
			dropped(p)
			continue
		}
		kept = append(kept, p)
	}
	return kept
}

// dropConflicting drops both parts of every conflicting pair.
func dropConflicting[T any](parts []T, conflict func(a, b T) bool, dropped func(T)) []T {
	bad := make([]bool, len(parts))
	for i := range parts {
		for j := i + 1; j < len(parts); j++ {
			if conflict(parts[i], parts[j]) {
				bad[i], bad[j] = true, true
			}
		}
	}
	kept := parts[:0:0]
	for i, p := range parts {
		if bad[i] {
			dropped(p)
			continue
		}
		kept = append(kept, p)
	}
	return kept
}

// claim is one key an entry occupies. Entries may share a key only when every
// claim on it is shareable and of the same kind, as plain HTTP or git entries
// on one host are.
type claim struct {
	key, kind string
	shareable bool
}

// entryClaims mirrors Parse's cross-entry checks: hosts, browser app hosts,
// test users, git repository routes, repositories with {requester} push
// prefixes (errRequesterRepo) and path prefix routes.
func entryClaims(e Entry) []claim {
	hostKey := fmt.Sprintf("%s:%d", e.Host, e.Port)
	claims := []claim{{key: "host " + hostKey, kind: e.Kind, shareable: e.Kind != "browser-session"}}
	if e.BrowserSession != nil {
		claims = append(claims,
			claim{key: "host " + fmt.Sprintf("%s:%d", e.BrowserSession.AppHost, e.Port), kind: "browser-session-app"},
			claim{key: fmt.Sprintf("user %+v", e.BrowserSession.User)})
	}
	if e.Git != nil {
		for _, repo := range e.Git.Repos {
			claims = append(claims, claim{key: "route " + hostKey + " " + e.Kind + " " + repo.Repo})
			if e.Kind == "git" {
				claims = append(claims, claim{key: "git repository " + repo.Repo, kind: e.Kind, shareable: !repo.perRequester()})
			}
		}
	}
	for _, prefix := range e.PathPrefixes {
		claims = append(claims, claim{key: "route " + hostKey + prefix})
	}
	return claims
}

// dropClaims drops every part holding a claim that conflicts with another
// claim on the same key, whichever part holds it, itself included.
func dropClaims[T any](parts []T, claimsOf func(T) []claim, dropped func(T)) []T {
	type holder struct {
		part int
		c    claim
	}
	byKey := map[string][]holder{}
	for i, p := range parts {
		for _, c := range claimsOf(p) {
			byKey[c.key] = append(byKey[c.key], holder{i, c})
		}
	}
	bad := make([]bool, len(parts))
	for _, holders := range byKey {
		if len(holders) < 2 {
			continue
		}
		shared := true
		for _, h := range holders {
			shared = shared && h.c.shareable && h.c.kind == holders[0].c.kind
		}
		if !shared {
			for _, h := range holders {
				bad[h.part] = true
			}
		}
	}
	kept := parts[:0:0]
	for i, p := range parts {
		if bad[i] {
			dropped(p)
			continue
		}
		kept = append(kept, p)
	}
	return kept
}

// dropPullRequestCrossings drops every github-api entry whose pull request
// prefixes reach push prefixes a pool they reach cannot push to
// (pullRequestCrossings), and each git entry it reaches into: as for any
// other conflict, both go.
func dropPullRequestCrossings[T any](parts []T, entryOf func(T) Entry, dropped func(T, error)) []T {
	all := make([]Entry, len(parts))
	for i, p := range parts {
		all[i] = entryOf(p)
	}
	reasons := map[string]error{}
	for _, e := range all {
		for _, c := range pullRequestCrossings(e, all) {
			for _, name := range []string{e.Name, c.git} {
				if reasons[name] == nil {
					reasons[name] = c.err
				}
			}
		}
	}
	kept := parts[:0:0]
	for i, p := range parts {
		if err := reasons[all[i].Name]; err != nil {
			dropped(p, err)
			continue
		}
		kept = append(kept, p)
	}
	return kept
}
