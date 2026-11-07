package httpcatalog

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Infisical/agent-vault/internal/imagerule"
)

// Dropped names one part a tolerant load left out, and why; names are safe to log, reasons carry no entry contents.
type Dropped struct {
	Kind   string // "entry", "pool", "harness" or "automation"
	Name   string
	Reason string
}

// ParseTolerant loads a catalog version one part at a time, so one bad part takes only itself out of force. Every dropped part fails closed: a dropped entry is unreachable, and a dropped pool or harness takes the entries granting it.
// Parts failing their own validation are dropped; parts that conflict (duplicate name, shared route, host, test user or repository, http2 disagreement, overlapping harness images, a pull request prefix reaching another pool's push prefix) are all dropped, never picking a winner. The kept parts are re-checked by Parse; an undecodable document or one Parse still refuses returns an error, and a version with every entry dropped loads empty.
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
	// A pool deciding per Automation may have one harness per identity kind (sharePool), at most one static-token; any other pool has one.
	harnesses = dropConflicting(harnesses, func(a, b keptHarness) bool {
		if a.harness.Authorization.PoolName == b.harness.Authorization.PoolName && !sharePool(a.harness, b.harness) {
			return true
		}
		if ta, tb := a.harness.Identity.Token, b.harness.Identity.Token; ta != nil && tb != nil && ta.Issuer == tb.Issuer {
			return true
		}
		return a.harness.Identity.Kind == IdentityStaticToken && b.harness.Identity.Kind == IdentityStaticToken
	}, func(h keptHarness) {
		drop("harness", h.harness.Name, errors.New("belongs to a pool another harness also names, or is one of two static-token harnesses, or shares a signed-token issuer"))
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
	// A signed-token issuer that equals a trust domain's is dropped alone, so the Kubernetes harness keeps serving.
	trust := map[string]bool{}
	for _, h := range harnesses {
		if h.harness.TrustDomain.Issuer != "" {
			trust[strings.TrimSuffix(h.harness.TrustDomain.Issuer, "/")] = true
		}
	}
	uncolliding := harnesses[:0:0]
	for _, h := range harnesses {
		if t := h.harness.Identity.Token; t != nil && trust[strings.TrimSuffix(t.Issuer, "/")] {
			drop("harness", h.harness.Name, errors.New("names an issuer that is a trustDomain.issuer"))
			continue
		}
		uncolliding = append(uncolliding, h)
	}
	harnesses = uncolliding
	if len(file.Harnesses) > 0 {
		// Harnesses gate admission once any are listed, so a pool whose harness was dropped goes too.
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
	entries = dropClaims(entries, func(e keptEntry) []claim { return entryClaims(e.entry) }, func(e keptEntry, c claim) {
		drop("entry", e.entry.Name, errors.New(c.conflict()))
	})
	entries = dropPullRequestCrossings(entries, func(e keptEntry) Entry { return e.entry }, func(e keptEntry, err error) {
		drop("entry", e.entry.Name, err)
	})

	kept := make(map[string]bool, len(entries))
	keptKind := make(map[string]string, len(entries))
	for _, e := range entries {
		kept[e.entry.Name] = true
		keptKind[e.entry.Name] = e.entry.Kind
	}
	type keptAutomation struct {
		raw   json.RawMessage
		id    string
		block Automation
	}
	signedHarnesses := map[string]bool{}
	hasGroupsClaim := map[string]bool{}
	for _, h := range harnesses {
		if h.harness.Identity.Kind == IdentitySignedToken {
			signedHarnesses[h.harness.Name] = true
			hasGroupsClaim[h.harness.Name] = h.harness.Identity.Token != nil && h.harness.Identity.Token.GroupsClaim != ""
		}
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
		if err == nil {
			err = a.checkWrite(func(entry string) string { return keptKind[entry] })
		}
		if err == nil && a.SignedToken != nil && !signedHarnesses[a.SignedToken.Harness] {
			err = fmt.Errorf("names undefined or dropped signed-token harness %q", a.SignedToken.Harness)
		}
		if err == nil && a.SignedToken != nil && len(a.SignedToken.Groups) > 0 && !hasGroupsClaim[a.SignedToken.Harness] {
			err = fmt.Errorf("lists signedToken groups but harness %q has no groupsClaim", a.SignedToken.Harness)
		}
		if err != nil {
			drop("automation", automationName(a.ID, i), err)
			continue
		}
		automations = append(automations, keptAutomation{raw, a.ID, a})
	}
	automations = dropDuplicates(automations, func(a keptAutomation) string { return a.id }, func(a keptAutomation) {
		drop("automation", a.id, errors.New("duplicate automation id"))
	})
	automations = dropClaims(automations, func(a keptAutomation) []claim { return append(googleClaims(a.block), signedClaims(a.block)...) }, func(a keptAutomation, c claim) {
		drop("automation", a.id, errors.New(c.conflict()))
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

func partName(raw json.RawMessage, i int) string {
	var named struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(raw, &named) == nil && idPattern.MatchString(named.Name) {
		return named.Name
	}
	return fmt.Sprintf("#%d", i)
}

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

// claim is one key an entry occupies; entries may share a key only when every claim on it is shareable and of the same kind. A setting every entry on a host must agree on is a shareable claim whose kind is its value.
type claim struct {
	key, kind string
	shareable bool
	reason    string // why a part holding it is dropped, when not a shared key
}

func (c claim) conflict() string {
	if c.reason != "" {
		return c.reason
	}
	return "shares a host, route, test user or repository with another entry"
}

// entryClaims mirrors Parse's cross-entry checks (hosts, http2 per host, app hosts, test users, git repository routes, {requester} repositories, path prefix routes).
func entryClaims(e Entry) []claim {
	hostKey := fmt.Sprintf("%s:%d", e.Host, e.Port)
	claims := []claim{
		{key: "host " + hostKey, kind: e.Kind, shareable: e.Kind != "browser-session"},
		{key: "http2 " + hostKey, kind: strconv.FormatBool(e.HTTP2), shareable: true, reason: "disagrees on http2 with another entry on its host"},
	}
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

// googleClaims mirrors indexAutomations' check that one Google service account unique ID or email belongs to one block.
func googleClaims(a Automation) []claim {
	g := a.GoogleServiceAccount
	if g == nil {
		return nil
	}
	const reason = "names a google service account another automation names"
	return []claim{{key: "google id " + g.UniqueID, reason: reason}, {key: "google email " + g.Email, reason: reason}}
}

// signedClaims mirrors indexAutomations' check that one signed-token harness and subject belong to one block.
func signedClaims(a Automation) []claim {
	t := a.SignedToken
	if t == nil {
		return nil
	}
	return []claim{{key: "signed " + t.Harness + "\x00" + t.Subject, reason: "names a signed-token harness and subject another automation names"}}
}

// dropClaims drops every part holding a claim that conflicts with another claim on the same key, itself included.
func dropClaims[T any](parts []T, claimsOf func(T) []claim, dropped func(T, claim)) []T {
	type holder struct {
		part int
		c    claim
	}
	claims := make([][]claim, len(parts))
	byKey := map[string][]holder{}
	for i, p := range parts {
		claims[i] = claimsOf(p)
		for _, c := range claims[i] {
			byKey[c.key] = append(byKey[c.key], holder{i, c})
		}
	}
	conflicted := map[string]bool{}
	for key, holders := range byKey {
		if len(holders) < 2 {
			continue
		}
		shared := true
		for _, h := range holders {
			shared = shared && h.c.shareable && h.c.kind == holders[0].c.kind
		}
		conflicted[key] = !shared
	}
	kept := parts[:0:0]
next:
	for i, p := range parts {
		for _, c := range claims[i] {
			if conflicted[c.key] {
				dropped(p, c)
				continue next
			}
		}
		kept = append(kept, p)
	}
	return kept
}

// dropPullRequestCrossings drops each github-api entry whose pull request prefixes reach push prefixes a pool it reaches cannot push to, and each git entry it reaches into.
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
