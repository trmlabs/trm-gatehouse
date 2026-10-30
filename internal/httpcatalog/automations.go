package httpcatalog

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"
)

// Automation is one unattended agent the catalog grants access to by its
// vendor id. It has no pool of its own: its runs land on a shared pool with
// identity "cursor-automation", and each request is decided for the
// Automation that started the run (the run token's automation_id). A new
// Automation is one block of catalog data, never a new pool, image or
// deployment.
//
// Its access is its own: the entries listed here, which the catalog's review
// approves. No person's groups or account decide it, whoever the run's token
// names, so a run with no person behind it is served the same entries.
type Automation struct {
	// ID is the vendor's automation id, as the run token carries it.
	ID string `json:"id"`
	// Name is a short label for audit rows and logs.
	Name string `json:"name"`
	// Owner names the team accountable for the Automation, for audit rows and
	// alerts: a directory group's name or object id. A catalog written before
	// owners named teams may still give a person's lower-case email, read as
	// the team's contact. It decides no access.
	Owner string `json:"owner"`
	// RunnerGroup is refused at load: who sets off a run decides nothing, so
	// a group of allowed runners would limit no one. The field is declared so
	// a catalog that sets it gets that reason, not an unknown-field error.
	RunnerGroup string `json:"runnerGroup,omitempty"`
	// Entries are the catalog entries the Automation may use. Each must also
	// be granted to the pool its runs land on, whose ceiling caps their tier.
	Entries []string `json:"entries"`
	// Write sets where the Automation gets the pool's write grant: the push
	// prefixes its git entry gives the pool, and the operations a github-api
	// repository's poolOperations give it. A block without the key keeps the
	// pool's grant on every entry, as a block did before the key existed. A
	// block with it, an empty list included, gets exactly the git and
	// github-api entries it names: on one it lists but does not name, the
	// Automation fetches and reads only, with no push and no GitHub operation
	// outside the reads (GitHubOperationWrites). The pool's own prefixes and
	// operations stay the ceiling; Write decides which of the pool's
	// Automations reach it, so one Automation's grant never widens another's.
	// A name must be one of Entries and refers to a git or github-api entry.
	Write WriteList `json:"write,omitzero"`
	// TokenSHA256 makes the block an agent that proves itself with a static
	// token (the static-token harness) instead of a vendor's run token: the
	// lower-case hex SHA-256 of the token, one value, or two while a rotation
	// overlaps. A block with it is reached only by that token, and a block
	// without it only by a run token, so the two sources never share an id.
	// Removing the block revokes the token at the next catalog reload.
	TokenSHA256 []string `json:"tokenSHA256,omitempty"`
	// Expires, optional and only with TokenSHA256, is an RFC 3339 time after
	// which the token is refused whatever its hash.
	Expires string `json:"expires,omitempty"`
	// Subagents caps how many subagent runs one run may register with this block's grant; zero registers none, and only run-token blocks may set it.
	Subagents int `json:"subagents,omitempty"`

	// Settings are plain configuration the Automation's runs get as
	// environment variables in their shells (see CheckSetting): never a
	// credential, and gating nothing. The broker serves them only to the
	// sidecar of a worker whose verified run token names this Automation.
	Settings map[string]string `json:"settings,omitempty"`

	// Gumloop makes the block an agent proving itself with a Gumloop-signed ID token; it excludes tokenSHA256.
	Gumloop *GumloopIdentity `json:"gumloop,omitempty"`

	expires time.Time
	hashes  [][32]byte // TokenSHA256 decoded once, at validation
}

// GumloopIdentity names the Gumloop org and optional owner whose ID tokens are this Automation; without OwnerID it takes any owner no other block names.
type GumloopIdentity struct {
	OrgID   string `json:"orgID"`
	OwnerID string `json:"ownerID,omitempty"`
}

// WriteList is an Automation's write list, and whether its block has the key.
// The zero value is a block without it. A key that is present is Set, an empty
// list or null included, so no spelling of "write nothing" reads as "no key".
type WriteList struct {
	Set   bool
	Names []string
}

func (w *WriteList) UnmarshalJSON(data []byte) error {
	w.Set = true
	return json.Unmarshal(data, &w.Names)
}

// MarshalJSON writes a set list as a list, [] when it names nothing, so a
// block that is written out and read back keeps what it granted.
func (w WriteList) MarshalJSON() ([]byte, error) {
	return json.Marshal(append([]string{}, w.Names...))
}

// IsZero reports a block without the key, which omitzero then leaves out.
func (w WriteList) IsZero() bool { return !w.Set }

// ErrAutomationReadOnly is a push or a GitHub write by an Automation whose
// block has a write list that does not name the entry (Automation.Write).
var ErrAutomationReadOnly = errors.New("automation has no write grant for this destination")

// automationContact is a plain lower-case email address: an owner as
// catalogs named it before owners named teams.
var automationContact = regexp.MustCompile(`^[a-z0-9._%+-]+@[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

// validate checks one Automation on its own and sorts its entries, so Uses is
// a binary search. Whether each entry exists is checked against the catalog.
func (a *Automation) validate() error {
	if !idPattern.MatchString(a.ID) {
		return errors.New("id must be a short identifier")
	}
	if !idPattern.MatchString(a.Name) {
		return errors.New("name must be a short identifier")
	}
	// A plain identifier covers a group's object id and a name without
	// spaces; an audit row holds no space, so a group whose name has one is
	// named by its id.
	if !idPattern.MatchString(a.Owner) && (len(a.Owner) > 254 || !automationContact.MatchString(a.Owner)) {
		return errors.New("owner must name a team: a group's name (letters, digits, '.', '_' or '-') or object id, or a lower-case contact email")
	}
	if a.RunnerGroup != "" {
		return errors.New("runnerGroup is not accepted: an Automation is served its own entries whoever runs it, so it would limit no one")
	}
	if len(a.Entries) == 0 {
		return errors.New("entries must name at least one catalog entry")
	}
	slices.Sort(a.Entries)
	for i, name := range a.Entries {
		if !idPattern.MatchString(name) || (i > 0 && a.Entries[i-1] == name) {
			return fmt.Errorf("entry %q is not a catalog entry name or is repeated", name)
		}
	}
	if err := a.validateToken(); err != nil {
		return err
	}
	if a.Subagents < 0 || a.Subagents > MaxSubagents {
		return fmt.Errorf("subagents must be from 0 to %d", MaxSubagents)
	}
	if a.Subagents > 0 && a.HasOwnIdentity() {
		return errors.New("subagents is for an Automation reached by a Cursor run token, not one with tokenSHA256 or gumloop")
	}
	if err := a.validateGumloop(); err != nil {
		return err
	}
	slices.Sort(a.Write.Names)
	for i, name := range a.Write.Names {
		if !idPattern.MatchString(name) || (i > 0 && a.Write.Names[i-1] == name) {
			return fmt.Errorf("write entry %q is not a catalog entry name or is repeated", name)
		}
	}
	return CheckSettings(a.Settings, SettingsMaxBytes())
}

func (a *Automation) validateGumloop() error {
	if a.Gumloop == nil {
		return nil
	}
	if a.HasToken() {
		return errors.New("gumloop and tokenSHA256 are two ways to prove one identity: a block has one")
	}
	if !idPattern.MatchString(a.Gumloop.OrgID) || (a.Gumloop.OwnerID != "" && !idPattern.MatchString(a.Gumloop.OwnerID)) {
		return errors.New("gumloop.orgID, and gumloop.ownerID when set, must be short identifiers")
	}
	return nil
}

var tokenHash = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (a *Automation) validateToken() error {
	if len(a.TokenSHA256) == 0 {
		if a.Expires != "" {
			return errors.New("expires is for a block with tokenSHA256")
		}
		return nil
	}
	if len(a.TokenSHA256) > 2 {
		return errors.New("tokenSHA256 holds one hash, or two while a token rotates")
	}
	for i, h := range a.TokenSHA256 {
		if !tokenHash.MatchString(h) || (i > 0 && h == a.TokenSHA256[0]) {
			return errors.New("tokenSHA256 values must be distinct, 64 lower-case hex characters")
		}
	}
	a.hashes = a.hashes[:0:0]
	for _, h := range a.TokenSHA256 {
		var raw [32]byte
		if _, err := hex.Decode(raw[:], []byte(h)); err != nil {
			return errors.New("tokenSHA256 values must be distinct, 64 lower-case hex characters")
		}
		a.hashes = append(a.hashes, raw)
	}
	// A static token is a standing credential held in another platform's
	// secret store, so the catalog bounds it: every token block carries an
	// expiry, and none reaches further than MaxTokenLifetime from now. This
	// is checked at load, so a hand-written or templated block cannot skip it.
	a.expires = time.Time{}
	if a.Expires == "" {
		return fmt.Errorf("expires is required with tokenSHA256, at most %s from now", maxTokenLifetimeText)
	}
	t, err := time.Parse(time.RFC3339, a.Expires)
	if err != nil {
		return errors.New("expires must be an RFC 3339 time")
	}
	// The zero time reads as "never expires" to the checks that use it, so a
	// templating slip that leaves it must fail closed.
	if t.IsZero() {
		return errors.New("expires must be a real time, not the zero time")
	}
	if t.After(tokenClock().Add(MaxTokenLifetime)) {
		return fmt.Errorf("expires is more than %s from now, the longest a token may live", maxTokenLifetimeText)
	}
	a.expires = t
	return nil
}

// MaxSubagents bounds the subagents setting so a mistyped value cannot read as unlimited.
const MaxSubagents = 10000

// MaxTokenLifetime is the longest a per-agent static token may live: a block
// with tokenSHA256 is refused when its expires is further out than this from
// the time the catalog loads. Renewal is a new token with --keep-hash, so the
// cap costs one rotation per period, and a leaked token is useful for a
// bounded time at most.
const MaxTokenLifetime = 90 * 24 * time.Hour

var maxTokenLifetimeText = fmt.Sprintf("%d days", int(MaxTokenLifetime/(24*time.Hour)))

// tokenClock is the time the cap is measured from; tests replace it.
var tokenClock = time.Now

// HasToken reports whether the block is an agent that proves itself with a
// static token.
func (a Automation) HasToken() bool { return len(a.TokenSHA256) > 0 }

// HasOwnIdentity is true for a static token or Gumloop ID token block, so no Cursor run token may name its id.
func (a Automation) HasOwnIdentity() bool { return a.HasToken() || a.Gumloop != nil }

// TokenExpires is when the block's token stops being accepted, or the zero
// time for none.
func (a Automation) TokenExpires() time.Time { return a.expires }

// MatchToken reports whether the token is one the block lists. It hashes the
// token once and always makes two constant-time comparisons, padding with a
// slot that cannot match, so the work is the same for one hash or two and for a
// block with none: an unknown id, which has no block, calls it on an empty
// Automation and does the same work as a known one.
func (a Automation) MatchToken(token string) bool {
	sum := sha256.Sum256([]byte(token))
	ok := 0
	for i := 0; i < 2; i++ {
		var want [32]byte
		valid := 0
		if i < len(a.hashes) {
			want, valid = a.hashes[i], 1
		}
		ok |= subtle.ConstantTimeCompare(sum[:], want[:]) & valid
	}
	return ok == 1
}

// checkWrite checks Write against the catalog: each name must be one of the
// Automation's own entries, and a git or github-api entry, the only kinds that
// have a write grant to give. kind returns an entry's kind, "" for none. It
// runs after validate, which sorts Entries for Uses.
func (a Automation) checkWrite(kind func(entry string) string) error {
	for _, name := range a.Write.Names {
		if !a.Uses(name) {
			return fmt.Errorf("write names entry %q, which entries does not list", name)
		}
		if k := kind(name); k != "git" && k != "github-api" {
			return fmt.Errorf("write names entry %q, which is not a git or github-api entry", name)
		}
	}
	return nil
}

// Uses reports whether the Automation may use the named entry.
func (a Automation) Uses(entry string) bool {
	_, ok := slices.BinarySearch(a.Entries, entry)
	return ok
}

// Writes reports whether the Automation gets the pool's write grant on the
// named git or github-api entry: on every entry when its block has no write
// key, and otherwise only on the entries the list names (Write).
func (a Automation) Writes(entry string) bool {
	if !a.Write.Set {
		return true
	}
	_, ok := slices.BinarySearch(a.Write.Names, entry)
	return ok
}

// indexAutomations validates the Automations against the catalog's entries (by
// name, each with its kind) and indexes them by id, so a lookup costs the same
// at any count.
func indexAutomations(list []Automation, entries map[string]string) (map[string]Automation, error) {
	index := make(map[string]Automation, len(list))
	claimed := map[string]string{} // gumloop org and owner: automation id
	for i := range list {
		a := &list[i]
		if err := a.validate(); err != nil {
			return nil, fmt.Errorf("automation %q: %w", automationName(a.ID, i), err)
		}
		if _, ok := index[a.ID]; ok {
			return nil, fmt.Errorf("duplicate automation %q", a.ID)
		}
		for _, name := range a.Entries {
			if _, ok := entries[name]; !ok {
				return nil, fmt.Errorf("automation %q names undefined entry %q", a.ID, name)
			}
		}
		if err := a.checkWrite(func(entry string) string { return entries[entry] }); err != nil {
			return nil, fmt.Errorf("automation %q: %w", a.ID, err)
		}
		if g := a.Gumloop; g != nil {
			key := g.OrgID + "\x00" + g.OwnerID
			if other, ok := claimed[key]; ok {
				return nil, fmt.Errorf("automations %q and %q name the same gumloop org and owner", other, a.ID)
			}
			claimed[key] = a.ID
		}
		index[a.ID] = *a
	}
	return index, nil
}

func automationName(id string, i int) string {
	if idPattern.MatchString(id) {
		return id
	}
	return fmt.Sprintf("#%d", i)
}

// Automation returns the listed Automation with this id.
func (c Catalog) Automation(id string) (Automation, bool) {
	a, ok := c.automations[id]
	return a, ok
}

// Automations returns how many Automations the catalog lists.
func (c Catalog) Automations() int { return len(c.automations) }

// Automation returns the Automation with this id when the pool decides per
// Automation; any other pool lists none.
func (p Pool) Automation(id string) (Automation, bool) {
	if p.Identity != IdentityCursorAutomation || id == "" {
		return Automation{}, false
	}
	a, ok := p.automations[id]
	return a, ok
}

// GrantsSubagents reports whether any Automation the pool lists sets subagents.
func (p Pool) GrantsSubagents() bool {
	if p.Identity != IdentityCursorAutomation {
		return false
	}
	for _, a := range p.automations {
		if a.Subagents > 0 {
			return true
		}
	}
	return false
}

// IdentityCursorAutomation is the pool identity whose runs are decided per
// Automation, on its own entries.
const IdentityCursorAutomation = "cursor-automation"

// ParseAutomationBlock reads one Automation block from a catalog's YAML or
// JSON list item and validates it on its own, as the catalog does before it
// checks the block against the entries. It is for tools that write a block,
// so they print only one the broker would accept.
func ParseAutomationBlock(data []byte) (Automation, error) {
	document, err := FromYAML(append([]byte("automations:\n"), data...))
	if err != nil {
		return Automation{}, err
	}
	var file struct {
		Automations []Automation `json:"automations"`
	}
	if err := strictDecode(document, &file); err != nil {
		return Automation{}, err
	}
	if len(file.Automations) != 1 {
		return Automation{}, errors.New("expected one automation block")
	}
	a := file.Automations[0]
	if err := a.validate(); err != nil {
		return Automation{}, err
	}
	// Which entries are git or github-api ones needs the catalog, and the
	// validator checks it; that a write name is one of the block's own does not.
	for _, name := range a.Write.Names {
		if !a.Uses(name) {
			return Automation{}, fmt.Errorf("write names entry %q, which entries does not list", name)
		}
	}
	return a, nil
}
