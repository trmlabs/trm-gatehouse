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
	"strings"
	"time"
)

// Automation is one unattended agent the catalog grants access to by vendor id; its runs land on a shared pool and each request is decided for the Automation that started the run.
// Its access is only the entries listed here, whoever the run's token names.
type Automation struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Owner names the team accountable for the Automation, for audit rows and alerts; it decides no access.
	Owner string `json:"owner"`
	// RunnerGroup is refused at load: who sets off a run decides nothing. Declared so a catalog that sets it gets that reason.
	RunnerGroup string `json:"runnerGroup,omitempty"`
	// Entries are the catalog entries the Automation may use; each must also be granted to the pool, whose ceiling caps their tier.
	Entries []string `json:"entries"`
	// Write sets where the Automation gets the pool's write grant. No key keeps the pool's grant on every entry; a key, even empty, grants exactly the git and github-api entries it names.
	// On a listed entry it does not name, the Automation fetches and reads only. The pool's prefixes and operations stay the ceiling.
	Write WriteList `json:"write,omitzero"`
	// TokenSHA256 makes the block an agent that proves itself with a static token: lower-case hex SHA-256, two while a rotation overlaps.
	// Such a block is reached only by that token; removing it revokes the token at the next reload.
	TokenSHA256 []string `json:"tokenSHA256,omitempty"`
	// Expires, only with TokenSHA256, is an RFC 3339 time after which the token is refused.
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

	// SignedToken makes the block an agent proving itself with a token a signed-token harness accepts; it excludes tokenSHA256, gumloop and googleServiceAccount.
	SignedToken *SignedTokenIdentity `json:"signedToken,omitempty"`

	// GoogleServiceAccount makes the block an agent proving itself with a Google ID token; it excludes tokenSHA256, gumloop and signedToken.
	GoogleServiceAccount *GoogleIdentity `json:"googleServiceAccount,omitempty"`

	expires time.Time
	hashes  [][32]byte // TokenSHA256 decoded once, at validation
}

// GumloopIdentity names the Gumloop org and optional owner whose ID tokens are this Automation; without OwnerID it takes any owner no other block names.
type GumloopIdentity struct {
	OrgID   string `json:"orgID"`
	OwnerID string `json:"ownerID,omitempty"`
}

// SignedTokenIdentity names the signed-token harness and the subject claim value whose tokens are this Automation. Groups, optional, are the groups a token must carry at least one of.
type SignedTokenIdentity struct {
	Harness string   `json:"harness"`
	Subject string   `json:"subject"`
	Groups  []string `json:"groups,omitempty"`
}

// GoogleIdentity is a service account's email and the numeric unique ID a token's sub must equal.
type GoogleIdentity struct {
	Email    string `json:"email"`
	UniqueID string `json:"uniqueID"`
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

// MarshalJSON writes a set list as a list, [] when empty, so a round trip keeps the grant.
func (w WriteList) MarshalJSON() ([]byte, error) {
	return json.Marshal(append([]string{}, w.Names...))
}

func (w WriteList) IsZero() bool { return !w.Set }

// ErrAutomationReadOnly is a push or GitHub write by an Automation whose write list does not name the entry.
var ErrAutomationReadOnly = errors.New("automation has no write grant for this destination")

// automationContact is a plain lower-case email address, an owner as older catalogs named them.
var automationContact = regexp.MustCompile(`^[a-z0-9._%+-]+@[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

// validate checks one Automation on its own and sorts its entries so Uses is a binary search.
func (a *Automation) validate() error {
	if !idPattern.MatchString(a.ID) {
		return errors.New("id must be a short identifier")
	}
	if !idPattern.MatchString(a.Name) {
		return errors.New("name must be a short identifier")
	}
	// A group whose name has a space is named by its id, since audit rows hold no space.
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
		return errors.New("subagents is for an Automation reached by a Cursor run token, not one with tokenSHA256, gumloop, googleServiceAccount or signedToken")
	}
	if err := a.validateGumloop(); err != nil {
		return err
	}
	if err := a.validateSignedToken(); err != nil {
		return err
	}
	if err := a.validateGoogle(); err != nil {
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

func (a *Automation) validateSignedToken() error {
	s := a.SignedToken
	if s == nil {
		return nil
	}
	if a.HasToken() || a.Gumloop != nil || a.GoogleServiceAccount != nil {
		return errors.New("signedToken, gumloop and tokenSHA256 are three ways to prove one identity: a block has one")
	}
	if !idPattern.MatchString(s.Harness) || s.Subject == "" || len(s.Subject) > 256 || !plainClaimValue(s.Subject) {
		return errors.New("signedToken.harness must be a harness name and signedToken.subject a plain value")
	}
	seen := map[string]bool{}
	for _, g := range s.Groups {
		if g == "" || len(g) > 256 || !plainClaimValue(g) || seen[g] {
			return fmt.Errorf("signedToken group %q is invalid or repeated", g)
		}
		seen[g] = true
	}
	return nil
}

// googleEmail is a lower-case service account email: user-managed, the default Compute Engine one, or the App Engine one.
var googleEmail = regexp.MustCompile(`^([a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam|[0-9]{1,20}-compute@developer|[a-z][a-z0-9-]{4,28}[a-z0-9]@appspot)\.gserviceaccount\.com$`)

// googleUniqueID is a service account's numeric unique ID.
var googleUniqueID = regexp.MustCompile(`^[0-9]{10,25}$`)

func (a *Automation) validateGoogle() error {
	g := a.GoogleServiceAccount
	if g == nil {
		return nil
	}
	if a.HasToken() || a.Gumloop != nil || a.SignedToken != nil {
		return errors.New("googleServiceAccount, tokenSHA256 and gumloop are ways to prove one identity: a block has one")
	}
	if !googleEmail.MatchString(g.Email) || !googleUniqueID.MatchString(g.UniqueID) {
		return errors.New("googleServiceAccount.email must be a lower-case service account email and googleServiceAccount.uniqueID its numeric unique ID")
	}
	if !idPattern.MatchString(a.Owner) {
		return errors.New("owner of a block with googleServiceAccount must name a team, not an email address")
	}
	return nil
}

// plainClaimValue matches what the verifier accepts from a claim: no space, quote, backslash or control character.
func plainClaimValue(s string) bool {
	return !strings.ContainsAny(s, " \"\\") && !strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
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
	// A static token is a standing credential, so every token block needs an expiry no further than MaxTokenLifetime from now, checked at load.
	a.expires = time.Time{}
	if a.Expires == "" {
		return fmt.Errorf("expires is required with tokenSHA256, at most %s from now", maxTokenLifetimeText)
	}
	t, err := time.Parse(time.RFC3339, a.Expires)
	if err != nil {
		return errors.New("expires must be an RFC 3339 time")
	}
	// The zero time reads as "never expires", so it must fail closed.
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

var tokenClock = time.Now

func (a Automation) HasToken() bool { return len(a.TokenSHA256) > 0 }

// HasOwnIdentity is true for a static token, Gumloop, Google or signed-token block, so no Cursor run token may name its id.
func (a Automation) HasOwnIdentity() bool {
	return a.HasToken() || a.Gumloop != nil || a.GoogleServiceAccount != nil || a.SignedToken != nil
}

// TokenExpires is when the block's token stops being accepted, or the zero
// time for none.
func (a Automation) TokenExpires() time.Time { return a.expires }

// MatchToken hashes once and always makes two constant-time comparisons, so the work is the same for one hash, two, or an unknown id.
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

// checkWrite requires each write name to be one of the Automation's own git or github-api entries; it runs after validate.
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

func (a Automation) Uses(entry string) bool {
	_, ok := slices.BinarySearch(a.Entries, entry)
	return ok
}

// Writes reports whether the Automation gets the pool's write grant on the entry: everywhere with no write key, else only the named entries.
func (a Automation) Writes(entry string) bool {
	if !a.Write.Set {
		return true
	}
	_, ok := slices.BinarySearch(a.Write.Names, entry)
	return ok
}

func indexAutomations(list []Automation, entries map[string]string) (map[string]Automation, error) {
	index := make(map[string]Automation, len(list))
	claimed := map[string]string{}       // gumloop org and owner: automation id
	claimedGoogle := map[string]string{} // google service account unique ID and email: automation id
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
		if g := a.GoogleServiceAccount; g != nil {
			for _, key := range []string{"id\x00" + g.UniqueID, "email\x00" + g.Email} {
				if other, ok := claimedGoogle[key]; ok {
					return nil, fmt.Errorf("automations %q and %q name the same google service account", other, a.ID)
				}
				claimedGoogle[key] = a.ID
			}
		}
		index[a.ID] = *a
	}
	return index, nil
}

// indexSignedAgents maps each signed-token block's harness and subject to its id, and refuses a block that names no signed-token harness or shares a subject with another.
func indexSignedAgents(automations map[string]Automation, harnesses []Harness) (map[string]string, error) {
	signed := map[string]bool{}
	hasGroupsClaim := map[string]bool{}
	for _, h := range harnesses {
		if h.Identity.Kind == IdentitySignedToken {
			signed[h.Name] = true
			hasGroupsClaim[h.Name] = h.Identity.Token != nil && h.Identity.Token.GroupsClaim != ""
		}
	}
	out := map[string]string{}
	for id, a := range automations {
		s := a.SignedToken
		if s == nil {
			continue
		}
		if !signed[s.Harness] {
			return nil, fmt.Errorf("automation %q names signed-token harness %q, which is not declared", id, s.Harness)
		}
		if len(s.Groups) > 0 && !hasGroupsClaim[s.Harness] {
			return nil, fmt.Errorf("automation %q lists signedToken groups but harness %q has no groupsClaim", id, s.Harness)
		}
		key := s.Harness + "\x00" + s.Subject
		if other, ok := out[key]; ok {
			a, b := min(id, other), max(id, other)
			return nil, fmt.Errorf("automations %q and %q name the same signedToken harness and subject", a, b)
		}
		out[key] = id
	}
	return out, nil
}

func automationName(id string, i int) string {
	if idPattern.MatchString(id) {
		return id
	}
	return fmt.Sprintf("#%d", i)
}

func (c Catalog) Automation(id string) (Automation, bool) {
	a, ok := c.automations[id]
	return a, ok
}

func (c Catalog) Automations() int { return len(c.automations) }

// Automation returns the Automation with this id when the pool decides per Automation; any other pool lists none.
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

// ParseAutomationBlock validates one Automation block on its own, for tools that write a block.
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
	for _, name := range a.Write.Names {
		if !a.Uses(name) {
			return Automation{}, fmt.Errorf("write names entry %q, which entries does not list", name)
		}
	}
	return a, nil
}
