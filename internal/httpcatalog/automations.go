package httpcatalog

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
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
	// Write names the git and github-api entries, among Entries, where the
	// Automation gets the pool's write grant: the push prefixes its git entry
	// gives the pool, and the operations a github-api repository's
	// poolOperations give it. On a git or github-api entry it lists but does
	// not name here, the Automation fetches and reads only: no push, and no
	// GitHub operation outside the reads (GitHubOperationWrites). The pool's
	// own prefixes and operations stay the ceiling; Write decides which of the
	// pool's Automations reach it, so one Automation's grant never widens
	// another's. Optional, and refused for any other kind of entry.
	Write []string `json:"write,omitempty"`
}

// ErrAutomationReadOnly is a push or a GitHub write by an Automation whose
// block does not list the entry in write (Automation.Write).
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
	slices.Sort(a.Write)
	for i, name := range a.Write {
		if !idPattern.MatchString(name) || (i > 0 && a.Write[i-1] == name) {
			return fmt.Errorf("write entry %q is not a catalog entry name or is repeated", name)
		}
	}
	return nil
}

// checkWrite checks Write against the catalog: each name must be one of the
// Automation's own entries, and a git or github-api entry, the only kinds that
// have a write grant to give. kind returns an entry's kind, "" for none. It
// runs after validate, which sorts Entries for Uses.
func (a Automation) checkWrite(kind func(entry string) string) error {
	for _, name := range a.Write {
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
// named git or github-api entry (Write).
func (a Automation) Writes(entry string) bool {
	_, ok := slices.BinarySearch(a.Write, entry)
	return ok
}

// indexAutomations validates the Automations against the catalog's entries (by
// name, each with its kind) and indexes them by id, so a lookup costs the same
// at any count.
func indexAutomations(list []Automation, entries map[string]string) (map[string]Automation, error) {
	index := make(map[string]Automation, len(list))
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

// IdentityCursorAutomation is the pool identity whose runs are decided per
// Automation, on its own entries.
const IdentityCursorAutomation = "cursor-automation"
