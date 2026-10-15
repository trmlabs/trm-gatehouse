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
type Automation struct {
	// ID is the vendor's automation id, as the run token carries it.
	ID string `json:"id"`
	// Name is a short label for audit rows and logs.
	Name string `json:"name"`
	// Owner is the email of the person accountable for the Automation. Above
	// T0 it is decided on the owner's account: it never reaches what the
	// owner could not, and it stops when the owner's account does.
	Owner string `json:"owner"`
	// Entries are the catalog entries the Automation may use. Each must also
	// be granted to the pool its runs land on.
	Entries []string `json:"entries"`
}

// automationOwner is a plain lower-case email address.
var automationOwner = regexp.MustCompile(`^[a-z0-9._%+-]+@[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

// validate checks one Automation on its own and sorts its entries, so Uses is
// a binary search. Whether each entry exists is checked against the catalog.
func (a *Automation) validate() error {
	if !idPattern.MatchString(a.ID) {
		return errors.New("id must be a short identifier")
	}
	if !idPattern.MatchString(a.Name) {
		return errors.New("name must be a short identifier")
	}
	if len(a.Owner) > 254 || !automationOwner.MatchString(a.Owner) {
		return errors.New("owner must be a lower-case email address")
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
	return nil
}

// Uses reports whether the Automation may use the named entry.
func (a Automation) Uses(entry string) bool {
	_, ok := slices.BinarySearch(a.Entries, entry)
	return ok
}

// indexAutomations validates the Automations against the catalog's entry
// names and indexes them by id, so a lookup costs the same at any count.
func indexAutomations(list []Automation, entries map[string]bool) (map[string]Automation, error) {
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
			if !entries[name] {
				return nil, fmt.Errorf("automation %q names undefined entry %q", a.ID, name)
			}
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
// Automation.
const IdentityCursorAutomation = "cursor-automation"
