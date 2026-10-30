package httpcatalog

import (
	"errors"
	"fmt"
	"strings"
)

// BasicPairBinding ties a non-secret Basic user to one operator-owned key.
type BasicPairBinding struct {
	Name string `json:"name"`
	User string `json:"user"`
	Key  KeyRef `json:"key"`
}

type BasicPairBindings []BasicPairBinding

// UnmarshalJSON refuses null and empty lists rather than falling back to Key.
func (p *BasicPairBindings) UnmarshalJSON(data []byte) error {
	var pairs []BasicPairBinding
	if err := strictDecode(data, &pairs); err != nil {
		return err
	}
	if len(pairs) == 0 {
		return errors.New("basicPairs must contain at least one binding")
	}
	*p = pairs
	return nil
}

func (e *Entry) normalizeBasicPairs() error {
	if e.Kind != "" || !e.BasicPair || e.Key != (KeyRef{}) || e.ClientCredentials != nil || len(e.BasicPairs) == 0 {
		return errors.New("basicPairs needs a Basic pair header entry and replaces key")
	}
	names, users := map[string]bool{}, map[string]bool{}
	refs := map[KeyRef]bool{}
	for i, pair := range e.BasicPairs {
		if !idPattern.MatchString(pair.Name) || names[pair.Name] {
			return fmt.Errorf("basicPairs[%d] needs a unique short binding name", i)
		}
		// A usable stored pair needs room for ':' and a non-empty password.
		if pair.User == "" || len(pair.User) > maxKeyBytes-2 || !printableASCII(pair.User) || strings.ContainsAny(pair.User, ": ") ||
			strings.Contains(pair.User, "__vault_") || users[pair.User] {
			return fmt.Errorf("basicPairs[%d] needs a unique non-placeholder printable Basic user without spaces or colons", i)
		}
		if !pair.Key.valid() {
			prefix, _ := keyPath()
			return fmt.Errorf("basicPairs[%d] key needs a KV mount, a path under %s/ and a field", i, prefix)
		}
		// One stored pair can satisfy only one configured public user.
		if refs[pair.Key] {
			return fmt.Errorf("basicPairs[%d] key reference is duplicated", i)
		}
		names[pair.Name], users[pair.User], refs[pair.Key] = true, true, true
	}
	return nil
}

func (r KeyRef) valid() bool {
	_, path := keyPath()
	return ValidMount(r.Mount) && len(r.Path) <= 127 && path.MatchString(r.Path) && r.Field != ""
}
