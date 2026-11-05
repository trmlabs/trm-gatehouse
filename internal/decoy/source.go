package decoy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

// Source is the decoy set in force. A failed load keeps the last good set, and a broker that never loaded one recognizes no decoy: decoys never hold up traffic.
type Source struct {
	current atomic.Pointer[Set]
	version atomic.Int64
}

// NewSource starts from a set at version 0.
func NewSource(set *Set) *Source {
	s := &Source{}
	s.current.Store(set)
	return s
}

// Current is the set in force; nil for a nil Source or before the first load.
func (s *Source) Current() *Set {
	if s == nil {
		return nil
	}
	return s.current.Load()
}

// Version is the version of the set in force, or 0 before the first load.
func (s *Source) Version() int { return int(s.version.Load()) }

// Loader returns every decoy by label, the fields it skipped (by label, never value), and their version;
// given the version in force it may return no values to say nothing changed.
type Loader func(ctx context.Context, known int) (values map[string]string, skipped []Rejected, version int, err error)

// Load reads the newest decoys and puts them in force; force rereads even at the same version. It returns the decoys left out.
func (s *Source) Load(ctx context.Context, load Loader, force bool) ([]Rejected, error) {
	known := s.Version()
	if force || s.Current() == nil {
		known = -1
	}
	values, skipped, version, err := load(ctx, known)
	if err != nil {
		return nil, err
	}
	if values == nil && version == known {
		return nil, nil
	}
	set, rejected := NewSet(values)
	s.current.Store(set)
	s.version.Store(int64(version))
	return append(skipped, rejected...), nil
}

// Watch loads every interval, and in full every refresh, until ctx ends; report hears each load's left-out decoys or error.
func (s *Source) Watch(ctx context.Context, interval, refresh time.Duration, load Loader, report func([]Rejected, error)) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	full := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		force := time.Since(full) >= refresh
		loadCtx, cancel := context.WithTimeout(ctx, interval/2)
		rejected, err := s.Load(loadCtx, load, force)
		cancel()
		if force && err == nil {
			full = time.Now()
		}
		if err != nil || len(rejected) > 0 {
			report(rejected, err)
		}
	}
}

// Logical is the Vault read a VaultLoader needs.
type Logical interface {
	ReadWithDataWithContext(ctx context.Context, path string, data map[string][]string) (*vaultapi.Secret, error)
}

// readConcurrency is how many owner secrets a load reads at once.
const readConcurrency = 64

var (
	kvPath    = regexp.MustCompile(`^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$`)
	ownerName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	fieldName = regexp.MustCompile(`^[a-z0-9][a-z0-9_]{0,63}$`)
)

// VaultLoader reads decoys from a KV v2 mount under prefix. The head's "names" field lists owners (a JSON array or a string holding one); its KV version is the set's version.
// Each pools/<name> string field is a decoy labelled "<name>/<field>"; a bad field name or non-string value is skipped and reported by label. A deleted owner secret has no decoys; any other read failure fails the load.
func VaultLoader(vault Logical, mount, prefix string) Loader {
	return func(ctx context.Context, known int) (map[string]string, []Rejected, int, error) {
		if vault == nil || !validPath(mount) || !validPath(prefix) {
			return nil, nil, 0, errors.New("decoy location is not configured")
		}
		base := mount + "/data/" + prefix + "/"
		head, version, err := readKV(ctx, vault, base+"head")
		if err != nil {
			return nil, nil, 0, fmt.Errorf("decoy head: %w", err)
		}
		if version == known {
			return nil, nil, version, nil
		}
		names, err := headNames(head["names"])
		if err != nil {
			return nil, nil, version, err
		}
		values, skipped, err := readOwners(ctx, vault, base+"pools/", names)
		if err != nil {
			return nil, nil, version, err
		}
		return values, skipped, version, nil
	}
}

// validPath is a KV path of plain segments, none "." or "..".
func validPath(p string) bool {
	if !kvPath.MatchString(p) {
		return false
	}
	for _, segment := range strings.Split(p, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func headNames(field interface{}) ([]string, error) {
	var raw []interface{}
	switch v := field.(type) {
	case []interface{}:
		raw = v
	case string:
		if json.Unmarshal([]byte(v), &raw) != nil {
			return nil, errors.New("decoy head names is not a JSON array")
		}
	default:
		return nil, errors.New("decoy head names is not a list")
	}
	seen := make(map[string]bool, len(raw))
	names := make([]string, 0, len(raw))
	for _, k := range raw {
		name, _ := k.(string)
		if !ownerName.MatchString(name) || seen[name] {
			return nil, fmt.Errorf("decoy head names %q, which is not a unique pool name", name)
		}
		seen[name] = true
		names = append(names, name)
	}
	return names, nil
}

// readOwners reads every owner's decoys concurrently; a field that is not a string or plain name is skipped and returned by label, sorted, never by value.
func readOwners(ctx context.Context, vault Logical, base string, names []string) (map[string]string, []Rejected, error) {
	values := map[string]string{}
	var skipped []Rejected
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var mu sync.Mutex
	var wg sync.WaitGroup
	var once sync.Once
	var failure error
	next := make(chan string)
	for range min(readConcurrency, max(len(names), 1)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for name := range next {
				data, _, err := readKV(ctx, vault, base+name)
				if errors.Is(err, errDeleted) {
					continue
				}
				if err != nil {
					once.Do(func() { failure = fmt.Errorf("decoys for %q: %w", name, err); cancel() })
					continue
				}
				mu.Lock()
				for field, v := range data {
					value, ok := v.(string)
					switch {
					case !fieldName.MatchString(field):
						skipped = append(skipped, Rejected{Label: name + "/" + field, Reason: "field name outside a-z, 0-9 and _"})
					case !ok:
						skipped = append(skipped, Rejected{Label: name + "/" + field, Reason: "value is not a string"})
					default:
						values[name+"/"+field] = value
					}
				}
				mu.Unlock()
			}
		}()
	}
	for _, name := range names {
		select {
		case next <- name:
		case <-ctx.Done():
		}
	}
	close(next)
	wg.Wait()
	if failure != nil {
		return nil, nil, failure
	}
	sort.Slice(skipped, func(i, j int) bool { return skipped[i].Label < skipped[j].Label })
	return values, skipped, nil
}

var errDeleted = errors.New("decoy secret deleted")

// readKV reads a KV v2 secret's data and version; errors never carry its contents.
func readKV(ctx context.Context, vault Logical, path string) (map[string]interface{}, int, error) {
	resp, err := vault.ReadWithDataWithContext(ctx, path, nil)
	if err != nil || resp == nil || resp.Data == nil {
		return nil, 0, errors.New("read failed")
	}
	data, _ := resp.Data["data"].(map[string]interface{})
	metadata, _ := resp.Data["metadata"].(map[string]interface{})
	version := 0
	switch n := metadata["version"].(type) {
	case json.Number:
		version, _ = strconv.Atoi(n.String())
	case float64:
		version = int(n)
	}
	if deleted, _ := metadata["deletion_time"].(string); data == nil && (deleted != "" || metadata["destroyed"] == true) {
		return nil, 0, errDeleted
	}
	if data == nil || version < 1 {
		return nil, 0, errors.New("response incomplete")
	}
	return data, version, nil
}
