package httpcatalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"
)

// Source is the live catalog. The broker reads Current per request; Watch
// swaps in each new valid version. A version that fails validation never
// replaces the last good catalog.
type Source struct {
	current atomic.Pointer[Catalog]
	version atomic.Int64
	loaded  atomic.Bool
	dropped atomic.Pointer[[]Dropped]

	mu       sync.Mutex
	onChange []func(Catalog)
	// accepted, when set, runs after each version is swapped in, with the
	// document it was loaded from and the parts left out of it.
	accepted func(version int, data []byte, dropped []Dropped)
}

// OnChange runs f after each new catalog version is swapped in, so state
// derived from an older version (cached tokens) can follow it.
func (s *Source) OnChange(f func(Catalog)) {
	s.mu.Lock()
	s.onChange = append(s.onChange, f)
	s.mu.Unlock()
}

// NewSource starts from a validated catalog at a version (0 for a file).
func NewSource(c Catalog, version int) *Source {
	s := &Source{}
	s.current.Store(&c)
	s.version.Store(int64(version))
	s.loaded.Store(true)
	return s
}

func (s *Source) Current() Catalog { return *s.current.Load() }

func (s *Source) Version() int { return int(s.version.Load()) }

// Loaded reports that a catalog is in force. A Source started with no
// catalog anywhere is empty, and refuses everything, until Watch loads one.
func (s *Source) Loaded() bool { return s.loaded.Load() }

// Dropped lists the parts the version in force left out (see ParseTolerant).
func (s *Source) Dropped() []Dropped {
	if d := s.dropped.Load(); d != nil {
		return *d
	}
	return nil
}

func (s *Source) swap(c Catalog, version int, dropped []Dropped) {
	s.current.Store(&c)
	s.version.Store(int64(version))
	s.dropped.Store(&dropped)
	s.loaded.Store(true)
}

// Loader returns the newest catalog document and its version.
type Loader func(context.Context) (data []byte, version int, err error)

// Open reads and validates a catalog once: no catalog, no Source. Parts that
// fail validation are left out (see ParseTolerant and Dropped).
func Open(ctx context.Context, load Loader) (*Source, error) {
	data, version, err := load(ctx)
	if err != nil {
		return nil, err
	}
	c, dropped, err := ParseTolerant(data)
	if err != nil {
		return nil, err
	}
	s := &Source{}
	s.swap(c, version, dropped)
	return s, nil
}

// Start is Open for a broker that must keep running through a catalog
// outage. It loads from load; if that fails, it starts from stored, the last
// catalog this broker accepted; with neither, it starts empty and not Loaded,
// refusing everything until Watch loads a version. The Source is never nil.
// The error reports why load did not answer, for the caller's log.
// accepted, if set, runs for the version Start puts in force and for each
// version Watch swaps in later, so the caller can keep the newest copy.
func Start(ctx context.Context, load, stored Loader, accepted func(version int, data []byte, dropped []Dropped)) (*Source, error) {
	s := &Source{accepted: accepted}
	empty := Catalog{}
	s.current.Store(&empty)
	data, version, loadErr := load(ctx)
	if loadErr == nil {
		var c Catalog
		var dropped []Dropped
		if c, dropped, loadErr = ParseTolerant(data); loadErr == nil {
			s.swap(c, version, dropped)
			if accepted != nil {
				accepted(version, data, dropped)
			}
			return s, nil
		}
	}
	if stored != nil {
		if data, version, err := stored(ctx); err == nil {
			// Not re-saved, and Watch still loads this version from the
			// primary: the stored copy only bridges an outage.
			if c, dropped, err := ParseTolerant(data); err == nil {
				s.swap(c, version, dropped)
				s.version.Store(0)
			}
		}
	}
	return s, loadErr
}

// Watch polls every interval until ctx ends. A new version is parsed and
// swapped in atomically, with any invalid or conflicting parts left out (see
// ParseTolerant), so access removals always take effect. A version that
// cannot be decoded at all is reported to rejected (with no catalog content)
// and the previous catalog stays in force.
func (s *Source) Watch(ctx context.Context, interval time.Duration, load Loader, rejected func(version int, err error)) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	refused := -1
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		loadCtx, cancel := context.WithTimeout(ctx, interval/2)
		data, version, err := load(loadCtx)
		cancel()
		if err != nil {
			rejected(version, fmt.Errorf("catalog unavailable: %w", err))
			continue
		}
		if version == s.Version() || version == refused {
			continue
		}
		c, dropped, err := ParseTolerant(data)
		if err != nil {
			refused = version
			rejected(version, err)
			continue
		}
		s.swap(c, version, dropped)
		if s.accepted != nil {
			s.accepted(version, data, dropped)
		}
		s.mu.Lock()
		hooks := append([](func(Catalog)){}, s.onChange...)
		s.mu.Unlock()
		for _, f := range hooks {
			f(c)
		}
	}
}

// VaultLoader reads the catalog document from field of a KV version 2
// secret, where Terraform writes it; the KV version is the catalog version.
func VaultLoader(vault Logical, mount, path, field string) Loader {
	return func(ctx context.Context) ([]byte, int, error) {
		if vault == nil || !kvPattern.MatchString(mount) || !kvPattern.MatchString(path) || field == "" {
			return nil, 0, errors.New("catalog location is not configured")
		}
		resp, err := vault.ReadWithDataWithContext(ctx, mount+"/data/"+path, nil)
		if err != nil || resp == nil || resp.Data == nil {
			return nil, 0, errors.New("catalog read failed")
		}
		data, _ := resp.Data["data"].(map[string]interface{})
		metadata, _ := resp.Data["metadata"].(map[string]interface{})
		document, _ := data[field].(string)
		version := 0
		switch n := metadata["version"].(type) {
		case json.Number:
			version, _ = strconv.Atoi(n.String())
		case float64:
			version = int(n)
		}
		if document == "" || version < 1 {
			return nil, 0, errors.New("catalog response incomplete")
		}
		return []byte(document), version, nil
	}
}

// FromYAML converts a YAML catalog (the reviewed source form) to the JSON the
// broker reads, so both pass through the same Parse.
func FromYAML(data []byte) ([]byte, error) {
	var doc any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("invalid catalog YAML: %w", err)
	}
	return json.Marshal(doc)
}
