package httpcatalog

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"

	vaultapi "github.com/hashicorp/vault/api"
)

// ListLogical reads and lists KV version 2 secrets.
type ListLogical interface {
	Logical
	ListWithContext(ctx context.Context, path string) (*vaultapi.Secret, error)
}

// prefixReadConcurrency is how many entry secrets a reload reads at once.
// It sets reload speed, not how many entries the catalog may hold.
const prefixReadConcurrency = 64

// VaultPrefixLoader reads a catalog stored one secret per entry, so it is not
// bounded by Vault's size limit for one secret. Under mount/prefix:
//
//   - head: field "catalog" is the catalog document without "entries"; field
//     "entries_sha256" is the SHA-256, in lowercase hex, of each entry name in
//     byte order followed by a newline, its stored JSON and a newline.
//   - entries/<name>: field "entry" is that entry's JSON.
//   - head, optionally: field "entries_names" lists the entry names, as a
//     JSON array or a string holding one. When it is there, only those
//     entries are read and digested, so a stray document under entries/ (one
//     left by a cancelled apply) is ignored instead of failing every reload.
//   - head, optionally: field "automations_buckets" maps each bucket name to
//     the SHA-256, in lowercase hex, of that bucket's stored field, as a JSON
//     object or a string holding one. Automations are then stored in buckets
//     and the head's document carries no "automations"; without the field,
//     the document may carry its own (bounded by Vault's size limit).
//   - automations/<bucket>: field "automations" is a JSON array of
//     Automations. Which bucket holds an Automation is the writer's choice
//     (by a hash of its id, so one change rewrites one bucket); an id in two
//     buckets is refused at load like any repeated id.
//
// Buckets are read incrementally: a reload reads only the buckets whose
// digest in the head differs from the last good catalog's, so changing one
// Automation costs the head and one bucket, however many there are.
//
// Terraform writes the entries, then the head. The head's KV version is the
// catalog version, so a poll costs one read until the head changes. A reload
// whose entries do not match the head's digest, such as one read while an
// apply is under way, returns an error: the last good catalog stays in force
// and the next poll tries again.
func VaultPrefixLoader(vault ListLogical, mount, prefix string) Loader {
	var mu sync.Mutex
	var lastVersion int
	var last []byte
	var lastEntries map[string]string // name to the entry JSON in the last good catalog
	var lastBuckets map[string]automationBucket
	return func(ctx context.Context) ([]byte, int, error) {
		if vault == nil || !kvPattern.MatchString(mount) || !kvPattern.MatchString(prefix) {
			return nil, 0, errors.New("catalog location is not configured")
		}
		head, version, err := readKV(ctx, vault, mount+"/data/"+prefix+"/head")
		if err != nil {
			return nil, 0, err
		}
		mu.Lock()
		defer mu.Unlock()
		if version == lastVersion {
			return last, version, nil
		}
		document, _ := head["catalog"].(string)
		want, _ := head["entries_sha256"].(string)
		if document == "" || len(want) != 64 {
			return nil, 0, errors.New("catalog head incomplete")
		}
		names, entries, err := readFolder(ctx, vault, mount, prefix, "entries", "entry", head["entries_names"])
		if err != nil {
			return nil, version, err
		}
		if folderDigest(names, entries) != want {
			return nil, version, fmt.Errorf("catalog entries do not match the head; retrying at the next poll (%s)", entryChanges(lastEntries, names, entries))
		}
		var buckets map[string]automationBucket
		if listed, ok := head["automations_buckets"]; ok {
			// Bucketed, so neither the head nor any one secret bounds how
			// many Automations there are.
			if buckets, err = readBuckets(ctx, vault, mount+"/data/"+prefix+"/automations/", listed, lastBuckets); err != nil {
				return nil, version, err
			}
		}
		out, err := assemble(document, names, entries, buckets)
		if err != nil {
			return nil, version, err
		}
		lastBuckets = buckets
		last, lastVersion = out, version
		lastEntries = make(map[string]string, len(names))
		for i, name := range names {
			lastEntries[name] = entries[i]
		}
		return out, version, nil
	}
}

// readFolder reads every secret under prefix/folder, in name order, and
// returns the names and each one's field. When the head lists the names
// (listed), only those are read; otherwise the folder is listed. A deleted
// secret is left out: it is no longer in the catalog.
func readFolder(ctx context.Context, vault ListLogical, mount, prefix, folder, field string, listed interface{}) ([]string, []string, error) {
	names, named, err := headNames(listed)
	if err != nil {
		return nil, nil, err
	}
	if !named {
		listing, err := vault.ListWithContext(ctx, mount+"/metadata/"+prefix+"/"+folder)
		if err != nil {
			return nil, nil, fmt.Errorf("catalog %s listing failed", folder)
		}
		// Vault answers LIST on an empty folder with 404, which the client
		// returns as no secret: none stored. The head's digest still decides,
		// so this loads only a head that itself says there are none.
		var keys []interface{}
		if listing != nil && listing.Data != nil {
			keys, _ = listing.Data["keys"].([]interface{})
		}
		for _, k := range keys {
			name, _ := k.(string)
			if !idPattern.MatchString(name) {
				return nil, nil, fmt.Errorf("catalog %s key %q is not a catalog name", folder, name)
			}
			names = append(names, name)
		}
	}
	sort.Strings(names)
	stored, err := readEntries(ctx, vault, mount+"/data/"+prefix+"/"+folder+"/", field, names)
	if err != nil {
		return nil, nil, err
	}
	kept, docs := names[:0:0], make([]string, 0, len(stored))
	for i, doc := range stored {
		if doc != "" {
			kept, docs = append(kept, names[i]), append(docs, doc)
		}
	}
	return kept, docs, nil
}

// folderDigest is the head's digest of a folder: the SHA-256, in lowercase
// hex, of each name in byte order followed by a newline, its stored JSON and
// a newline.
func folderDigest(names, docs []string) string {
	digest := sha256.New()
	for i, name := range names {
		digest.Write([]byte(name + "\n" + docs[i] + "\n"))
	}
	return hex.EncodeToString(digest.Sum(nil))
}

// automationBucket is one stored bucket of Automations: its digest and its
// items, kept so an unchanged bucket is never read again.
type automationBucket struct {
	digest string
	items  []json.RawMessage
}

// readBuckets reads the buckets the head lists whose digest differs from the
// last good catalog's, concurrently, and reuses the rest. A bucket whose
// stored field does not hash to the head's digest (an apply under way) fails
// the reload; the last good catalog stays in force.
func readBuckets(ctx context.Context, vault Logical, base string, listed interface{}, last map[string]automationBucket) (map[string]automationBucket, error) {
	digests, err := bucketDigests(listed)
	if err != nil {
		return nil, err
	}
	out := make(map[string]automationBucket, len(digests))
	var changed []string
	for name, digest := range digests {
		if b, ok := last[name]; ok && b.digest == digest {
			out[name] = b
			continue
		}
		changed = append(changed, name)
	}
	sort.Strings(changed)
	stored, err := readEntries(ctx, vault, base, "automations", changed)
	if err != nil {
		return nil, err
	}
	for i, name := range changed {
		sum := sha256.Sum256([]byte(stored[i]))
		if stored[i] == "" || hex.EncodeToString(sum[:]) != digests[name] {
			return nil, fmt.Errorf("catalog automations bucket %q does not match the head; retrying at the next poll (%d of %d buckets changed)", name, len(changed), len(digests))
		}
		var items []json.RawMessage
		if err := json.Unmarshal([]byte(stored[i]), &items); err != nil {
			return nil, fmt.Errorf("catalog automations bucket %q is not a JSON array", name)
		}
		out[name] = automationBucket{digest: digests[name], items: items}
	}
	return out, nil
}

// bucketDigests reads the head's bucket map: bucket names to SHA-256 hex.
func bucketDigests(field interface{}) (map[string]string, error) {
	raw, ok := field.(map[string]interface{})
	if text, isText := field.(string); isText {
		ok = json.Unmarshal([]byte(text), &raw) == nil
	}
	if !ok {
		return nil, errors.New("catalog head automations_buckets is not a JSON object")
	}
	out := make(map[string]string, len(raw))
	for name, v := range raw {
		digest, _ := v.(string)
		if !idPattern.MatchString(name) || len(digest) != 64 || strings.Trim(digest, "0123456789abcdef") != "" {
			return nil, fmt.Errorf("catalog head bucket %q has no lowercase SHA-256", name)
		}
		out[name] = digest
	}
	return out, nil
}

// headNames reads the head's optional entry name list. listed is false when
// the head has none, and the loader lists entries/ instead.
func headNames(field interface{}) (names []string, listed bool, err error) {
	if field == nil {
		return nil, false, nil
	}
	var raw []interface{}
	switch v := field.(type) {
	case []interface{}:
		raw = v
	case string:
		if json.Unmarshal([]byte(v), &raw) != nil {
			return nil, true, errors.New("catalog head entries_names is not a JSON array")
		}
	default:
		return nil, true, errors.New("catalog head entries_names is not a list")
	}
	seen := make(map[string]bool, len(raw))
	names = make([]string, 0, len(raw))
	for _, k := range raw {
		name, _ := k.(string)
		if !idPattern.MatchString(name) || seen[name] {
			return nil, true, fmt.Errorf("catalog head names %q, which is not a unique entry name", name)
		}
		seen[name] = true
		names = append(names, name)
	}
	return names, true, nil
}

// errDeleted is a KV secret whose current version is deleted or destroyed.
// Vault still lists its key until its metadata is removed.
var errDeleted = errors.New("catalog secret deleted")

// entryChanges names what differs from the last good catalog, so an operator
// can find a stray or half-written document from the log: every count in
// full and up to shownNames names of each kind. Names are catalog
// identifiers, so they are safe to log; entry contents never are.
func entryChanges(last map[string]string, names, entries []string) string {
	const shownNames = 20
	var added, changed, removed []string
	seen := make(map[string]bool, len(names))
	for i, name := range names {
		seen[name] = true
		switch old, ok := last[name]; {
		case !ok:
			added = append(added, name)
		case old != entries[i]:
			changed = append(changed, name)
		}
	}
	for name := range last {
		if !seen[name] {
			removed = append(removed, name)
		}
	}
	sort.Strings(removed)
	show := func(kind string, list []string) string {
		if len(list) > shownNames {
			return fmt.Sprintf("%s %d: %s, ...", kind, len(list), strings.Join(list[:shownNames], ","))
		}
		return fmt.Sprintf("%s %d: %s", kind, len(list), strings.Join(list, ","))
	}
	return fmt.Sprintf("listed %d; since the last good catalog %s; %s; %s", len(names), show("added", added), show("changed", changed), show("removed", removed))
}

func readKV(ctx context.Context, vault Logical, path string) (map[string]interface{}, int, error) {
	resp, err := vault.ReadWithDataWithContext(ctx, path, nil)
	if err != nil || resp == nil || resp.Data == nil {
		return nil, 0, errors.New("catalog read failed")
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
		return nil, 0, errors.New("catalog response incomplete")
	}
	return data, version, nil
}

// readEntries reads every entry's stored JSON, concurrently, in names order.
// A deleted entry reads as "": it is no longer in the catalog.
func readEntries(ctx context.Context, vault Logical, base, field string, names []string) ([]string, error) {
	out := make([]string, len(names))
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	var once sync.Once
	var failure error
	next := make(chan int)
	for range min(prefixReadConcurrency, max(len(names), 1)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				data, _, err := readKV(ctx, vault, base+names[i])
				if errors.Is(err, errDeleted) {
					continue
				}
				entry, _ := data[field].(string)
				if err == nil && entry == "" {
					err = fmt.Errorf("catalog %s incomplete", field)
				}
				if err != nil {
					once.Do(func() { failure = fmt.Errorf("catalog %s %q: %w", field, names[i], err); cancel() })
					continue
				}
				out[i] = entry
			}
		}()
	}
	for i := range names {
		select {
		case next <- i:
		case <-ctx.Done():
		}
	}
	close(next)
	wg.Wait()
	if failure != nil {
		return nil, failure
	}
	return out, nil
}

// assemble rebuilds the one-document form Parse validates. Each entry's name
// must be the key it is stored under. Bucketed Automations join in bucket
// name order.
func assemble(document string, names, entries []string, buckets map[string]automationBucket) ([]byte, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(document), &top); err != nil {
		return nil, errors.New("catalog head is not a JSON object")
	}
	if _, ok := top["entries"]; ok {
		return nil, errors.New("catalog head must not carry entries")
	}
	list, err := keyedList("entry", "name", names, entries)
	if err != nil {
		return nil, err
	}
	top["entries"] = list
	if buckets != nil {
		if _, ok := top["automations"]; ok {
			return nil, errors.New("catalog head must not carry automations it stores in buckets")
		}
		order := make([]string, 0, len(buckets))
		for name := range buckets {
			order = append(order, name)
		}
		sort.Strings(order)
		var all []json.RawMessage
		for _, name := range order {
			all = append(all, buckets[name].items...)
		}
		if top["automations"], err = json.Marshal(all); err != nil {
			return nil, err
		}
	}
	return json.Marshal(top)
}

// keyedList joins stored JSON objects into an array, checking that each
// one's key field is the name it is stored under.
func keyedList(kind, key string, names, docs []string) (json.RawMessage, error) {
	var list bytes.Buffer
	list.WriteByte('[')
	for i, raw := range docs {
		var keyed map[string]json.RawMessage
		var stored string
		if json.Unmarshal([]byte(raw), &keyed) != nil || json.Unmarshal(keyed[key], &stored) != nil || stored != names[i] {
			return nil, fmt.Errorf("catalog %s %q is stored under another name", kind, names[i])
		}
		if i > 0 {
			list.WriteByte(',')
		}
		list.WriteString(raw)
	}
	list.WriteByte(']')
	return list.Bytes(), nil
}
