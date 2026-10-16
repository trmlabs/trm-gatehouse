// Package decoy recognizes decoy credentials: values planted in agent
// sessions that look like keys and that no service accepts. A request that
// presents one shows the session was steered into hunting for secrets, so the
// broker refuses it and records why.
//
// A Set holds only SHA-256 digests. The broker hashes each decoy as it loads
// and keeps no value, so nothing it logs, stores or returns can carry one.
// Each candidate in a request is hashed and looked up by its digest's first
// eight bytes, then confirmed with a constant-time compare, so a lookup costs
// the same at any set size and its timing depends on digests only.
package decoy

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"net/http"
	"sort"
	"strings"
)

// A decoy is one run of decoy characters (A-Z, a-z, 0-9, "_" and "-"),
// MinLength to MaxLength long. Text is split at every other byte, so a decoy
// sent as a bearer token, a header value, a query value, a JSON string or a
// Basic credential part is always one whole run.
const (
	MinLength = 20
	MaxLength = 256
)

// Surfaces name where a request presented a decoy. Each is a fixed code for
// the audit row.
const (
	SurfaceHeader   = "header"
	SurfacePath     = "path"
	SurfaceQuery    = "query"
	SurfaceUserinfo = "userinfo"
	SurfaceBody     = "body"
	SurfacePassword = "password"
)

// placeholderMarker starts every broker placeholder. A decoy holding it could
// match a placeholder a worker legitimately sends.
const placeholderMarker = "__vault_"

// Match is a decoy a request presented: the decoy's label, "<owner>/<name>",
// and the surface it was found in. It never carries the value.
type Match struct {
	Label   string
	Surface string
}

// Rejected names a decoy left out of a set and why, never its value.
type Rejected struct {
	Label  string
	Reason string
}

type entry struct {
	digest [sha256.Size]byte
	label  string
}

// Set is an immutable set of decoy digests. A nil Set holds none.
type Set struct {
	index   map[uint64][]entry
	lengths [MaxLength + 1]bool
	size    int
}

// NewSet hashes each value under its label. A value outside the decoy
// alphabet or length, one holding a placeholder marker, or a repeat of another
// is left out and reported by label. Labels are taken in byte order, so the
// same values always keep the same labels.
func NewSet(values map[string]string) (*Set, []Rejected) {
	s := &Set{index: make(map[uint64][]entry, len(values))}
	labels := make([]string, 0, len(values))
	for label := range values {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	var rejected []Rejected
	for _, label := range labels {
		value := values[label]
		if reason := invalid(value); reason != "" {
			rejected = append(rejected, Rejected{Label: label, Reason: reason})
			continue
		}
		digest := sha256.Sum256([]byte(value))
		if _, repeat := s.lookup(digest); repeat {
			rejected = append(rejected, Rejected{Label: label, Reason: "repeats another decoy"})
			continue
		}
		key := binary.BigEndian.Uint64(digest[:8])
		s.index[key] = append(s.index[key], entry{digest: digest, label: label})
		s.lengths[len(value)] = true
		s.size++
	}
	return s, rejected
}

func invalid(value string) string {
	if len(value) < MinLength || len(value) > MaxLength {
		return "length outside 20 to 256"
	}
	for i := 0; i < len(value); i++ {
		if !decoyByte(value[i]) {
			return "character outside A-Z, a-z, 0-9, _ and -"
		}
	}
	if strings.Contains(value, placeholderMarker) {
		return "holds a placeholder marker"
	}
	return ""
}

func decoyByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}

// Len is the number of decoys in the set.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return s.size
}

// Request reports a decoy in a request's user info, path, query or any header
// value. A Basic credential is decoded first, and percent-encoding is undone.
func (s *Set) Request(r *http.Request) (Match, bool) {
	if s.Len() == 0 || r == nil {
		return Match{}, false
	}
	if u := r.URL; u != nil {
		if u.User != nil {
			password, _ := u.User.Password()
			if label, ok := s.text([]byte(u.User.Username() + ":" + password)); ok {
				return Match{Label: label, Surface: SurfaceUserinfo}, true
			}
		}
		if label, ok := s.text([]byte(u.EscapedPath())); ok {
			return Match{Label: label, Surface: SurfacePath}, true
		}
		if label, ok := s.text([]byte(u.RawQuery)); ok {
			return Match{Label: label, Surface: SurfaceQuery}, true
		}
	}
	for _, values := range r.Header {
		for _, v := range values {
			if label, ok := s.header(v); ok {
				return Match{Label: label, Surface: SurfaceHeader}, true
			}
		}
	}
	return Match{}, false
}

// Body reports a decoy in a request body the broker has already read.
func (s *Set) Body(body []byte) (Match, bool) {
	if s.Len() == 0 {
		return Match{}, false
	}
	if label, ok := s.text(body); ok {
		return Match{Label: label, Surface: SurfaceBody}, true
	}
	return Match{}, false
}

// Password reports a decoy sent as a database password.
func (s *Set) Password(password string) (Match, bool) {
	if s.Len() == 0 {
		return Match{}, false
	}
	if label, ok := s.text([]byte(password)); ok {
		return Match{Label: label, Surface: SurfacePassword}, true
	}
	return Match{}, false
}

// header checks a header value as sent and, for a Basic credential, decoded.
func (s *Set) header(v string) (string, bool) {
	if label, ok := s.text([]byte(v)); ok {
		return label, true
	}
	if len(v) > 6 && strings.EqualFold(v[:6], "basic ") {
		encoded := strings.TrimSpace(v[6:])
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			if decoded, err := enc.DecodeString(encoded); err == nil {
				return s.text(decoded)
			}
		}
	}
	return "", false
}

// text checks data as sent and, when it holds percent-encoding, decoded.
func (s *Set) text(data []byte) (string, bool) {
	if label, ok := s.find(data); ok {
		return label, true
	}
	if bytes.IndexByte(data, '%') >= 0 {
		return s.find(percentDecode(data))
	}
	return "", false
}

// find hashes each run of decoy characters whose length some decoy has.
func (s *Set) find(data []byte) (string, bool) {
	start := -1
	for i := 0; i <= len(data); i++ {
		if i < len(data) && decoyByte(data[i]) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			if n := i - start; n <= MaxLength && s.lengths[n] {
				if label, ok := s.lookup(sha256.Sum256(data[start:i])); ok {
					return label, true
				}
			}
			start = -1
		}
	}
	return "", false
}

// lookup confirms a digest against every decoy sharing its first eight bytes.
func (s *Set) lookup(digest [sha256.Size]byte) (string, bool) {
	for _, e := range s.index[binary.BigEndian.Uint64(digest[:8])] {
		if subtle.ConstantTimeCompare(e.digest[:], digest[:]) == 1 {
			return e.label, true
		}
	}
	return "", false
}

// percentDecode undoes %XX escapes and leaves a malformed one as sent, so a
// stray "%" never hides the rest of the text.
func percentDecode(data []byte) []byte {
	out := make([]byte, 0, len(data))
	for i := 0; i < len(data); i++ {
		if data[i] == '%' && i+2 < len(data) {
			if hi, ok := unhex(data[i+1]); ok {
				if lo, ok := unhex(data[i+2]); ok {
					out = append(out, hi<<4|lo)
					i += 2
					continue
				}
			}
		}
		out = append(out, data[i])
	}
	return out
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
