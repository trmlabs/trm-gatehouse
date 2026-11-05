package httpcatalog

import (
	"errors"
	"regexp"
	"strings"
)

// RequesterToken, as the last segment of a push prefix, confines each requester of a pool to its own branches (refs/heads/cursor/<pool>/{requester}/); a prefix without it is shared by the whole pool.
// It is valid only at the end of a push prefix, for pools that name who runs each request (see grantable); an un-narrowed prefix matches no branch, so a check that skips ForRequester refuses rather than shares.
const RequesterToken = "{requester}"

func requesterTemplate(prefix string) (string, bool) {
	return strings.CutSuffix(prefix, RequesterToken+"/")
}

func IsRequesterTemplate(prefix string) bool { return strings.Contains(prefix, RequesterToken) }

func validRequesterTemplate(prefix string) bool {
	static, ok := requesterTemplate(prefix)
	return ok && strings.HasPrefix(static, "refs/heads/") && len(static) > len("refs/heads/") && strings.HasSuffix(static, "/") &&
		validPlainRefPrefix(static)
}

// segmentPattern is what a requester segment may hold: the characters of a lower-cased email,
// an object ID or a catalog identifier, all safe in a git ref and an audit row.
var segmentPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@+-]{0,199}$`)

var objectIDSegment = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// RequesterSegment is the branch segment naming a requester under a {requester} prefix: a lower-cased email,
// an Entra object ID, or "automation-" and the Automation's catalog id; anyone else has none and reaches nothing.
func RequesterSegment(kind, subject string) string {
	var segment string
	switch kind {
	case "person":
		segment = strings.ToLower(subject)
		// An email, or the Entra object ID of a Cursor user the broker maps.
		if strings.Count(segment, "@") != 1 && !objectIDSegment.MatchString(segment) {
			return ""
		}
	case "automation":
		if subject == "" || strings.Contains(subject, "@") {
			return ""
		}
		segment = "automation-" + subject
	default:
		return ""
	}
	if !segmentPattern.MatchString(segment) || strings.Contains(segment, "..") || strings.HasSuffix(segment, ".") || strings.HasSuffix(segment, ".lock") {
		return ""
	}
	return segment
}

// ForRequester narrows each {requester}/ push prefix to the requester's own segment, or drops it when segment is ""; every other prefix stays after the requester's own.
func (g GitRequest) ForRequester(segment string) GitRequest {
	g.RefPrefixes = narrowPrefixes(g.RefPrefixes, segment)
	g.HeadPrefixes = narrowPrefixes(g.HeadPrefixes, segment)
	return g
}

func narrowPrefixes(prefixes []string, segment string) []string {
	if prefixes == nil {
		return nil
	}
	var own, others []string
	for _, prefix := range prefixes {
		static, ok := requesterTemplate(prefix)
		switch {
		case !ok:
			others = append(others, prefix)
		case segment != "":
			own = append(own, static+segment+"/")
		}
	}
	return append(append(make([]string, 0, len(own)+len(others)), own...), others...)
}

func (r GitRepo) pushTemplates(pool string) bool {
	prefixes, _ := r.PushPrefixes(pool)
	for _, prefix := range prefixes {
		if _, ok := requesterTemplate(prefix); ok {
			return true
		}
	}
	return false
}

func (r GitRepo) perRequester() bool {
	prefixes := append([]string(nil), r.RefPrefixes...)
	for _, own := range r.PoolRefPrefixes {
		prefixes = append(prefixes, own...)
	}
	for _, prefix := range prefixes {
		if _, ok := requesterTemplate(prefix); ok {
			return true
		}
	}
	return false
}

// errRequesterRepo refuses a second git entry listing a repository with {requester} push prefixes: overlappingPrefixes works within one entry only, so another entry's prefix could reach into each requester's branches.
var errRequesterRepo = errors.New("a repository with {requester} push prefixes is listed by one git entry only")

var requesterIdentities = map[string]bool{"claude-session": true, "cursor-session": true, "attested-person": true, IdentityCursorAutomation: true}

// requesterGrantable refuses {requester} push prefixes for a pool that does not name who runs each request, where they would read as a grant but reach nothing.
func requesterGrantable(e Entry, pool string, p Pool, defined bool) error {
	if e.Kind != "git" || e.Git == nil {
		return nil
	}
	for _, r := range e.Git.Repos {
		if r.pushTemplates(pool) && (!defined || !requesterIdentities[p.Identity]) {
			return errRequesterPool
		}
	}
	return nil
}

var errRequesterPool = errors.New("a {requester} push prefix needs a defined pool that names who runs each request (identity claude-session, cursor-session, attested-person or cursor-automation)")
