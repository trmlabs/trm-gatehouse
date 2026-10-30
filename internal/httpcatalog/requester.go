package httpcatalog

import (
	"errors"
	"regexp"
	"strings"
)

// RequesterToken, as the last segment of a push prefix, gives each requester
// on a pool branches of their own: refs/heads/cursor/<pool>/{requester}/
// lets a run push, and act on pull requests, only under
// refs/heads/cursor/<pool>/<its requester>/, never under another person's or
// Automation's. A prefix without it is shared by every requester of the pool,
// which is how a team that works on the same branches on purpose says so.
//
// Only push prefixes (refPrefixes, poolRefPrefixes) take it, only at the end,
// after a branch path (refs/heads/...), and only for pools that name who runs
// each request (see grantable). The broker matches requests against the pool's
// prefixes and then narrows them with GitRequest.ForRequester; a prefix still
// holding the token matches no branch, so a check that skips the narrowing
// refuses rather than share.
const RequesterToken = "{requester}"

// requesterTemplate returns the part of a ref or branch prefix before a
// trailing {requester}/, and whether it has one.
func requesterTemplate(prefix string) (string, bool) {
	return strings.CutSuffix(prefix, RequesterToken+"/")
}

// IsRequesterTemplate reports whether a prefix still holds RequesterToken: one
// GitRequest.ForRequester has not narrowed, which must match nothing.
func IsRequesterTemplate(prefix string) bool { return strings.Contains(prefix, RequesterToken) }

// validRequesterTemplate checks a push prefix ending in {requester}/: the part
// before it is a valid branch push prefix of at least one segment, and the
// token appears nowhere else.
func validRequesterTemplate(prefix string) bool {
	static, ok := requesterTemplate(prefix)
	return ok && strings.HasPrefix(static, "refs/heads/") && len(static) > len("refs/heads/") && strings.HasSuffix(static, "/") &&
		validPlainRefPrefix(static)
}

// segmentPattern is what a requester segment may hold: the characters of a
// lower-cased email, an object ID or a catalog identifier, all safe in a git ref, a GitHub
// branch name and an audit row.
var segmentPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@+-]{0,199}$`)

var objectIDSegment = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// RequesterSegment is the branch segment that names a requester under a
// {requester} prefix: a person's email, lower-cased, or their Entra object ID
// (a Cursor user the broker maps), or "automation-" and the Automation's
// catalog id. Emails always hold one "@", object IDs are hex groups and
// Automation segments start "automation-", so no person's segment is an
// Automation's. Anyone else (a runner
// agent, a workload, a request naming no one) has none, nor does a name git
// cannot carry in a branch, so a {requester} prefix reaches nothing for them.
// kind and subject are authorize.Requester's.
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

// ForRequester narrows a matched request to one requester: each push prefix
// ending in {requester}/ (in RefPrefixes, and among HeadPrefixes the branch
// form of one) becomes that requester's own, segment from RequesterSegment,
// or is dropped when segment is "". Every other prefix, a pull request prefix
// included, stays as it is, after the requester's own, so a refusal that
// names where to push names theirs first.
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

// pushTemplates reports whether any push prefix of the repository that
// reaches pool (the shared ones, then the pool's own) holds RequesterToken.
func (r GitRepo) pushTemplates(pool string) bool {
	prefixes, _ := r.PushPrefixes(pool)
	for _, prefix := range prefixes {
		if _, ok := requesterTemplate(prefix); ok {
			return true
		}
	}
	return false
}

// perRequester reports whether any push prefix of the repository, shared or
// any pool's own, holds RequesterToken.
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

// errRequesterRepo refuses a second git entry listing a repository with
// {requester} push prefixes. A pool's pull request reach joins the push
// prefixes of every git entry listing the repository (pushBranchPrefixes),
// while overlappingPrefixes keeps prefixes apart within one entry only, so
// another entry's prefix could reach into each requester's own branches.
var errRequesterRepo = errors.New("a repository with {requester} push prefixes is listed by one git entry only")

// requesterIdentities are the pool identities that name who runs each
// request, so a {requester} prefix can name them.
var requesterIdentities = map[string]bool{"claude-session": true, "cursor-session": true, "attested-person": true, IdentityCursorAutomation: true}

// requesterGrantable refuses a git entry whose push prefixes for pool hold
// RequesterToken unless the catalog defines the pool with an identity that
// names who runs each request; on any other pool the prefix would reach
// nothing, which reads as a grant but is none.
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
