package httpcatalog

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// The path guard keeps a worker from using a browser session to mint a credential or change the account.
// deniedSegments are refused anywhere in an API path, in any case and ignoring "-" and "_".
var deniedSegments = segmentSet("apikey", "apikeys", "password", "changepassword", "resetpassword", "mfa", "otp", "totp",
	"invitations", "invites", "oauth", "tokens", "token", "sso", "saml", "scim", "connections", "roles", "ipallowlist",
	"authentication", "admin", "usermanagement", "bulkoperations", "rotatesecret", "webhooks", "credentials", "secrets",
	"keys", "clientsecret", "permissions", "impersonate", "sessions")

// readOnlySegments pass only GET, HEAD and OPTIONS wherever they appear: the same routes invite and create users.
var readOnlySegments = segmentSet("usersorganizations")

func segmentSet(names ...string) map[string]bool {
	set := map[string]bool{}
	for _, n := range names {
		set[n] = true
	}
	return set
}

func foldSegment(s string) string {
	return strings.NewReplacer("-", "", "_", "").Replace(strings.ToLower(s))
}

var (
	ErrDeniedPath   = errors.New("path denied for browser sessions")
	ErrReadOnlyPath = errors.New("path is read-only for browser sessions")
)

var templateSegment = regexp.MustCompile(`^(\*|[A-Za-z0-9][A-Za-z0-9._~-]{0,127})$`)

func pathSegments(path string) []string {
	var out []string
	for _, s := range strings.Split(path, "/") {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// templateCovers reports whether a path lies at or below a template, with * matching one segment; names compare without case so the guard fails closed.
func templateCovers(template, path []string) bool {
	if len(path) < len(template) {
		return false
	}
	for i, t := range template {
		if t != "*" && !strings.EqualFold(t, path[i]) {
			return false
		}
	}
	return true
}

func (e *Entry) normalizeBrowserPaths() error {
	if len(e.PathPrefixes) == 0 {
		return errors.New("browser-session entries list their pathPrefixes")
	}
	templates := map[string][][]string{}
	for field, list := range map[string][]string{"deniedPaths": e.DeniedPaths, "readOnlyPaths": e.ReadOnlyPaths} {
		for _, t := range list {
			segments := pathSegments(t)
			valid := strings.HasPrefix(t, "/") && !strings.HasSuffix(t, "/") && !strings.Contains(t, "//") && len(segments) > 0
			for _, s := range segments {
				valid = valid && templateSegment.MatchString(s) && s != "." && s != ".."
			}
			if !valid {
				return fmt.Errorf("invalid %s template %q", field, t)
			}
			templates[field] = append(templates[field], segments)
		}
	}
	for _, p := range e.PathPrefixes {
		segments := pathSegments(p)
		if !strings.HasPrefix(p, "/") || len(segments) == 0 || strings.ContainsAny(p, "?#%*{} \\;") || strings.Contains(p, "//") || strings.Contains(p, "__") {
			return fmt.Errorf("invalid path prefix %q: browser-session prefixes name a part of the API, never /", p)
		}
		for _, s := range segments {
			if s == "." || s == ".." {
				return fmt.Errorf("invalid path prefix %q", p)
			}
			if deniedSegments[foldSegment(s)] {
				return fmt.Errorf("path prefix %q contains a denied segment", p)
			}
		}
		// A prefix at or below a denied template grants nothing; one above it is refused at run time.
		for _, t := range templates["deniedPaths"] {
			if templateCovers(t, segments) {
				return fmt.Errorf("path prefix %q lies within deniedPaths template /%s", p, strings.Join(t, "/"))
			}
		}
	}
	return nil
}

func (e *Entry) guardBrowserPath(method, path string) error {
	segments := pathSegments(path)
	readOnly := false
	for _, s := range segments {
		folded := foldSegment(s)
		if deniedSegments[folded] {
			return ErrDeniedPath
		}
		readOnly = readOnly || readOnlySegments[folded]
	}
	for _, t := range e.DeniedPaths {
		if templateCovers(pathSegments(t), segments) {
			return ErrDeniedPath
		}
	}
	for _, t := range e.ReadOnlyPaths {
		readOnly = readOnly || templateCovers(pathSegments(t), segments)
	}
	if readOnly && method != "GET" && method != "HEAD" && method != "OPTIONS" {
		return ErrReadOnlyPath
	}
	return nil
}
