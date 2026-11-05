package httpcatalog

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// GCPBinding mints a short-lived Google token per entry in one of three modes: Downscope (Bucket set),
// Impersonate (ServiceAccount set), or Identity (ServiceAccount and Audience set, ID token).
type GCPBinding struct {
	Bucket string `json:"bucket,omitempty"`
	Prefix string `json:"prefix,omitempty"`
	Role   string `json:"role,omitempty"`

	ServiceAccount string   `json:"serviceAccount,omitempty"`
	Scopes         []string `json:"scopes,omitempty"`

	// Audience selects an ID token: the aud claim the entry's host verifies. It excludes scopes, bucket, prefix and role.
	Audience string `json:"audience,omitempty"`

	// LifetimeSeconds bounds how long a minted token is used (default 900, at most 3600); a downscoped token also ends with the broker's own token, an ID token with its own exp.
	LifetimeSeconds int `json:"lifetimeSeconds,omitempty"`
}

var (
	gcsBucket      = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{1,61}[a-z0-9]$`)
	gcsPrefix      = regexp.MustCompile(`^([A-Za-z0-9_-]+/)+$`)
	serviceAccount = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$`)
	googleScope    = regexp.MustCompile(`^https://www\.googleapis\.com/auth/[a-z0-9._-]+$`)
	// An audience is whatever the verifying service pins: printable, no spaces, short enough for a claim.
	idTokenAudience = regexp.MustCompile(`^[\x21-\x7e]{1,512}$`)
	// Storage roles a boundary may carry: object data only, never bucket or IAM administration.
	storageRoles = map[string]bool{"roles/storage.objectViewer": true, "roles/storage.objectCreator": true, "roles/storage.objectUser": true}
	// Data-plane hosts an entry may reach; a minted token never goes to a host that mints credentials or changes IAM.
	dataPlaneHosts = map[string]bool{"storage.googleapis.com": true, "bigquery.googleapis.com": true, "bigquerystorage.googleapis.com": true}
	// Domains an ID token never goes to: Google's own APIs take access tokens, and its credential and metadata endpoints take nothing the broker should send.
	googleDomains = []string{"googleapis.com", "google.com", "google.internal"}
)

// gcpForwardHeaders are the headers Google clients need besides ForwardHeaders; X-Goog-User-Project bills another project, so it passes only when the entry names it.
var gcpForwardHeaders = []string{"Accept", "Content-Type", "User-Agent", "X-Goog-Api-Client", "X-Goog-Request-Params",
	"X-Upload-Content-Type", "X-Upload-Content-Length", "Content-Range", "Range", "If-Match", "If-None-Match"}

func (e *Entry) normalizeGCP() error {
	if e.Git != nil || e.Postgres != nil || e.Memgraph != nil || e.BrowserSession != nil || e.Key != (KeyRef{}) || e.Header != "" || e.Scheme != "" || e.BasicUser || e.BasicPair || e.PairUserHeader != "" {
		return errors.New("gcp entries take host, pools, placeholder, tier, gcp and optional paths, methods and forward headers")
	}
	g := e.GCP
	if g == nil {
		return errors.New("gcp entries need gcp settings")
	}
	if g.Audience == "" && !dataPlaneHosts[e.Host] {
		return errors.New("gcp entries reach a listed Google data-plane host: storage, bigquery or bigquerystorage.googleapis.com")
	}
	if g.Audience != "" && underGoogleDomain(e.Host) {
		return errors.New("an identity entry reaches the service that verifies its ID token, never a Google host")
	}
	if e.Tier != "T1" && e.Tier != "T2" {
		return errors.New("gcp entries are tier T1 or T2")
	}
	switch {
	case g.Audience != "":
		if g.ServiceAccount == "" || !serviceAccount.MatchString(g.ServiceAccount) || g.Bucket != "" || g.Prefix != "" || g.Role != "" || len(g.Scopes) > 0 {
			return errors.New("an identity entry needs a service account email and an audience, and no scopes, bucket, prefix or role")
		}
		if !idTokenAudience.MatchString(g.Audience) || len(e.PathPrefixes) == 0 {
			return errors.New("an identity entry needs a printable audience without spaces and explicit path prefixes")
		}
		// A token for one service must not be handed to another that could replay it there.
		if u, err := url.Parse(g.Audience); err == nil && u.Scheme == "https" && !strings.EqualFold(u.Hostname(), e.Host) {
			return errors.New("an identity entry's https audience names the entry's own host")
		}
	case g.Bucket != "" && g.ServiceAccount == "":
		if e.Host != "storage.googleapis.com" || !gcsBucket.MatchString(g.Bucket) || !gcsPrefix.MatchString(g.Prefix) ||
			strings.Contains(g.Bucket, "..") || !storageRoles[g.Role] || len(g.Scopes) > 0 {
			return errors.New("a downscoped entry needs storage.googleapis.com, a bucket, a prefix ending in / and an object role")
		}
		if len(e.PathPrefixes) == 0 {
			e.PathPrefixes = []string{"/storage/v1/b/" + g.Bucket + "/", "/upload/storage/v1/b/" + g.Bucket + "/", "/download/storage/v1/b/" + g.Bucket + "/"}
		}
	case g.ServiceAccount != "" && g.Bucket == "":
		if !serviceAccount.MatchString(g.ServiceAccount) || g.Prefix != "" || g.Role != "" || len(e.PathPrefixes) == 0 {
			return errors.New("an impersonating entry needs a service account email and explicit path prefixes")
		}
		if len(g.Scopes) == 0 {
			g.Scopes = []string{"https://www.googleapis.com/auth/cloud-platform"}
		}
		for _, s := range g.Scopes {
			if !googleScope.MatchString(s) {
				return fmt.Errorf("invalid scope %q", s)
			}
		}
	default:
		return errors.New("gcp entries set either bucket (downscope), serviceAccount (impersonate) or serviceAccount and audience (identity)")
	}
	if g.LifetimeSeconds == 0 {
		g.LifetimeSeconds = 900
	}
	if g.LifetimeSeconds < 300 || g.LifetimeSeconds > 3600 {
		return errors.New("gcp lifetimeSeconds must be 300 to 3600")
	}
	for _, p := range e.PathPrefixes {
		if !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "?#%*{} \\") || strings.Contains(p, "//") || strings.Contains(p, "/..") || strings.Contains(p, "__") {
			return fmt.Errorf("invalid path prefix %q", p)
		}
	}
	if len(e.Methods) == 0 {
		e.Methods = []string{"DELETE", "GET", "HEAD", "PATCH", "POST", "PUT"}
	}
	for i, m := range e.Methods {
		e.Methods[i] = strings.ToUpper(m)
		if !allowedMethods[e.Methods[i]] {
			return fmt.Errorf("method %q not supported", m)
		}
	}
	sort.Strings(e.Methods)
	if !placeholder.MatchString(e.Placeholder) {
		return errors.New("placeholder must look like __vault_NAME__")
	}
	if len(e.Pools) == 0 {
		return errors.New("at least one pool is required")
	}
	for _, pool := range e.Pools {
		if !idPattern.MatchString(pool) {
			return fmt.Errorf("invalid pool %q", pool)
		}
	}
	for i, h := range e.ForwardHeaders {
		e.ForwardHeaders[i] = http.CanonicalHeaderKey(h)
		if !tokenPattern.MatchString(h) || reservedHeaders[e.ForwardHeaders[i]] {
			return fmt.Errorf("forward header %q not allowed", h)
		}
	}
	if e.MaxRequestBytes == 0 {
		e.MaxRequestBytes = 16 << 20
	}
	if e.MaxResponseBytes == 0 {
		e.MaxResponseBytes = 256 << 20
	}
	if e.MaxRequestBytes < 0 || e.MaxRequestBytes > 1<<30 || e.MaxResponseBytes < 1 || e.MaxResponseBytes > 4<<30 {
		return errors.New("size limits out of range")
	}
	return nil
}

func underGoogleDomain(host string) bool {
	for _, d := range googleDomains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

func (c Catalog) GCPMatch(host string, port int, method, path, pool string) (*Entry, bool, error) {
	host = strings.ToLower(host)
	var best *Entry
	bestLen, listed := -1, false
	for i := range c.entries {
		e := &c.entries[i]
		if e.Kind != "gcp" || e.Host != host || e.Port != port {
			continue
		}
		listed = true
		for _, prefix := range e.PathPrefixes {
			if pathWithin(path, prefix) && len(prefix) > bestLen {
				best, bestLen = e, len(prefix)
			}
		}
	}
	switch {
	case !listed:
		return nil, false, nil
	case best == nil:
		return nil, true, ErrUnlisted
	case !contains(best.Methods, method):
		return best, true, ErrMethod
	case !contains(best.Pools, pool):
		return best, true, ErrPool
	}
	return best, true, nil
}

func (e *Entry) GCPForwardsHeader(name string) bool {
	name = http.CanonicalHeaderKey(name)
	return contains(gcpForwardHeaders, name) || e.forwardsGRPCHeader(name) || contains(e.ForwardHeaders, name)
}
