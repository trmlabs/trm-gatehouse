package mitm

import (
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// linkTarget is the URL of one link in a Link header, between angle brackets.
var linkTarget = regexp.MustCompile(`<([^<>]*)>`)

// repointLinks rewrites the pagination links of a GitHub API answer so the next
// page goes through the route the request took. GitHub names a repository's
// next page by its numeric id (/repositories/{id}/...), which no route lists,
// where the request named it as /repos/{owner}/{repo}/...; a client that follows
// the link would be refused after the first page. A link is rewritten only when
// it is an https URL on host, the host the request went to, and names the id of
// the repository the request matched (the one repository its token was minted
// for), with nothing else in the path to read two ways. Any other link, one
// naming another repository's id included, is left as GitHub wrote it, so a
// page is never pointed at a repository the request did not match. The
// rewritten URL is an ordinary request: it is matched, authorized and held to
// the entry's routes like the first one. id 0 means the id is not known, and
// nothing is rewritten.
func repointLinks(h http.Header, host, repo string, id int64) {
	values := h.Values("Link")
	if id <= 0 || len(values) == 0 {
		return
	}
	rewritten := make([]string, len(values))
	for i, value := range values {
		rewritten[i] = linkTarget.ReplaceAllStringFunc(value, func(link string) string {
			if next, ok := repointedLink(link[1:len(link)-1], host, repo, id); ok {
				return "<" + next + ">"
			}
			return link
		})
	}
	h["Link"] = rewritten
}

// repointedLink returns the /repos/{repo}/ form of a /repositories/{id}/ URL on
// host, and false for any other URL.
func repointedLink(raw, host, repo string, id int64) (string, bool) {
	u, err := url.Parse(raw)
	prefix := "/repositories/" + strconv.FormatInt(id, 10) + "/"
	if err != nil || u.Scheme != "https" || !strings.EqualFold(u.Host, host) || u.User != nil || u.Fragment != "" ||
		u.RawPath != "" || !strings.HasPrefix(u.Path, prefix) {
		return "", false
	}
	u.Path = "/repos/" + repo + "/" + strings.TrimPrefix(u.Path, prefix)
	return u.String(), true
}
