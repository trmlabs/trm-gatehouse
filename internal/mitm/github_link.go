package mitm

import (
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var linkTarget = regexp.MustCompile(`<([^<>]*)>`)

// repointLinks rewrites an https Link URL on host that names the matched repository's numeric id (/repositories/{id}/...) to the /repos/{owner}/{repo}/... route the request took, since no route lists the id form.
// Any other link is left as GitHub wrote it, so a page never points at a repository the request did not match; id 0 rewrites nothing.
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
