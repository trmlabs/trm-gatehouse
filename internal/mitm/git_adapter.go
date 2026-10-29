package mitm

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Infisical/agent-vault/internal/auditchain"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/githubapp"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
)

// forwardGit serves git smart-HTTP for a catalog git entry. The worker sends
// no credential; the broker adds a token minted for this one repository with
// contents read, or write only for a push to a write binding. GitHub's own
// branch protection still governs every push, and the pool's ref prefixes
// (httpcatalog GitRepo.PushPrefixes), narrowed to the requester's own where
// the pool gives each requester theirs (GitRequest.ForRequester), narrow it.
// Every ref a push names is checked, so a force push or a branch delete is
// held to the same prefixes as any other update.
func (p *Proxy) forwardGit(w http.ResponseWriter, r *http.Request, target string, scope *brokercore.ProxyScope, event auditchain.Event, git httpcatalog.GitRequest, matchErr error) {
	a := p.adapter
	if git.Entry != nil {
		event.Binding = git.Entry.Name + "/" + git.Repo.Repo
	}
	deny := func(status int, outcome string) { p.adapterDeny(w, event, target, status, outcome) }
	switch {
	case errors.Is(matchErr, httpcatalog.ErrUnlisted):
		deny(http.StatusForbidden, "unlisted")
		return
	case errors.Is(matchErr, httpcatalog.ErrMethod):
		deny(http.StatusMethodNotAllowed, "method")
		return
	case errors.Is(matchErr, httpcatalog.ErrReadOnly):
		deny(http.StatusForbidden, "read_only")
		return
	case errors.Is(matchErr, httpcatalog.ErrAutomationReadOnly):
		deny(http.StatusForbidden, "automation_read_only")
		return
	case matchErr != nil:
		deny(http.StatusForbidden, "pool")
		return
	case git.Write && git.Limited && len(git.RefPrefixes) == 0:
		// Every prefix was a {requester} one, and this request names no
		// requester with a branch segment (a runner agent, no session): it
		// may clone and fetch only.
		deny(http.StatusForbidden, "no_branch_prefix")
		return
	}
	entry := git.Entry
	if a.GitTokens == nil {
		// Waiting does not help: only an operator (a restart, for a minter
		// wired at startup) can give the broker one.
		p.adapterDenyAs(w, event, target, http.StatusServiceUnavailable, "token_unavailable", "broker_misconfigured", 0)
		return
	}
	expected := hostHeaderForScheme("https", target)
	if r.URL.IsAbs() || (r.Host != target && r.Host != expected) || r.URL.User != nil || r.URL.Fragment != "" || r.URL.RawPath != "" ||
		unsafePath(r.URL.Path) || r.Header.Get("Upgrade") != "" || strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") || len(r.Trailer) > 0 ||
		(r.Method == http.MethodGet && r.ContentLength > 0) {
		deny(http.StatusBadRequest, "request_shape")
		return
	}
	// The worker holds no credential, so it may send none.
	if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
		deny(http.StatusBadRequest, "credential_header")
		return
	}
	// git compresses large fetch negotiations; nothing else may be encoded.
	encoding := r.Header.Get("Content-Encoding")
	if encoding != "" && (encoding != "gzip" || git.Write || r.Method != http.MethodPost) {
		deny(http.StatusBadRequest, "request_shape")
		return
	}
	body := &limitedBody{reader: r.Body, remaining: entry.MaxRequestBytes}
	var outBody io.Reader = body
	if git.Write && r.Method == http.MethodPost {
		// Every push names its refs in the audit row, and a limited one may
		// change only refs under its prefixes.
		consumed, refs, capabilities, err := readReceivePackCommands(body, entry.Git.MaxPushCommandBytes)
		if err != nil {
			deny(http.StatusBadRequest, "push_shape")
			return
		}
		event.Branch = refsField(refs)
		if git.Limited {
			for _, ref := range refs {
				if !hasAnyPrefix(ref, git.RefPrefixes) {
					event.Branch = auditchain.BranchField(ref)
					p.refusePush(w, event, target, body, capabilities, refs, git.RefPrefixes)
					return
				}
			}
		}
		outBody = io.MultiReader(bytes.NewReader(consumed), body)
	}
	enf := p.rateLimit.EnforceProxy(r.Context(), proxyLimitActor(scope), entry.Name)
	if !enf.Allowed {
		p.adapterRateDeny(w, event, target, enf.Decision)
		return
	}
	defer enf.Release()
	app := githubapp.App{AppID: entry.Git.AppID, InstallationID: entry.Git.InstallationID}
	permissions := githubapp.ContentsRead
	if git.Write {
		permissions = githubapp.ContentsWrite
	}
	token, err := a.GitTokens.Token(r.Context(), app, git.Repo.Repo, permissions)
	if err != nil {
		deny(http.StatusServiceUnavailable, "token_unavailable")
		return
	}
	outURL := &url.URL{Scheme: "https", Host: target, Path: r.URL.Path, RawQuery: r.URL.RawQuery}
	if r.Method == http.MethodGet {
		outBody = http.NoBody
	}
	out, err := http.NewRequestWithContext(r.Context(), r.Method, outURL.String(), outBody)
	if err != nil {
		deny(http.StatusBadRequest, "request_shape")
		return
	}
	if r.Method == http.MethodPost {
		out.ContentLength = r.ContentLength // -1 streams chunked, as git does for large pushes
	}
	out.Host = expected
	for _, name := range []string{"Accept", "Content-Type", "User-Agent", "Git-Protocol", "Content-Encoding"} {
		if v := r.Header.Values(name); len(v) > 0 {
			out.Header[name] = append([]string(nil), v...)
		}
	}
	payload := "x-access-token:" + token.Value()
	credential := "Basic " + base64.StdEncoding.EncodeToString([]byte(payload))
	out.Header.Set("Authorization", credential)
	out.Header.Set("Accept-Encoding", "identity")

	admitted := event
	admitted.Event, admitted.Outcome = auditchain.EventHTTPRequest, "admitted"
	if err := a.Audit.Record(admitted); err != nil {
		refuse(w, "audit_unavailable")
		return
	}
	admittedAt := time.Now()
	finish := func(status int, outcome string) {
		outcome, cause := splitOutcome(outcome)
		done := event
		done.Event, done.Outcome, done.Cause, done.Status = auditchain.EventHTTPResponse, outcome, cause, status
		done.Duration = time.Since(admittedAt).Milliseconds()
		_ = a.Audit.Record(done)
	}
	needles := secretRepresentations(map[string]string{"token": token.Value(), "basic": payload, "credential": credential})
	p.relayScreened(w, out, needles, entry.MaxResponseBytes, finish, func(*http.Response) {
		a.GitTokens.Invalidate(app, git.Repo.Repo, permissions)
	}, body.exceeded.Load)
}

// limitedBody streams a request body and fails once it passes its limit.
type limitedBody struct {
	reader    io.Reader
	remaining int64
	exceeded  atomic.Bool
}

var errBodyTooLarge = errors.New("request body exceeds its limit")

func (b *limitedBody) Read(p []byte) (int, error) {
	if b.remaining <= 0 {
		var probe [1]byte
		if n, _ := b.reader.Read(probe[:]); n > 0 {
			b.exceeded.Store(true)
			return 0, errBodyTooLarge
		}
		return 0, io.EOF
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.reader.Read(p)
	b.remaining -= int64(n)
	return n, err
}

// readReceivePackCommands reads a push's command list (pkt-lines up to the
// flush, at most limit bytes: the entry's maxPushCommandBytes) and returns the
// bytes read, every ref the push would change and the capabilities git asked
// for on its first command. Push certificates are refused, since their refs
// cannot be checked here.
func readReceivePackCommands(r io.Reader, limit int64) ([]byte, []string, []string, error) {
	var consumed []byte
	var refs, capabilities []string
	for int64(len(consumed)) < limit {
		head := make([]byte, 4)
		if _, err := io.ReadFull(r, head); err != nil {
			return nil, nil, nil, err
		}
		consumed = append(consumed, head...)
		n, err := strconv.ParseUint(string(head), 16, 16)
		if err != nil {
			return nil, nil, nil, err
		}
		if n == 0 {
			if len(refs) == 0 {
				return nil, nil, nil, errors.New("push without commands")
			}
			return consumed, refs, capabilities, nil
		}
		if n < 5 {
			return nil, nil, nil, errors.New("invalid pkt-line")
		}
		payload := make([]byte, n-4)
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, nil, nil, err
		}
		consumed = append(consumed, payload...)
		line, asked, hasCapabilities := strings.Cut(strings.TrimSuffix(string(payload), "\n"), "\x00")
		switch {
		case strings.HasPrefix(line, "shallow "):
			continue
		case strings.HasPrefix(line, "push-cert"):
			return nil, nil, nil, errors.New("push certificates are not supported")
		}
		fields := strings.Fields(line)
		if len(fields) != 3 || !objectID(fields[0]) || !objectID(fields[1]) || !strings.HasPrefix(fields[2], "refs/") {
			return nil, nil, nil, errors.New("invalid push command")
		}
		if hasCapabilities && len(refs) == 0 {
			capabilities = strings.Fields(asked)
		}
		refs = append(refs, fields[2])
	}
	return nil, nil, nil, errors.New("push command list too long")
}

func objectID(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// hasAnyPrefix reports whether ref is under one of prefixes. A {requester}
// prefix that ForRequester has not narrowed matches nothing.
func hasAnyPrefix(ref string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if !httpcatalog.IsRequesterTemplate(prefix) && strings.HasPrefix(ref, prefix) {
			return true
		}
	}
	return false
}

// refsField is a push's refs for its audit row's branch field: the refs,
// comma-separated, as many whole ones as fit the field with room left to
// count the rest as "+N". A first ref the field cannot carry reads "invalid".
func refsField(refs []string) string {
	var field string
	for i, ref := range refs {
		next, rest := ref, ""
		if i > 0 {
			next = field + "," + ref
		}
		if i+1 < len(refs) {
			rest = ",+" + strconv.Itoa(len(refs)-i-1)
		}
		if auditchain.BranchField(ref) != ref || len(next)+len(rest) > maxBranchField {
			if i == 0 {
				return "invalid" + rest
			}
			return field + ",+" + strconv.Itoa(len(refs)-i)
		}
		field = next
	}
	return field
}

// maxBranchField is auditchain's limit on a branch field.
const maxBranchField = 255

// refusePush refuses a push that would change a ref outside the branches this
// run may write. The refusal is git's own when git asked for a report (every
// git does): GitHub never sees the push, each ref is rejected with the
// reason, so git prints "! [remote rejected] ... (reason)", and on a side
// band the branches the run may push to, as "remote:" lines. An agent learns
// where to push from the refusal alone, whatever named its branch. The rest
// of the push is read and dropped first, as a git server does, so git reads
// the report rather than a broken connection. A push that asked for no
// report, or whose rest is over the entry's limit, gets the plain refusal.
func (p *Proxy) refusePush(w http.ResponseWriter, event auditchain.Event, target string, body *limitedBody, capabilities, refs, prefixes []string) {
	reporting := containsString(capabilities, "report-status") || containsString(capabilities, "report-status-v2")
	if _, err := io.Copy(io.Discard, body); err != nil || !reporting {
		p.adapterDeny(w, event, target, http.StatusForbidden, "ref_outside_binding")
		return
	}
	event.Event, event.Outcome, event.Status = auditchain.EventDenied, "ref_outside_binding", http.StatusOK
	event.Target = auditchain.TargetField(target)
	if p.adapter.Audit.Record(event) != nil {
		refuse(w, "audit_unavailable")
		return
	}
	w.Header().Set(RefusalHeader, "ref_outside_binding")
	w.Header().Set("Content-Type", "application/x-git-receive-pack-result")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(receivePackRefusal(capabilities, refs, prefixes))
}

// receivePackRefusal is a receive-pack report rejecting every ref of a push
// (GitHub receives none of a refused push): each ref outside prefixes with
// the branches the run may push to, and any other as not pushed, on the side
// band git asked for, if any.
func receivePackRefusal(capabilities, refs, prefixes []string) []byte {
	var branches []string
	for _, prefix := range prefixes {
		if branch, ok := strings.CutPrefix(prefix, "refs/heads/"); ok && branch != "" {
			branches = append(branches, branch)
		}
	}
	reason := "outside the branches this run may push to"
	switch {
	case len(branches) > 3:
		reason += "; push to a branch under " + strings.Join(branches[:3], ", ") + " or another of yours"
	case len(branches) > 0:
		reason += "; push to a branch under " + strings.Join(branches, " or ")
	}
	report := pktLine("unpack ok\n")
	for _, ref := range refs {
		if hasAnyPrefix(ref, prefixes) {
			report += pktLine("ng " + ref + " not pushed: another ref in this push is outside the branches this run may push to\n")
			continue
		}
		report += pktLine("ng " + ref + " " + reason + "\n")
	}
	report += "0000"
	band := 0
	switch {
	case containsString(capabilities, "side-band-64k"):
		band = 65520 - 5
	case containsString(capabilities, "side-band"):
		band = 1000 - 5
	}
	if band == 0 {
		return []byte(report)
	}
	message := "Gatehouse refused this push: it changes a ref outside the branches this run may push to.\n"
	if len(branches) > 0 {
		message += "Push to a branch under " + branches[0] + ", for example: git switch -c " + branches[0] + "<topic> && git push -u origin HEAD\n"
	}
	var out strings.Builder
	for _, part := range []struct {
		channel byte
		data    string
	}{{2, message}, {1, report}} {
		for data := part.data; data != ""; {
			n := min(len(data), band)
			out.WriteString(pktLine(string(part.channel) + data[:n]))
			data = data[n:]
		}
	}
	out.WriteString("0000")
	return []byte(out.String())
}

// pktLine frames one git pkt-line.
func pktLine(payload string) string { return fmt.Sprintf("%04x%s", len(payload)+4, payload) }
