package mitm

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"slices"

	"github.com/Infisical/agent-vault/internal/auditchain"
)

// readyAnswerLimit bounds GitHub's answer to readyMutation, which names one
// pull request's number and draft state.
const readyAnswerLimit = 64 << 10

// graphqlErrorType is a GraphQL error type as GitHub names them (FORBIDDEN,
// NOT_FOUND). Any other value is logged as "invalid", so nothing else GitHub
// sends reaches the log.
var graphqlErrorType = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

// relayReady sends readyMutation and reads GitHub's whole answer before any of
// it reaches the worker. GitHub answers a mutation it refuses with HTTP 200 and
// an errors list (a token without contents write gets FORBIDDEN), so relaying
// that 200 would let the worker's gh exit 0 with the pull request still a
// draft, and the audit row would say completed. A 200 that does not show pull
// request number ready is recorded as graphql_error and answered 502 with a
// fixed body; the broker log names the pull request, the reason and the error
// types, never GitHub's messages, under the row's session. A 200 that does
// show it, and any other status, is relayed as relayResponse relays any
// answer.
func (p *Proxy) relayReady(w http.ResponseWriter, out *http.Request, needles [][]byte, limit, number int64, event auditchain.Event, finish func(int, string), rejected func(*http.Response)) {
	resp, err := p.upstream.RoundTrip(out)
	if err != nil {
		finish(http.StatusBadGateway, "upstream_error")
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		return
	}
	if resp.StatusCode != http.StatusOK {
		p.relayResponse(w, resp, needles, limit, finish, rejected)
		return
	}
	limit = min(limit, readyAnswerLimit)
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	_ = resp.Body.Close()
	switch {
	case err != nil:
		finish(http.StatusBadGateway, "upstream_error")
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		return
	case int64(len(data)) > limit:
		finish(http.StatusBadGateway, "response_too_large")
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		return
	}
	if reason, types := readyRefused(data, number); reason != "" {
		p.logger.Warn("github pull request not marked ready", "session", event.Session, "pool", event.Pool, "binding", event.Binding,
			"pullRequest", number, "reason", reason, "errorTypes", types)
		finish(http.StatusBadGateway, "graphql_error")
		body, _ := json.Marshal(map[string]string{"message": "GitHub did not mark the pull request ready", "code": "graphql_error", "reason": reason})
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write(append(body, '\n'))
		return
	}
	resp.Body = io.NopCloser(bytes.NewReader(data))
	p.relayResponse(w, resp, needles, limit, finish, rejected)
}

// readyRefused reports why GitHub's answer to readyMutation does not show pull
// request number ready, or "" when it does: "errors" when it lists any, with
// their distinct types ("none" for an error without one); "still_draft" when
// the pull request it returns is still a draft; "unexpected" for any other
// answer.
func readyRefused(data []byte, number int64) (reason string, types []string) {
	var answer struct {
		Data *struct {
			Mark *struct {
				PullRequest *struct {
					Number  int64 `json:"number"`
					IsDraft *bool `json:"isDraft"`
				} `json:"pullRequest"`
			} `json:"markPullRequestReadyForReview"`
		} `json:"data"`
		Errors []struct {
			Type string `json:"type"`
		} `json:"errors"`
	}
	if json.Unmarshal(data, &answer) != nil {
		return "unexpected", nil
	}
	if len(answer.Errors) > 0 {
		for _, e := range answer.Errors {
			t := e.Type
			switch {
			case t == "":
				t = "none"
			case !graphqlErrorType.MatchString(t):
				t = "invalid"
			}
			if !slices.Contains(types, t) && len(types) < 8 {
				types = append(types, t)
			}
		}
		slices.Sort(types)
		return "errors", types
	}
	if answer.Data == nil || answer.Data.Mark == nil || answer.Data.Mark.PullRequest == nil {
		return "unexpected", nil
	}
	switch pr := answer.Data.Mark.PullRequest; {
	case pr.Number != number || pr.IsDraft == nil:
		return "unexpected", nil
	case *pr.IsDraft:
		return "still_draft", nil
	}
	return "", nil
}
