package mitm

import (
	"bytes"
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/Infisical/agent-vault/internal/httpcatalog"
)

// CI restarts let an agent update its own pull request's branch or rerun a workflow run on a branch the pool could push to.
// A rerun keeps the original run's actor, and that actor is not checked here.

// restartEvents are the run events a rerun may repeat (a push, or a pull request from the branch); other events carry other trust and are never rerun by an agent.
var restartEvents = map[string]bool{"push": true, "pull_request": true}

var headSHA = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)

// restartInScope reads what a CI restart acts on with the request's token and returns its head branch for the audit row.
// ok is true only when the branch is in this repository (not a fork) under api.HeadPrefixes and, for a run, a push or pull request from it started the run; any failed read refuses.
func (p *Proxy) restartInScope(r *http.Request, target, host string, api httpcatalog.GitRequest, token string) (branch string, ok bool) {
	type repository struct {
		FullName string `json:"full_name"`
	}
	id := strconv.FormatInt(api.RestartOf, 10)
	if api.Route == "update-branch" {
		var pr struct {
			Head struct {
				Ref  string      `json:"ref"`
				Repo *repository `json:"repo"`
			} `json:"head"`
		}
		if !p.githubGet(r, target, host, "/repos/"+api.Repo.Repo+"/pulls/"+id, token, &pr) {
			return "", false
		}
		if pr.Head.Repo == nil {
			return pr.Head.Ref, false
		}
		return pr.Head.Ref, headInReach(api.Repo.Repo, pr.Head.Repo.FullName, pr.Head.Ref, api.HeadPrefixes)
	}
	var run struct {
		HeadBranch     string      `json:"head_branch"`
		Event          string      `json:"event"`
		Repository     *repository `json:"repository"`
		HeadRepository *repository `json:"head_repository"`
	}
	if !p.githubGet(r, target, host, "/repos/"+api.Repo.Repo+"/actions/runs/"+id, token, &run) {
		return "", false
	}
	if !restartEvents[run.Event] || run.Repository == nil || !strings.EqualFold(run.Repository.FullName, api.Repo.Repo) || run.HeadRepository == nil {
		return run.HeadBranch, false
	}
	return run.HeadBranch, headInReach(api.Repo.Repo, run.HeadRepository.FullName, run.HeadBranch, api.HeadPrefixes)
}

func restartOutcome(route string) string {
	if route == "update-branch" {
		return "pull_request_target"
	}
	return "run_target"
}

// restartBody rebuilds a CI restart's body: none, or an empty object, plus expected_head_sha on a branch update; anything else is refused.
func restartBody(data []byte, updateBranch bool) ([]byte, bool) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, true
	}
	allowed := map[string]bool{}
	if updateBranch {
		allowed["expected_head_sha"] = true
	}
	fields, ok := jsonFields(data, allowed)
	if !ok {
		return nil, false
	}
	raw, set := fields["expected_head_sha"]
	if !set {
		return nil, true // {}
	}
	var sha string
	if json.Unmarshal(raw, &sha) != nil || !headSHA.MatchString(sha) {
		return nil, false
	}
	out, err := json.Marshal(map[string]string{"expected_head_sha": sha})
	return out, err == nil
}
