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

// CI restarts let an agent bring its own pull request's branch up to date with
// the base (PUT .../pulls/{n}/update-branch) and run a workflow run again
// (POST .../actions/runs/{id}/rerun and /rerun-failed-jobs), instead of pushing
// an empty commit to start CI again. Each acts only on a branch the pool could
// push to itself, so it grants nothing a push does not.

// restartEvents are the workflow run events a rerun may repeat: a run GitHub
// started for a push to the branch, or for a pull request from it. A
// schedule, a dispatch, pull_request_target or workflow_run carries other
// trust and is never run again by an agent; a run of the default branch is
// refused by its branch.
var restartEvents = map[string]bool{"push": true, "pull_request": true}

// headSHA is a full commit ID, SHA-1 or SHA-256.
var headSHA = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)

// restartInScope reads what a CI restart acts on, with the request's
// one-repository token, and returns its head branch for the audit row. ok is
// true only when that branch is in this repository (never a fork) under
// api.HeadPrefixes, the pool's push prefixes, and, for a workflow run, GitHub
// started the run for a push or a pull request from that branch. Any failed
// read refuses, and nothing read here is kept past this request.
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

// restartOutcome names a refused CI restart in the audit trail.
func restartOutcome(route string) string {
	if route == "update-branch" {
		return "pull_request_target"
	}
	return "run_target"
}

// restartBody rebuilds a CI restart's body: none, or an empty JSON object; a
// branch update may also carry expected_head_sha, a full commit ID, so GitHub
// updates the branch only if its head has not moved. Anything else, such as
// enable_debug_logging on a rerun, is refused.
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
