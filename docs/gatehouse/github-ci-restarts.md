# Restarting CI on an agent's own branch

An agent whose pull request fell behind its base branch, or whose CI run failed for a reason outside its change, used to push an empty commit to start CI again. That leaves noise in the history and runs every workflow, not just the one that failed. A `github-api` catalog entry can now let agents do the two things a person would do instead: update the pull request's branch from its base, and run a workflow run again. Both are off unless a repository opts in, and both act only on a branch the agent could already push to. A rerun keeps the original run's actor, so it can repeat a run a person started on that branch (see Limits).

## Turning it on

Add the operations to a repository in a `github-api` entry. The pool also needs a `git` entry for the same repository, on the git host that matches the API host (`github.com` for `api.github.com`), with write access and branch push prefixes for the pool, shared (`refPrefixes`) or its own (`poolRefPrefixes`):

```json
{"name": "github-api", "host": "api.github.com", "kind": "github-api", "pools": ["<pool agent ID>"],
 "git": {"appID": 0, "installationID": 0, "repos": [
   {"repo": "example-org/example-repo", "access": "write",
    "operations": ["pr.open", "pr.read", "pr.comment", "actions.read",
                   "pr.update_branch", "actions.rerun", "actions.rerun_failed"]}]}}

{"name": "github", "host": "github.com", "kind": "git", "pools": ["<pool agent ID>"],
 "git": {"appID": 0, "installationID": 0, "repos": [
   {"repo": "example-org/example-repo", "access": "write", "refPrefixes": ["refs/heads/agent/"]}]}}
```

| Operation | Route (under `/repos/{owner}/{repo}`) | Token scope |
|---|---|---|
| `pr.update_branch` | `PUT /pulls/{n}/update-branch`, with no body, `{}`, or `{"expected_head_sha": "<full commit ID>"}` | `pull_requests: write`, `contents: write` |
| `actions.rerun` | `POST /actions/runs/{id}/rerun`, with no body or `{}` | `actions: write` |
| `actions.rerun_failed` | `POST /actions/runs/{id}/rerun-failed-jobs`, with no body or `{}` | `actions: write` |

Without the opt-in, or without a `git` entry that lets the pool push to at least one branch prefix (`refs/heads/...`), shared or its own, the routes do not exist and are refused as `unlisted`. A `git` entry with no prefixes, only tag prefixes, or `refs/heads/` alone (every branch) gives no branch prefixes, so it enables nothing.

`gh run rerun <id>` and `gh run rerun <id> --failed` use these routes; they also read the run and its workflow first, which needs `actions.read`. `gh api -X PUT repos/<owner>/<repo>/pulls/<n>/update-branch` updates a branch. `gh pr update-branch` uses GraphQL and is not served by this route.

## What the broker checks

Every request is checked the same way, with nothing kept between requests:

1. The route is listed for the repository and the pool, and the requester passes the `github-api` entry's authorization and also the `git` entry's (its tier and groups), as a push would.
2. The broker mints a token for that one repository with only the scope above, and reads the target with it:
   - **Branch update:** the pull request. Its head must be a branch of this repository (never a fork) under the pool's push prefixes in the `git` entry: the shared `refPrefixes` and the pool's own `poolRefPrefixes`, never another pool's, and a `{requester}` prefix only as the requester's own (see "Each requester's own branches" in `docs/gatehouse/git-adapter.md`). The repository's `pullRequestPrefixes` and `poolPullRequestPrefixes` do not count here: they let a pool comment on pull requests other agents or people opened, not write to their branches.
   - **Rerun:** the workflow run. GitHub must have started it for a `push` or a `pull_request` event, in this repository, from a head branch of this repository under the pool's push prefixes. A run of a branch outside the prefixes, such as the default branch (a deploy, for example), a scheduled or dispatched run, `pull_request_target`, `workflow_run`, and any run from a fork are refused.
3. Any failed read (GitHub unreachable, an error status, a body that does not parse) refuses the request. The broker fails closed and never retries on the agent's behalf.
4. GitHub receives the request rebuilt from the checked fields. A rerun's `enable_debug_logging` and any other field are refused.

A refusal is `403` with outcome `pull_request_target` (branch update) or `run_target` (rerun). A body the broker does not accept is `400 request_shape`.

## Audit

Each request's rows name the operation (`pr.update_branch`, `actions.rerun` or `actions.rerun_failed`) and carry `branch`: the head branch GitHub reported for the pull request or run, admitted or refused, or `invalid` when it is not a plain name. A refused rerun of a default branch run records `branch: main`, for example. The field is new in audit `macVersion` 7 (see the signed audit guide).

## GitHub App permissions

The App and each installation that serves these repositories must hold `actions: write` for reruns, and `contents: write` and `pull_requests: write` for branch updates; without them only these routes fail (`503 token_unavailable`). The broker's installation check reports an installation holding `actions: write` unless some repository in the catalog opts into a rerun.

## Limits

- **Scale.** Each request costs one extra GitHub read (the pull request or run) before the write, against the installation's hourly API budget, which every pool on that installation shares. Nothing is cached, so the cost grows with restart requests, not with the number of agents. As for every `github-api` route, nothing limits requests per installation: the broker's proxy rate limit is one setting for all proxied traffic, counted per agent and entry, and one agent's allowance is far above an installation's budget. If restarts crowd the budget, the fix is a per-installation limit on `github-api` writes, or spreading pools across App installations, not a cache.
- **Run actor.** GitHub runs a rerun with the privileges of the actor who started the original run, not of whoever asked for the rerun. A run a person started on an agent branch (by pushing a fix-up to it, for example) runs again as that person, so a workflow step gated on `github.actor` or on the actor's repository permission sees the person, which no push by the pool can produce. It is the same commit and workflow file, and environment approvals still apply. The broker does not check the run's actor.
- **Workflow files.** GitHub may refuse an update that brings in changes under `.github/workflows` unless the token also holds the `workflows` permission, which the broker never requests; the agent then sees GitHub's answer.
- **Tags.** GitHub's run object names a tag push's tag in `head_branch` and does not say whether it was a tag. A tag whose name falls under a branch push prefix would pass the branch check. Keep agent branch prefixes out of tag names.
- **Not served.** Rerunning one job (`POST /actions/jobs/{id}/rerun`), cancelling a run, and dispatching a workflow by file are unlisted.
