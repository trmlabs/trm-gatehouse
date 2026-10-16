# Git adapter

The git adapter lets a worker clone, fetch and push over HTTPS without ever holding a GitHub credential. The worker runs ordinary git through the broker with no token. The broker checks that the repository is in the catalog for the worker's pool, and that a push is allowed. It then adds a short-lived GitHub App installation token minted for that one repository and records the call in the signed audit trail. GitHub's branch protection still applies to every push.

## Catalog entry

A git entry in `AGENT_VAULT_HTTP_CATALOG_FILE` lists repositories, not paths:

```json
{"name": "github", "host": "github.com", "kind": "git", "pools": ["<pool agent ID>"],
 "git": {"appID": 0, "installationID": 0, "repos": [
   {"repo": "trmlabs/trm-b2b", "access": "write", "refPrefixes": ["refs/heads/cursor/"]},
   {"repo": "trmlabs/docs", "access": "read"}]}}
```

| Field | Rule |
| --- | --- |
| `repos[].access` | `read` allows clone and fetch. `write` also allows push. |
| `maxRequestBytes` | Default 1 GiB, the largest push accepted. Fetch negotiation may be gzip-compressed; it passes through unchanged. |
| `repos[].refPrefixes` | Optional, write only. A push that would create, update or delete any ref outside these prefixes is refused before it reaches GitHub. Push certificates are refused when prefixes are set. They apply to every pool of the entry. |
| `repos[].poolRefPrefixes` | Optional, write only. Each pool of the entry, mapped to push prefixes of its own, such as `{"pool-a": ["refs/heads/cursor/pool-a/"], "pool-b": ["refs/heads/cursor/pool-b/"]}`. A pool pushes under `refPrefixes` and its own list only. Once a repository lists either field, a pool with neither may clone and fetch but never push. The map names at least one pool (an empty map or `null` is refused), each list holds distinct prefixes, and no pool's prefix may start, or be started by, another pool's or a shared one (ignoring case), so one entry serves many pools without any of them pushing to another's branches. For pools kept apart, use only per-pool lists: the shared ones reach every pool of the entry. |
| `appID`, `installationID` | The GitHub App installation that mints tokens. |

Only git's three smart-HTTP endpoints are served: `info/refs` with one `service` parameter, `git-upload-pack` and `git-receive-pack`. Git LFS, the REST API and every other path are refused. A host cannot mix git and header entries.

## Tokens

For each request the broker uses a token scoped to exactly one repository, with `metadata: read` plus `contents: read`, or `contents: write` only for a push to a `write` binding. A token GitHub returns with any wider scope is revoked and refused. Tokens are reused until ten minutes before their one-hour expiry. One mint is shared across concurrent requests, and a failed mint is not retried for five seconds. A 401 or 403 from GitHub drops and revokes the token, at most once per repository every 30 seconds. A catalog change that removes a repository or narrows its access revokes the tokens it no longer grants, and a stopping broker revokes every token it holds. The worker sends no `Authorization` header; a request that carries one is refused. Responses that echo the token in any encoding are cut off.

## The App key

Import the App's private key into Vault Transit, so it never leaves Vault, and give the broker only:

```hcl
path "transit/sign/github-app/sha2-256" { capabilities = ["update"] }
```

Set `AGENT_VAULT_GITHUB_APP_TRANSIT_KEY=github-app` (mount `AGENT_VAULT_GITHUB_APP_TRANSIT_MOUNT`, default `transit`). `AGENT_VAULT_GITHUB_API_URL` overrides `https://api.github.com`, for GitHub Enterprise Server or a test server. The fallback, `AGENT_VAULT_GITHUB_APP_KV_PATH`, reads a PEM from field `private_key` on the `gatehouse` KV mount into broker memory for each signature. Creating the App, and choosing its permissions and installation, is a separate decision.

## Branch protection

The App acts as itself on GitHub, so branch protection and rulesets govern its pushes like any other actor's. Never add the App to a bypass list. Protect the default and release branches, and keep `refPrefixes` to agent branch names such as `refs/heads/cursor/`, so the broker refuses a push to a protected branch before GitHub has to.

## Worker setup (Cursor)

- Turn off `--mint-github-token` and the dashboard's GitHub token minting, so the worker gets no token.
- Route `github.com` through the worker's sidecar (`HTTPS_PROXY`) and trust the broker CA (`GIT_SSL_CAINFO` or `http.sslCAInfo`).
- Use `https://github.com/<owner>/<repo>.git` remotes, and remove any credential helper, `http.extraHeader` or `url.<token URL>.insteadOf` rewrite.
- Open risk: the Cursor README says runs fail to clone without the minting toggle. How Cursor's worker applies its token is not visible in our repositories, so confirm a run clones with the toggle off before relying on this.

## Opening pull requests (GitHub REST)

A `github-api` entry lets agents work with pull requests in listed repositories, doing only the operations each repository lists. It never reviews, approves or merges a pull request, and never pushes through the API except for the opt-in `pr.update_branch`, which merges the base branch into a head under the pool's own push prefixes (see `docs/gatehouse/github-ci-restarts.md`):

```json
{"name": "github-api", "host": "api.github.com", "kind": "github-api", "pools": ["<pool agent ID>"],
 "git": {"appID": 0, "installationID": 0, "repos": [
   {"repo": "example-org/example-repo", "access": "write"},
   {"repo": "example-org/example-service", "access": "write",
    "operations": ["pr.read", "pr.list", "pr.comment", "pr.edit", "pr.label", "pr.ready", "actions.read"],
    "pullRequestPrefixes": ["factory/"], "labels": ["preview"]}]}}
```

Responses, including log and artifact downloads, stream to the worker through the token screen. One longer than the entry's `maxResponseBytes` (default 4 GiB, at most 8 GiB) is cut off and audited as `response_too_large`.

`operations` comes from this vocabulary. A repository that lists none gets `pr.open`, `pr.read` and `pr.comment`. Paths are under `/repos/{owner}/{repo}`:

| Operation | Routes | Token scope |
|---|---|---|
| `pr.open` | `POST /pulls`, from a branch under the pool's own push prefixes (its `git` entry's `refPrefixes` and the pool's `poolRefPrefixes`) | `pull_requests: write`, `contents: read` |
| `pr.read` | `GET /pulls/{n}`; and, only for a pool whose `git` entry can clone the repository (they return code), `GET /pulls/{n}/files` and `GET /compare/{base}...{head}` (two refs with no slash; query `page`, `per_page`). The broker authorizes the requester against that `git` entry too, so a code read never reaches a person the clone would refuse | same |
| `pr.list` | `GET /pulls` (query `state`, `head`, `base`, `sort`, `direction`, `page`, `per_page`), `GET /issues/{n}/comments` (query `since`, `page`, `per_page`) | same |
| `pr.comment` | `POST /issues/{n}/comments` and `POST .../comments/{id}/replies` with `{"body": ...}` only; `POST /pulls/{n}/comments` with `body` plus `commit_id`, `path`, `line`, `side`, `start_line`, `start_side`, `subject_type` or `position` (never `in_reply_to`); on a pull request in reach | same |
| `pr.edit` | `PATCH /pulls/{n}` with `{"body": ...}` only, on a pull request in reach (never its state, base or title); `PATCH /issues/comments/{id}` on a comment the App itself made there | same |
| `pr.label` | `POST /issues/{n}/labels` on a pull request in reach, with only the repository's `labels` | same |
| `pr.ready` | `POST /pulls/{n}/ready` marks a draft in reach ready. Not a GitHub REST route: GitHub does this only through GraphQL, so the broker sends that one mutation | `pull_requests: write`, `contents: write` |
| `dispatch` | `POST /dispatches` with one of the repository's `dispatchEvents` and an optional `client_payload` object. GitHub runs the matching workflows from the default branch | `contents: write` |
| `actions.read` | Workflows, workflow runs, jobs, logs and artifacts (what `gh run list`, `view`, `watch` and `download` read). For a log or artifact download the broker follows GitHub's redirect to its signed download host itself, without the token; the broker's network policy must allow those hosts. Also a commit's statuses (`GET /commits/{sha}/status` and `/statuses`) and check runs (`GET /commits/{sha}/check-runs`, `GET /check-runs/{id}` and its annotations), by commit SHA only, each with a token holding only that permission | `actions: read`; `statuses: read`; `checks: read` |
| `deployments.read` | Deployments and their statuses | `deployments: read` |
| `pr.update_branch` | `PUT /pulls/{n}/update-branch` on a pull request whose head is under the pool's own push prefixes (never `pullRequestPrefixes`); opt-in, see `docs/gatehouse/github-ci-restarts.md` | `pull_requests: write`, `contents: write` |
| `actions.rerun`, `actions.rerun_failed` | `POST /actions/runs/{id}/rerun` and `/rerun-failed-jobs` on a `push` or `pull_request` run from a branch under the pool's own push prefixes; opt-in, see `docs/gatehouse/github-ci-restarts.md` | `actions: write` |

The App and each installation must hold `checks: read` and `statuses: read` for the check run and commit status routes, and `actions: read` and `deployments: read` for theirs; without a permission only its routes fail (503 `token_unavailable`). `pr.ready`'s token holds `contents: write` as well as `pull_requests: write`, because GitHub refuses the ready mutation without it; the broker builds that mutation itself and the worker never sees the token. GitHub reports a refused mutation inside an HTTP 200, so the broker reads the whole answer, and when it does not show the pull request ready the worker gets 502 with `{"code": "graphql_error"}` and a `reason`, and the audit row records `graphql_error`.

A pull request is in reach when its head is a branch of the same repository under the pool's own push prefixes (the shared `refPrefixes` and its `poolRefPrefixes`), or under the repository's `pullRequestPrefixes` (branch names ending in `/`, for pull requests another agent or a person opened), which apply to every pool of the entry, or under the pool's own list in `poolPullRequestPrefixes` (pool to branch prefixes shaped like `pullRequestPrefixes`, with the same pool and overlap rules as `poolRefPrefixes`). No pull request prefix may start, or be started by, a push prefix in the `git` entry a clone of the repository uses (the API host without `api.`, port 443) that a pool it reaches cannot push to, compared as refs and ignoring case. A pool's own pull request list reaches that pool only, and the shared list every pool of the `github-api` entry. A pool's own push prefixes are that pool's alone, and the shared `refPrefixes` belong to every pool of the `git` entry, so a `github-api` pool the `git` entry does not grant may reach none of them. A write repository with neither list lets every pool of the `git` entry push any branch, so it counts as a shared push prefix of `refs/heads/`: a `github-api` pool that entry does not grant may have no pull request prefix there. Otherwise a catalog file and the validator refuse the catalog, and a catalog read from Vault leaves both entries out, as for any other conflict between entries. Reads, lists, repository dispatch and Actions reads are held to no prefix: they stay per repository for every pool of the entry. `labels` come only with `pr.label` and `dispatchEvents` only with `dispatch`; `pullRequestPrefixes` and `poolPullRequestPrefixes` need an operation that acts on an existing pull request. Any other path, method or query key is refused. Each token is minted for one repository with only the scope its operation needs, and always `metadata: read`. A write body is JSON, limited to 1 MiB, and GitHub receives it rebuilt from the checked fields; a placeholder anywhere in it is refused. The worker sends no token, or the placeholder `__vault_GITHUB_TOKEN__`, so `gh api` works with `GH_TOKEN=__vault_GITHUB_TOKEN__`. Other `gh` commands use GraphQL and are refused as `unlisted`; when the request is a mutation a route here serves, the refusal's next step names that route, such as `POST /repos/{owner}/{repo}/pulls/{n}/ready` for `gh pr ready`. A worker's own token is refused.

The broker checks each App installation's repositories against the catalog (`AGENT_VAULT_GITHUB_APP_SCOPE`). An installation that also reaches a repository the catalog does not list, or every repository, is reported in a `github app installation scope` log line; the listed repositories keep their tokens, and in `refuse` mode (the default) no token is ever minted for an unlisted repository. Only an installation whose repositories cannot be read stops its tokens in `refuse` mode, until a check succeeds (retried after 30 seconds). `warn` reports and serves either way.
