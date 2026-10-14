# Git adapter

The git adapter lets a worker clone, fetch and push over HTTPS without ever holding a GitHub credential. The worker runs ordinary git through the broker with no token. The broker checks that the repository is in the catalog for the worker's pool, and that a push is allowed. It then adds a short-lived GitHub App installation token minted for that one repository and records the call in the signed audit trail. GitHub's branch protection still applies to every push.

## Catalog entry

A git entry in `AGENT_VAULT_HTTP_CATALOG_FILE` lists repositories, not paths:

```json
{"name": "github", "host": "github.com", "kind": "git", "pools": ["<pool agent ID>"],
 "git": {"appID": 0, "installationID": 0, "repos": [
   {"repo": "example-org/example-app", "access": "write", "refPrefixes": ["refs/heads/cursor/"]},
   {"repo": "example-org/docs", "access": "read"}]}}
```

| Field | Rule |
| --- | --- |
| `repos[].access` | `read` allows clone and fetch. `write` also allows push. |
| `maxRequestBytes` | Default 1 GiB, the largest push accepted. Fetch negotiation may be gzip-compressed; it passes through unchanged. |
| `repos[].refPrefixes` | Optional, write only. A push that would create, update or delete any ref outside these prefixes is refused before it reaches GitHub. Push certificates are refused when prefixes are set. |
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

## Opening pull requests (GitHub REST)

A `github-api` entry lets agents work with pull requests in listed repositories, doing only the operations each repository lists, and never review, approve, merge or push through the API:

```json
{"name": "github-api", "host": "api.github.com", "kind": "github-api", "pools": ["<pool agent ID>"],
 "git": {"appID": 0, "installationID": 0, "repos": [
   {"repo": "example-org/example-repo", "access": "write"},
   {"repo": "example-org/example-service", "access": "write",
    "operations": ["pr.read", "pr.list", "pr.comment", "pr.edit", "pr.label", "pr.ready", "actions.read"],
    "pullRequestPrefixes": ["factory/"], "labels": ["preview"]}]}}
```

`operations` comes from this vocabulary. A repository that lists none gets `pr.open`, `pr.read` and `pr.comment`. Paths are under `/repos/{owner}/{repo}`:

| Operation | Routes | Token scope |
|---|---|---|
| `pr.open` | `POST /pulls`, from a branch under the pool's own push prefixes (its `git` entry's `refPrefixes`) | `pull_requests: write`, `contents: read` |
| `pr.read` | `GET /pulls/{n}` | same |
| `pr.list` | `GET /pulls` (query `state`, `head`, `base`, `sort`, `direction`, `page`, `per_page`), `GET /issues/{n}/comments` (query `since`, `page`, `per_page`) | same |
| `pr.comment` | `POST /issues/{n}/comments` and `POST .../comments/{id}/replies` with `{"body": ...}` only; `POST /pulls/{n}/comments` with `body` plus `commit_id`, `path`, `line`, `side`, `start_line`, `start_side`, `subject_type` or `position` (never `in_reply_to`); on a pull request in reach | same |
| `pr.edit` | `PATCH /pulls/{n}` with `{"body": ...}` only, on a pull request in reach (never its state, base or title); `PATCH /issues/comments/{id}` on a comment the App itself made there | same |
| `pr.label` | `POST /issues/{n}/labels` on a pull request in reach, with only the repository's `labels` | same |
| `pr.ready` | `POST /pulls/{n}/ready` marks a draft in reach ready. Not a GitHub REST route: GitHub does this only through GraphQL, so the broker sends that one mutation | same |
| `dispatch` | `POST /dispatches` with one of the repository's `dispatchEvents` and an optional `client_payload` object. GitHub runs the matching workflows from the default branch | `contents: write` |
| `actions.read` | Workflow runs, jobs, logs and artifacts. For a log or artifact download the broker follows GitHub's redirect to its signed download host itself, without the token; the broker's network policy must allow those hosts | `actions: read` |
| `deployments.read` | Deployments and their statuses | `deployments: read` |

A pull request is in reach when its head is a branch of the same repository under the pool's own push prefixes, or under the repository's `pullRequestPrefixes` (branch names ending in `/`, for pull requests another agent or a person opened). `labels` come only with `pr.label` and `dispatchEvents` only with `dispatch`; `pullRequestPrefixes` need an operation that acts on an existing pull request. Any other path, method or query key is refused. Each token is minted for one repository with only the scope its operation needs, and always `metadata: read`. A write body is JSON, limited to 1 MiB, and GitHub receives it rebuilt from the checked fields; a placeholder anywhere in it is refused. The worker sends no token, or the placeholder `__vault_GITHUB_TOKEN__`, so `gh api` works with `GH_TOKEN=__vault_GITHUB_TOKEN__`. Other `gh` commands use GraphQL and are refused. A worker's own token is refused.

The broker checks each App installation's repositories against the catalog (`AGENT_VAULT_GITHUB_APP_SCOPE`). An installation that also reaches a repository the catalog does not list, or every repository, is reported in a `github app installation scope` log line; the listed repositories keep their tokens, and in `refuse` mode (the default) no token is ever minted for an unlisted repository. Only an installation whose repositories cannot be read stops its tokens in `refuse` mode, until a check succeeds (retried after 30 seconds). `warn` reports and serves either way.
