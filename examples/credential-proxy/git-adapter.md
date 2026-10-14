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
- Open risk: the Cursor README says runs fail to clone without the minting toggle. How Cursor's worker applies its token is not visible in our repositories, so confirm a run clones with the toggle off before relying on this.

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
| `graphql` | `POST /graphql`, for `gh pr` commands: opt-in, and each field still needs its own operation (below). With it, `pr.read` also covers a pull request's comments, reviews and review threads | `pull_requests: write` only |
| `dispatch` | `POST /dispatches` with one of the repository's `dispatchEvents` and an optional `client_payload` object. GitHub runs the matching workflows from the default branch | `contents: write` |
| `actions.read` | Workflow runs, jobs, logs and artifacts. For a log or artifact download the broker follows GitHub's redirect to its signed download host itself, without the token; the broker's network policy must allow those hosts | `actions: read` |
| `deployments.read` | Deployments and their statuses | `deployments: read` |

A pull request is in reach when its head is a branch of the same repository under the pool's own push prefixes, or under the repository's `pullRequestPrefixes` (branch names ending in `/`, for pull requests another agent or a person opened). `labels` come only with `pr.label` and `dispatchEvents` only with `dispatch`; `pullRequestPrefixes` need an operation that acts on an existing pull request. Any other path, method or query key is refused. Each REST token is minted for one repository with only the scope its operation needs, and always `metadata: read` (GraphQL tokens: below). A write body is JSON, limited to 1 MiB, and GitHub receives it rebuilt from the checked fields; a placeholder anywhere in it is refused. The worker sends no token, or the placeholder `__vault_GITHUB_TOKEN__`, so `gh api` works with `GH_TOKEN=__vault_GITHUB_TOKEN__`. A worker's own token is refused.

### GraphQL (`gh pr` commands)

`POST /graphql` on a `github-api` host is served only for repositories that list the `graphql` operation, so an entry written for REST does not widen when the broker starts serving GraphQL. Each request is checked against the same operations; nothing passes through. The broker parses each request, maps every top-level field or mutation to an operation, and sends GitHub the parsed document printed again with its variables re-encoded, so GitHub runs exactly what was checked. The mapping covers what gh 2.89.0 sends for `gh pr view`, `list`, `status`, `checks`, `comment`, `edit --body`, `edit --add-label` and `ready` (`gh pr diff` is REST):

| GraphQL | Operation |
|---|---|
| `repository(owner, name) { pullRequest }`, `node(id) { ... on PullRequest }` | `pr.read` |
| `repository(owner, name) { pullRequests }` or `{ defaultBranchRef }`, `search(query: "repo:owner/name ...", type: ISSUE)` | `pr.list` |
| `repository(owner, name) { labels }` (gh looks up a label's ID) | `pr.label` |
| `addComment` | `pr.comment` |
| `updatePullRequest`, with `body` only | `pr.edit` |
| `addLabelsToLabelable`, with labels from `labels` only (at most 99) | `pr.label` |
| `markPullRequestReadyForReview` | `pr.ready` |

Every query also needs `pr.read`, and so does every mutation whose payload selects more than `__typename` or `clientMutationId`: below a mapped field any selection is allowed, and pull requests can be read from almost anywhere (a label's or a commit's pull requests, a comment's subject). So over GraphQL, `pr.read` reads a pull request with its comments, reviews and review threads (REST keeps comment listing under `pr.list`); that is the authority a repository grants by listing `graphql`. GraphQL tokens are minted for the one repository with `pull_requests: write` and no `contents`, so nested fields cannot read files, history or another private repository; those take a `git` entry. The main fields that read files (`object`, `file`, `tree`, `entries`, `readme`, the contributing guidelines, code of conduct and issue and pull request templates, a review comment's `diffHunk`, and the `Blob`, `Tree` and `TreeEntry` types) are also refused at any depth, as defense in depth; the token is the control. One request reaches exactly one listed repository.

What works today: `gh pr list`, `gh pr view --json` without `statusCheckRollup`, `comment`, `edit --body`, `edit --add-label` and `ready`. Default `gh pr view`, `gh pr status` and `gh pr checks` read check status (`statusCheckRollup`), which needs `checks: read` and `statuses: read` on the token; the broker cannot request those yet, GitHub then answers with an error, and gh stops on any GraphQL error. Default `gh pr view` also reads project items, which may fail the same way. Those commands are a follow-up.

Refused: any other top-level field or mutation (merge, review, approve, title, state and base edits, `viewer`, `organization`, `nodes`, and repository fields other than those above), a second mutation, a mutation whose `input` is not a variable, introspection, subscriptions, directives, more than 10 aliases, a selection deeper than 20 or wider than 1,000 fields once fragments are expanded, `first` or `last` above 100, more than 2,000 requests by GitHub's own cost estimate (gh's largest query is about 210; GitHub charges a point per 100 against the installation's hourly budget, which every pool shares), and a document over 64 KiB. A search must name exactly one `repo:` and no `org:`, `user:`, `owner:`, negated or grouped qualifier. gh's pull request feature detection (`__type(name) { fields(includeDeprecated: true) { name } }` for three types) is answered by the broker and never reaches GitHub.

A mutation names its pull request (and labels) by node ID, which does not say which repository it is in. Before any lookup the broker keeps only the pool's repositories whose entries pass authorization, and applies the rate limit. A current GitHub node ID carries its repository's database ID; the broker uses that only to choose which repository's token to ask with, then asks GitHub what each node is (`nodes(ids)`, with that one repository's token, so a node elsewhere comes back empty). The pull request must be in that repository with its head in reach, exactly as for a REST write, and each label must be one of the repository's `labels`. A lookup GitHub does not answer refuses the request with `503 target_lookup`; one repository that cannot be read does not stop the others. Answers are kept for five minutes (repository IDs for an hour) in bounded caches, so a renamed label keeps its old name for up to five minutes. The broker asks GitHub for current IDs on every request it relays (`X-Github-Next-Global-ID: 1`), so gh never holds an older ID that names no repository; such an ID is refused. Audit rows carry the same binding as REST (`github-api/example-org/example-repo`), so anything matching on it sees GraphQL traffic too.

The broker checks each App installation's repositories against the catalog (`AGENT_VAULT_GITHUB_APP_SCOPE`). An installation that also reaches a repository the catalog does not list, or every repository, is reported in a `github app installation scope` log line; the listed repositories keep their tokens, and in `refuse` mode (the default) no token is ever minted for an unlisted repository. Only an installation whose repositories cannot be read stops its tokens in `refuse` mode, until a check succeeds (retried after 30 seconds). `warn` reports and serves either way.
