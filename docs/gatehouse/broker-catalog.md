# Broker catalog

The broker catalog is the one list of everything workers may reach through the broker: databases, HTTP services, git repositories and the GitHub pull request API, each granted to named worker pools. Adding a destination is one entry in one reviewed file. Your deployment pipeline writes the catalog to Vault, and the broker picks up the new version within 30 seconds, with no restart.

## Where it lives and how it loads

- **Source:** a YAML file in a reviewed repository, ideally next to the Vault roles and key paths its entries use, so one pull request creates both. Validate it in CI and write it as JSON to a KV version 2 secret, field `catalog`.
- **Broker:** `AGENT_VAULT_CATALOG_VAULT_PATH=<mount>/<path>`, for example `gatehouse/agents-catalog`. The broker polls every 30 seconds. A new version replaces the old one atomically, and the next request or connection uses it. See [When a catalog is bad or Vault is down](#when-a-catalog-is-bad-or-vault-is-down) for what happens to a bad entry and to a start without Vault.
- **One secret per entry:** `AGENT_VAULT_CATALOG_VAULT_PREFIX=<mount>/<prefix>` reads the same catalog split so no single secret holds all of it, which is how a catalog grows past Vault's size limit for one secret. The layout is below. Set this or `AGENT_VAULT_CATALOG_VAULT_PATH`, never both; the single document stays accepted while catalogs move.
- **Fixed file:** `AGENT_VAULT_HTTP_CATALOG_FILE` still works for local fixtures. It is read once at start.

## Format

```yaml
pools:
  - {name: example-agents, namespace: example-agents, serviceAccount: example-worker}
entries:
  - name: appdb                       # the database name a worker connects to
    kind: postgres
    host: db.example.com
    pools: [example-agents]
    postgres: {database: app, mount: database, role: staging.us.example.app-readonly}
  - name: search-api
    host: api.example.com
    pathPrefixes: [/search]
    methods: [GET]
    header: X-Api-Key
    placeholder: __vault_SEARCH_KEY__
    key: {mount: gatehouse, path: vendors/search-api, field: key}
    pools: [example-agents]
```

Entry kinds: `postgres` (port 5432 by default; `sslmode` is `verify-full`, the only mode the catalog accepts; `access` is `read` by default and must be `write` exactly for a `-readwrite` role; the broker needs `AGENT_VAULT_CATALOG_ENVIRONMENT`, and `validate` needs `--environment`, such as `staging`, and every role must then be `staging.<region>.<cluster>.<name>-readonly` or `-readwrite`, or that name prefixed `gatehouse-`; `AGENT_VAULT_CATALOG_ROLE_PATTERN` (`validate --role-pattern`) replaces that naming rule with a regular expression for the role before its suffix, which must contain `{environment}`, and a role must still be a plain Vault name ending in `-readonly` or `-readwrite`; with no environment set, a catalog with any `postgres` entry is refused), `memgraph` (port 7687 by default; `access` is `read` by default or `write`, through one broker login in Vault; see the graph databases guide), HTTP (no kind; see the HTTP header adapter guide), `git` and `github-api` (see the git adapter guide). When `pools` is defined, an entry can grant only defined pool names. Grants match the scope's pool, which the broker's attestation sets from the worker Pod's approved controller. The agent ID stays the broker's own identifier for revocation, Vault roles, cleanup and audit. A scope with no pool matches no grant. Audit rows carry both `pool` and `agent`.

## External pools

A pool with `ceiling: external` is below T0: its workers serve people outside the company, so it reaches nothing. The catalog refuses any entry that grants it, and an external pool takes no verified identity. It exists so a harness for customer-facing sandboxes can be declared before entries can be scoped to a tenant.

## Harness profiles

A harness is one kind of agent runtime: Cursor workers, Claude sessions, agent-sandbox. Each is one `harnesses` entry that answers three questions: how its agents prove who they are, how they reach the broker, and whether access is decided for the pool, for the person, or for the Automation that started the run. A new runtime needs a new entry, and code only if it brings a new identity kind. A harness carries the identity kind, not the pool: a pool that decides per Automation may have its Kubernetes harness and, beside it, one [static agent token](agent-tokens.md) harness, so adding a platform to that pool is one catalog edit.

```yaml
harnesses:
  - name: cursor
    trustDomain: {issuer: https://container.googleapis.com/v1/projects/P/locations/L/clusters/C, keys: in-cluster, audience: gatehouse}
    identity: {kind: pod-token, ownerKind: ReplicaSet, namespaces: [example-agents], imageDigests: [sha256:...]}
    path: {kind: sidecar}
    authorization: {mode: pool, poolName: example-agents}
    client: {proxyEnv: GATEHOUSE_HTTPS_PROXY, caFileEnv: GATEHOUSE_CA_FILE, caSpkiEnv: GATEHOUSE_CA_SPKI}
```

| Field | Values |
|---|---|
| `trustDomain` | `issuer` (HTTPS), `keys` (`in-cluster`: the broker's own cluster API; `remote`: the issuer's published keys; `pinned`: the issuer's public keys held in the broker's identity configuration, no fetch), `audience` |
| `identity.kind` | `pod-token` (the Pod's own token, live Pod and source address), `session-jwt` (the same, plus a runner session naming the person, pinned to its first Pod), `proxy-attested` (a shared proxy in the agent's cluster checks the Pod and presents its own token), `static-token` (a per-agent bearer token with no Kubernetes proof; see [Agent tokens](agent-tokens.md)) |
| `identity` | `ownerKind` (the controller kind that must own the agent Pod), `namespaces`, `imageDigests`, optional `imagePrefix` (proxy-attested only: a repository or tenant path ending in `/` under `AGENT_VAULT_IMAGE_REGISTRY`; `imageDigests` may then be empty or list platform containers; two harnesses may not overlap), optional `requester` (`session-jwt` for Claude, `cursor-oidc` for Cursor, `pod-annotation` for agent-sandbox in person mode, or `signed-assertion`) |
| `path` | `kind` (`sidecar`, `shared-proxy`, or `direct` for `static-token`), `crossCluster` (the agents run in another cluster than the broker; see [Sidecars in another cluster](#sidecars-in-another-cluster)) |
| `authorization` | `mode` (`pool`, `person` or `automation`), `poolName` |
| `client` | Environment variable names the worker render sets: `proxyEnv` (Gatehouse's proxy URL), `caFileEnv` (its CA file), optional `caSpkiEnv` (the CA's SPKI hash, for a browser launched with a trust flag). Cursor keeps `HTTPS_PROXY` for its own gateway, so it uses the `GATEHOUSE_` names; harnesses that leave the standard names free use `HTTPS_PROXY` and `SSL_CERT_FILE`. Every harness sets `caSpkiEnv` to `GATEHOUSE_CA_SPKI`, because Chromium on Linux trusts only its own certificate store: browsers trust Gatehouse by key hash everywhere, with no `certutil` in the image. The broker does not read these |

Every field is required except `requester`, `crossCluster` and `caSpkiEnv`, and the catalog is refused when an entry is incomplete or contradictory: a `pod-token` harness runs a sidecar and decides for the pool; `session-jwt` decides for the person; `proxy-attested` runs a shared proxy, and decides for the person exactly when its requester is `pod-annotation`; a cross-cluster path uses remote (or pinned) keys, and a sidecar on it is admitted only where the broker reads that cluster's Pods (below); `person` needs a requester. `automation` is a `session-jwt` sidecar with requester `cursor-oidc`. `signed-assertion` is refused until the broker verifies assertions. Once a catalog declares harnesses, each pool belongs to exactly one (except that a pool deciding per Automation may add one `static-token` harness beside its Kubernetes harness), its namespace is listed (a `static-token` harness lists none), and its `identity` agrees with the mode (`claude-session`, `cursor-session` or `attested-person` exactly for `person`, `cursor-automation` exactly for `automation`), and a person pool's requester is its own kind's (`session-jwt` for `claude-session`, `cursor-oidc` for `cursor-session`, `pod-annotation` for `attested-person`). A catalog without harnesses keeps today's behavior: each pool's profile is derived from its `identity`.

### Sidecars in another cluster

A broker serves sidecars in another cluster when its workload identity configuration lists that cluster as a trust domain with `pods`: the cluster's API server, named by host (for GKE, its DNS-based control-plane endpoint), and a credential the broker reads Pods with (`google`, the broker's own Google identity, which needs only permission to get Pods there; or `token-file`, a bearer token file re-read on every call). Pool bindings in that domain then admit the cluster's sidecars as the broker's own cluster's are admitted: the Pod's token verified by the cluster's keys, then its live Pod read on every connection and recheck (UID, controller, images, worker container, deadline and the Cursor run the spawn hook recorded). The connection's source address is not compared with the Pod's, because across clusters it is a load balancer's; the Pod must still be running for its token to admit, and the token's lifetime (at most the domain's `maxTokenLifetimeSeconds`) bounds a replay from anywhere else. A domain without `pods` admits only shared proxies. Sidecars in another cluster connect to the broker's ordinary listeners; the cross-cluster listener stays for shared proxies.

### Who a Claude session names

A `session-jwt` harness verifies the Claude runner's session token (`CLAUDE_CODE_SESSION_ACCESS_TOKEN`, `sk-ant-cc-` prefix) against Anthropic's published keys, as Anthropic's [Verify session identity in self-hosted environments](https://code.claude.com/docs/en/self-hosted-environments-identity) describes: issuer `ccr`, role `session_worker`, the runner pool's `ccpool_` ID in the audience. The creator is in `act`: `act.sub` is `user:<id>` for a person or `agent:<id>` for the organization's service identity, and `act.email` is the person's address when the creating surface recorded one. `act.attested_by` is reserved by Anthropic and not read.

A session names a person only when `act.sub` is `user:<id>` and `act.email` is in a domain listed in `AGENT_VAULT_RUNNER_PERSON_DOMAINS`. The person is that email, which the directory looks up as the Entra user principal name. A session without a recorded email (one dispatched from the CLI can lack it), with an email in another domain, or with no domains configured names no person: it gets T0 entries only, and every entry above T0 is refused. An `agent:` session never names a person. Any other `sk-ant-` token, such as a hosted session's, is refused.

### Who a Cursor run names

A `session-jwt` harness with requester `cursor-oidc` and a `cursor-session` pool verify the Cursor run's identity token, as Cursor's [OIDC tokens](https://cursor.com/docs/cloud-agent/identity) page describes. A self-hosted worker started with `--identity-socket` serves one socket per claimed run, and Cursor fills the token's claims from that run, so code on the worker cannot mint a token for another run or another owner. The sidecar mints the token itself, for each connection, from the one socket under the worker's `<data dir>/identity/` (relay settings `sessionSocketDir` and `sessionAudience`), so the agent never chooses which token is sent. It reuses a token until a minute before it expires; connections that open together share one mint, and a refresh that fails leaves the token in hand to be sent until it expires. No claim, or two sockets, sends nothing. The sidecar logs a failed mint with the socket's status (`cursor_mint_failed`) and the directory turning to no socket or several (`cursor_claim_unavailable`), never a token.

The broker checks the RS256 signature against Cursor's published keys (`https://api.cursor.com/keys`), issuer `https://api.cursor.com`, an audience exactly equal to `AGENT_VAULT_CURSOR_AUDIENCE` (Cursor does not allowlist audiences), `agent_runtime: self_hosted`, a `team_id` in `AGENT_VAULT_CURSOR_TEAM_IDS`, a `cloud_agent_id`, and a lifetime of at most an hour (Cursor's is five minutes). A run names a person only when `sub` is `user:<id>` and `owner_email` is in a domain listed in `AGENT_VAULT_CURSOR_PERSON_DOMAINS`; the person is that email, looked up as the Entra user principal name. A `service_account:` run never names a person. On a `cursor-session` pool every request must name a person, T0 included: a request with no run token is refused (`session_missing`), and so is one whose run names no person, such as a service account's, an owner without a known email or in another domain, or any run when no domains are configured (`no_person`). A run an Automation started is refused too (`automation_on_person_pool`) unless the pool opts in; see [What an Automation's run may use](#what-an-automations-run-may-use). The refusal is that one request's: other Pods, and later requests that carry a good token, are decided on their own. `CURSOR_USER_ID` in the worker's environment is never read: the agent can rewrite it.

To name a person by immutable IDs instead of email, set `AGENT_VAULT_CURSOR_PEOPLE_FILE` to a JSON file of Cursor user ID to Entra object ID, the same map the Cursor runner admits by (`{"<cursor user id>": "<entra object id>"}`; keep the two in agreement). A `user:<id>` run then names a person only when `<id>` is in the map: the person is the mapped object ID, which the directory looks up as an object ID, and `owner_email` and `AGENT_VAULT_CURSOR_PERSON_DOMAINS` are ignored. An unmapped user names no person (`no_person`), so entries above T0 are refused. The audit row's `requester` and a `{requester}` branch segment then hold the object ID, not an email. The file is read once at start: change it, then restart the broker. Startup fails if the file is missing, is not one JSON object, holds an ID that is not plain, an object ID that is not a lower-case GUID, or a duplicate ID or object ID. Unset, owner_email is used as described above.

Any process on a worker can mint a token for that worker's run, and a token copied elsewhere would otherwise still verify. So a token counts only on the Pod the spawn hook created for its run: its `cloud_agent_id` must equal the Pod's `gatehouse.trmlabs.com/cursor-request-id` annotation, which the hook writes from `CURSOR_REQUEST_ID` (the same `bc-` ID; the worker cannot change its own Pod) and the broker reads from the live Pod at each admission. A Pod without that annotation names nobody (`session_run`). Each token is also pinned to the first Pod that presents it, and, since runs on one Pod share its workspace, each Pod to its first run owner (`sub`) for a day: a run by anyone else on that Pod is refused (`session_pod_owner`).

### What an Automation's run may use

A pool with `identity: cursor-automation` (harness mode `automation`) decides each request for the Cursor Automation that started the run, not for the pool or a person. Its access is what the Automation's own grants allow: one `automations` block per Automation lists the entries it may use, and the reviewed change that adds the block is the approval. A new Automation needs no pool, image or deployment.

```yaml
automations:
  - id: <automation_id from the run token>
    name: explorer                 # a label for audit rows
    owner: platform-team           # the accountable team: a group's name or object id
    entries: [tracker, repo]       # entries it may use; each also granted to the pool
    write: [repo]                  # optional: where it may push and change pull requests; [] fetches and reads only
    settings: {API_BASE: https://api.example.com/v1}   # optional: plain configuration for its runs' shells; see below
    subagents: 25                  # optional: how many subagent runs each of its runs may register; absent, none
```

The run token is verified exactly as on a `cursor-session` pool (run, Pod and run-owner pins included). Then every request on the pool, T0 included, must come from an Automation the catalog lists and use an entry listed for it:

| Check | Refusal |
|---|---|
| `source` is `AUTOMATIONS` with an `automation_id`, so a person's run routed here gets nothing, unless the run is a subagent an Automation's run registered (below) | `not_automation` |
| The id is listed | `automation_unlisted` |
| The entry is one the Automation lists, even when the pool is granted it | `automation_not_granted` |
| The entry's tier is within the pool's `ceiling` (the catalog also refuses such a grant at load) | `pool_ceiling` |
| A push, or a GitHub operation that changes something, on a `git` or `github-api` entry the Automation lists when its `write` list does not name it | `automation_read_only` |

A `git` or `github-api` entry gives a pool one write grant: the push prefixes of a `git` repository and the `poolOperations` of a `github-api` repository. `write` is optional and says which Automations get it. A block without the key keeps the pool's grant on every entry it lists, so a broker that reads `write` changes nothing until a catalog sets it. A block with the key, an empty list included, gets exactly the entries it names. On a `git` or `github-api` entry an Automation lists but a `write` list does not name, it fetches and reads only: no push (the `git-receive-pack` advertisement included), and over REST and GraphQL only `pr.read`, `pr.list`, `actions.read`, `deployments.read` and `graphql`. Every other operation is a write and needs the grant, an operation added later included: `pr.open`, `pr.comment`, `pr.edit`, `pr.label`, `pr.ready`, `dispatch`, `pr.update_branch`, `actions.rerun` and `actions.rerun_failed`. A GraphQL read of a repository's labels needs `pr.label`, so it is a write too. A CI restart reaches no further than a push, so it needs `write` on the `git` entry that holds its branch as well as on the `github-api` entry. The refusal is made after the entry's authorization, and its audit row names the Automation. Over git and REST it comes before any token is minted or GitHub asked. A GraphQL request that names a pull request by node ID, where the Automation names some of the entries that could serve it but not the one the pull request is in, is first looked up with a read-only token, and refused once the entry is known. The pool's own prefixes and operations stay the ceiling: `write` never gives an Automation more than its pool has, and a pool that does not name an Automation's entry gives it nothing. Each name in `write` must be one of the Automation's `entries` and a `git` or `github-api` entry, or the catalog refuses the block (a tolerant load drops that Automation, so its runs are refused). A requester that is not an Automation, such as a person on a `cursor-session` pool, is unaffected.

Deploy a broker that reads `write` to every replica before any block carries it. An older broker reading Vault drops a block with a field it does not know, so that Automation is refused entirely. An older broker started on a catalog file, and a catalog validator pinned to an older commit, are stricter: each refuses the whole catalog, and the broker does not start. So repin the validator, and deploy the new broker to anything that reads a catalog file, before a catalog uses `write`. A catalog that sets no `write` behaves the same on either broker, so the deploy changes nothing an Automation may do. Before rolling back to a broker that predates `write`, remove the key from every block, in Vault and in any catalog file, and let every replica load that version (a catalog in Vault is polled every 30 seconds); then repin the validator and the broker. A broker that old drops each block that still has the key, so those Automations are refused until the catalog changes. Without the key every Automation has the pool's grant again, so one that must not push in the meantime should lose its `git` and `github-api` entries in the same version.

Nothing about a person is checked, at any tier: no groups, no account, no directory lookup, so an automation pool needs no directory configured. The person the run token names, if any, is recorded and decides nothing: a run whose token names a service account (`sub` `service_account:`), or a user outside the configured domains, is served the same entries. A token that names neither a user nor a service account is refused (`session_token`). An entry's `requires` groups apply to the person and workload pools that share it, never to an Automation. An allowed request records `t0` at T0 and `automation_granted` above it.

The broker cannot see who edited an Automation or set off its trigger, and the run's person does not limit it, so anyone who can edit or trigger an Automation in Cursor can use its entries. List only what its task needs, and keep editing and triggering with the owning team. To stop an Automation, remove its block, or remove an entry from its list to stop just that one: once every replica loads that version (a catalog in Vault is polled every 30 seconds; a fixed file needs a restart), its runs are refused (`automation_unlisted` or `automation_not_granted`), and an open database session ends at its next recheck.

`owner` names the team accountable for the Automation, for audit rows and alerts: a directory group's name (up to 128 letters, digits, `.`, `_` and `-`, starting with a letter or digit; an audit row holds no space, so a group whose name has one is named by its object id) or object id. The broker does not look it up, and it decides no access. A catalog written before owners named teams may still give a person's lower-case email; it is read as the team's contact and gates nothing.

`runnerGroup` is refused at load: who sets off a run decides nothing, so a group of allowed runners would limit no one.

An Automation's run on a `cursor-session` (person) pool is refused (`automation_on_person_pool`), so by default an Automation is never served a person's access. A pool that names no person, such as `example-agents` above, cannot tell an Automation's run from anyone else's: it serves every run its T0 entries. A run counts as an Automation's when its token's `source` is `AUTOMATIONS` or it carries an `automation_id`; a new automated source that sets neither would be served as its person. A pool opts in to serving them with `automationRunsAsPerson: true` (`cursor-session` pools only; on any other pool the catalog refuses it): an Automation's run there is then served as the person its token names, with every entry that pool grants and that person's groups, not the Automation's list. A person's own run, from the web, Slack or the API, is unaffected.

Every audit row from a Cursor run that reaches the authorization check (one for a matched entry or database) records the token's `source` and `automation`, on any pool and on refusals; on an automation pool, a listed Automation's `automationName` and `automationOwner` (its owning team) too, and `requester` is the person the run's token names, or is absent when it names none. Such a row records `tier` and `decision` (such as `t0`, `automation_granted`, `automation_not_granted` or `pool_ceiling`), and no `groups`, `cacheAgeSec`, `requesterOID` or `requesterDepartment`. Automations are indexed by id at load, so a lookup costs the same at 100,000 as at one. An `id`, `name` and entry names are plain identifiers; `owner` is a plain identifier or a lower-case email. A tolerant load drops an Automation that is invalid, repeats another's id, or names an entry that was dropped, and keeps the rest.

### Plain settings for an Automation's runs

An Automation's runs often need configuration that is not a credential, such as an API's base URL or the ids of its own agents. A vendor's secret sync could deliver it, but it copies every team secret onto the worker, so Gatehouse workers never turn it on. Instead the Automation's block lists `settings`, and its runs get them as environment variables in the agent's shells:

```yaml
automations:
  - id: <automation_id from the run token>
    name: explorer
    owner: platform-team
    entries: [tracker]
    settings:
      API_BASE: https://api.example.com/v1
      AGENT_USER_IDS: explorer-agent
```

The worker's sidecar (relay setting `automationSettings`) asks the broker once the run's identity socket is up, and writes the answer as `export` lines to a file in a directory the worker mounts read-only. The worker points `BASH_ENV` at a loader that reads the file, so every non-interactive bash the agent runs has the settings before its first command. The broker answers `GET /v1/automation-settings` on the listener the sidecar already reaches it on, with the same Pod proof as a CONNECT and the run's token, and resolves the requester exactly as for a request through the proxy: the token must be for the run the live Pod was started for, pinned to that Pod, and the Pod to one run owner. Nothing in the request names an Automation, so a worker reads only its own run's settings. A requester that is not an Automation, on any pool, gets an empty set. Any refusal is a bare 403, with its reason in the audit row. Each answer writes an `automation_settings` audit row naming the settings served, never a value.

Settings are never secrets, and the catalog refuses anything that looks like one. A tolerant load leaves that Automation out, so its runs are refused until the block is fixed:

| Refused | Why |
|---|---|
| A name with `TOKEN`, `KEY`, `SECRET`, `PASSWORD`, `PASSWD`, `CREDENTIAL` or `PRIVATE` in it, in any case | It reads as a credential's. A credential stays in Vault, behind a placeholder |
| A value holding `__vault_`, in any case | A placeholder belongs only in a request through the broker |
| A value shaped like a credential: a PEM block, a GitHub, Slack, AWS or API key, a JWT, or a URL carrying a password | The same |
| A name the shell, the worker's runtime or Gatehouse sets, or one that changes how programs run: `PATH`, `HOME`, `USER`, `SHELL`, `ENV`, `BASH_ENV`, `IFS`, `PS1` to `PS4`, `PROMPT_COMMAND`, `TMPDIR`, `NODE_OPTIONS`, the CA bundle and interpreter path variables, the Go toolchain's (`GOFLAGS`, `GOPROXY`, `GOPRIVATE`, `GONOSUMDB`, `GOINSECURE` and the like), `PERLLIB`, any name ending `_PROXY`, and any name starting `GATEHOUSE_`, `AGENT_VAULT_`, `CURSOR_`, `BASH_`, `LD_`, `DYLD_`, `GIT_`, `SSL_`, `KUBERNETES_`, `PIP_`, `UV_`, `NPM_CONFIG_`, `NODE_TLS_`, `XDG_` or `PYTHON`, in any case | A setting only adds configuration; it never redirects traffic, trust or code |
| A name that is not letters, digits and `_`, starts with a digit or is over 128 characters, or a value with a control character such as a newline | Each setting is one shell variable on one line |
| More than `AGENT_VAULT_CATALOG_SETTINGS_MAX_BYTES` bytes of names and values together (default 65536, at most 1048576; `validate --settings-max-bytes`) | The values become a process's environment |

The sidecar's `automationSettings` takes `file` (absolute, in a directory of its own), `waitSeconds` (default 180, at most 3600) and `refreshSeconds` (default 300, 30 to 86400). The file is replaced whole each time (written beside it, then renamed), so a shell reads the old file or the new one. It exists within `waitSeconds` of the sidecar starting, so a shell waiting for it waits no longer: without the broker's answer by then, or when the broker refuses the run, the file sets nothing and prints one line on stderr saying the settings are unavailable, and the sidecar keeps asking (after a failure within 30 seconds, after a refusal at the next refresh); a later answer replaces it. The sidecar asks again every `refreshSeconds`, so a catalog change reaches shells started after it. It logs `settings_written` with the names and how long after it started, `settings_refused`, `settings_unavailable` and `settings_wait_expired`, never a value. Only a sidecar that relays a Cursor run's token (`sessionSocketDir`) accepts the setting, and an older relay refuses a configuration that has it, so update the relay image and its configuration together.

Deploy a broker that reads `settings` to every replica, and repin the catalog validator, before any block carries it. An older broker reading Vault drops a block with a field it does not know, so that Automation is refused, and an older validator refuses the whole catalog. A catalog without `settings` behaves the same on either broker. Before rolling back to an older broker, remove `settings` from every block and let every replica load that version.

### An Automation's subagents

An Automation's run may start subagents. Each is a Cursor run of its own, with its own `bc-` id, on its own worker Pod, and its first request is usually the clone of its repository. Cursor's token for a subagent's run names no Automation and nothing about the run that started it, so on its own it is refused (`not_automation`). The parent proves the link instead: its run registers each subagent's run with the broker, and the subagent's run is then served as the same Automation, with exactly that Automation's block (its `entries` and `write`), while the parent's run is live.

An Automation opts in with `subagents`, the most subagent runs one of its runs may register (1 to 10,000). Without it, its runs register none. A block with `tokenSHA256` cannot set it: a static-token agent has no run to vouch for.

To register a subagent, the parent's run sends `POST https://subagents.gatehouse.invalid/v1/subagents/<bc- id>`, with no body, through the same proxy as every other request, as soon as it learns the subagent's id. The host is the broker's own on a pool that decides per Automation and is under `.invalid`, so nothing on it goes upstream. A run registers each subagent once; a repeat by the same run is accepted. The answer is JSON naming the subagent's `run`, the `parentRun`, the `automation` and when the registration `expires`: the parent Pod's deadline.

```sh
curl -sS -X POST --proxy "$GATEHOUSE_HTTPS_PROXY" --cacert "$GATEHOUSE_CA_FILE" \
  "https://subagents.gatehouse.invalid/v1/subagents/$SUBAGENT_ID"
```

| Check, at registration | Refusal |
|---|---|
| The caller is a listed Automation's own run, verified by its run token on its own Pod, as for any request | the usual refusal, such as `not_automation` |
| The caller is not itself a subagent | `subagent_nested` |
| The Automation's block sets `subagents` | `subagents_not_granted` |
| The id is a `bc-` run id other than the caller's | `request_shape` |
| No other run registered it first | `subagent_taken` |
| The caller has registered fewer subagents than its block allows | `subagent_limit` |

| Check, on each of the subagent's requests | Refusal |
|---|---|
| Its run is registered (the request waits for it, below) | `not_automation` |
| Its token's owner (`sub`) and team equal the parent's, it is on the parent's pool, and it names no other Automation | `subagent_mismatch` |
| The Automation is still listed and still sets `subagents` | `automation_unlisted` or `subagents_not_granted` |
| The parent's Pod has not reached its deadline and, read live from its cluster, is the same Running Pod with its worker container running and still serving the parent's run | `subagent_parent_gone` |

The subagent's token is verified as any run's is, with the run, Pod and run owner pins. Every replica reads the same registrations from the broker's store, and a registry the broker cannot read or write is refused as `subagent_unavailable` (503 with `Retry-After`). A subagent's clone can arrive before its parent has registered it, so a run's Pod waits for the registration from its first request, up to `AGENT_VAULT_SUBAGENT_WAIT_SECONDS` (default 120, at most 600) when the pool has an Automation that sets `subagents`; after that its requests are decided at once.

The link holds because the parent vouches for it, not because Cursor states it. A parent can lend its grant only to a run of the same Cursor owner and team, on the same pool, while the parent's own run is live, and never more than its own block. A parent whose agent is misled can lend the grant to another such run, which could then do what the parent itself could.

Every row from a verified Cursor run records `run`, the run's `cloud_agent_id`. A subagent's rows also record `parentRun`, the registering run, and name the Automation in `automation`, `automationName` and `automationOwner`; `source` stays what the subagent's own token said. A registration's rows (`binding: subagents`, `operation: subagent.register`) name the registering run in `run` and the subagent's run in `path`.

Deploy a broker that reads `subagents` to every replica before any block sets it: an older broker reading Vault drops a block with a field it does not know, and one started on a catalog file refuses the whole catalog, as for `write`.

### Who an agent-sandbox Pod names

A `proxy-attested` harness with requester `pod-annotation` and an `attested-person` pool take the person from the shared proxy's attestation. For a namespace listed in the proxy's `requesterNamespaces`, the proxy reads the agent Pod's `gatehouse.trmlabs.com/requester` annotation and attests it as `requester`. Admission policy sets that annotation to the login of whoever created the Sandbox and freezes it, and the controller copies it onto the Pod. The proxy admits no Pod there without one, and ends an open connection if it changes.

The person is that login, looked up as the Entra user principal name, when its domain is listed in `AGENT_VAULT_SANDBOX_PERSON_DOMAINS`. A login in another domain names no person and gets T0 only. With no domains configured, every request on such a pool is refused (`requester_unverifiable`). A person-mode pool whose attestation carries no requester is refused (`requester_missing`). A requester attested for any other pool, pool-mode agent-sandbox namespaces included, is refused (`requester_unexpected`), so a proxy fault cannot lend a person to a pool.

## Validation

`agent-vault broker-catalog validate catalog.yaml --require-pools --environment staging --allowed-host-suffix .example.com` runs the broker's own parser (`--environment` is required when the catalog has database entries, and `--image-registry`, which defaults to `AGENT_VAULT_IMAGE_REGISTRY`, when a harness names an `imagePrefix`). It checks the schema, exact hosts with no wildcards or IP addresses, unique routes, methods, key locations and pool grants, and keeps every host inside the allowed domains. Run it in CI before the catalog is written to Vault. For CI without access to this repository, `Dockerfile.catalog-validator` builds the same command into a small image (glibc base with a shell, so it can serve as a CI job container), at the broker's reviewed commit; pin it by digest.

## Egress

The broker's network policy allows the approved data-plane ranges once. Inside the broker, `AGENT_VAULT_EGRESS_RANGES` (comma-separated CIDRs) confines every resolved destination address to those ranges, public or private. An unparseable value allows nothing. A destination is reachable only when its host is in the catalog and its address is in these ranges. A new database in an existing range needs no network change. Only a new range needs a second change, in the broker's network policy.

For hosts whose addresses move (a SaaS API behind a CDN), `AGENT_VAULT_EGRESS_RANGES_FILE` names a file of single addresses (one per line, or comma or space separated, `#` comments) that also count as egress ranges. The broker re-reads it at most every 5 seconds, so a job that resolves the catalog's host names can keep it current without a restart or an address in the deployment's configuration. A missing file adds nothing until the first good read, and the broker logs one warning naming its path, so a mistyped path shows; a file with no address, or with anything but single addresses (a range, a name), is refused whole and the last good set stays. After a good read, removing or emptying the file revokes nothing while the broker runs: revoke by writing a shorter list. To revoke every address, empty the file and restart the broker, which reads it fresh. Replace the file atomically (write a temporary file and rename it; a Kubernetes ConfigMap mounted as a directory does, but a `subPath` mount never receives updates), since the broker cannot tell a file cut off mid-write from a whole one. Setting only the file confines egress to it. The private and metadata blocks apply to these addresses as to every other. As with a new range, the broker's network policy must also admit them.

## One secret per entry

Under `AGENT_VAULT_CATALOG_VAULT_PREFIX=<mount>/<prefix>`:

| Secret | Field | Holds |
|---|---|---|
| `<prefix>/head` | `catalog` | The catalog document without `entries`, for example the `pools` list. |
| `<prefix>/head` | `entries_sha256` | SHA-256, lowercase hex, over every entry in byte order of name: the name, a newline, the stored entry JSON, a newline. |
| `<prefix>/head` | `entries_names` | Optional. The entry names, as a JSON array (or a string holding one). When present, the broker reads and digests only these entries, so a stray document under `entries/` (one a cancelled apply left behind) is ignored instead of failing every reload. Without it, the broker lists `entries/` as before. |
| `<prefix>/entries/<name>` | `entry` | One entry's JSON. Its `name` must equal `<name>`. |
| `<prefix>/head` | `automations_buckets` | Optional. Bucket name to the SHA-256, lowercase hex, of that bucket's stored `automations` field, as a JSON object (or a string holding one). When present, the head's `catalog` must not carry `automations`; without it, the head's `catalog` may carry them, bounded by the size limit for one secret. |
| `<prefix>/automations/<bucket>` | `automations` | A string holding a JSON array of Automations (Terraform's `jsonencode` of the list); the head's digest is over that string. Put each in a bucket by a hash of its id (for example the first byte of its SHA-256, 256 buckets), so one change rewrites one bucket. |

Write every changed entry first and the head last. The head's KV version is the catalog version: each poll reads only the head, and reads every entry only when that version changes. Buckets are read incrementally: a new head rereads only the buckets whose digest changed, so changing one Automation costs the head, the entries and one bucket. Write changed buckets before the head. If the entries read do not hash to the head's digest, because an apply is part way through, the broker logs `broker catalog version rejected`, keeps the last good catalog and tries again at the next poll. A head that carries `entries` is refused. An entry whose current version is deleted or destroyed is out of the catalog, so removing an entry needs no metadata cleanup; leave it out of the digest.

A broker that predates Automations knows neither the `cursor-automation` identity nor the `automation` mode. Reading Vault, it drops a `cursor-automation` pool as an unknown identity, with its harness and every entry that grants the pool, including an entry the pool shares with person pools, so those people lose that entry too. A file catalog, and a catalog validator pinned to an older commit, refuse the whole catalog. An older broker also refuses any catalog document that carries `automations`, including the copy the broker stores for a Vault outage. A new broker puts bucketed Automations in that stored copy whether or not any pool uses them. An older broker also drops a pool that sets `automationRunsAsPerson`, as an unknown field, with every entry that grants it. So deploy a broker that reads them to every replica, and repin the catalog validator, before the catalog gets its first `cursor-automation` pool, `automation` harness, Automation or `automationRunsAsPerson`, and write Automations only in buckets: an older broker reading Vault ignores `automations_buckets`. An earlier broker that decides an Automation on its owner's account accepts only an email `owner`: it drops an Automation whose `owner` names a team, and a catalog validator pinned to that commit refuses the catalog. Name owners by team only after every replica, and the validator, run a broker that reads them. Until every replica runs this broker, an older replica still refuses a run that is not the owner's or names no person; before rolling back to such a broker, set every owner back to an email. Once this broker is deployed, an Automation's run on a `cursor-session` pool is refused until that pool sets `automationRunsAsPerson`, which can be written only after every replica runs this broker. To roll back, first remove every `cursor-automation` pool, `automation` harness, Automation and `automationRunsAsPerson` from the catalog (an older broker serves none of them anyway) and let every replica load that version. Rolling back is then safe while Vault answers, because an older replica's first load rewrites the stored copy; one that starts during a Vault outage before then cannot read the copy and refuses every destination until Vault answers.

## When a catalog is bad or Vault is down

One bad input never stops the broker or freezes the catalog, and nothing fails open:

| Event | What the broker does |
|---|---|
| One entry fails validation (an unknown field from a newer format, a bad host, grant or tier) | Leaves that entry out and logs `broker catalog part left out` with the version, kind, name and reason. The rest of the version applies, so removals in it take effect. The left-out entry is unreachable. |
| Entries conflict (a duplicate name, a shared route, host, test user or repository, entries on one host and port that disagree on `http2`, or a `github-api` entry's pull request prefix on a push prefix, in any `git` entry listing the repository, that a pool it reaches cannot push to, or on a `{requester}` one, or a repository listed by two `git` entries when either gives it `{requester}` push prefixes) | Leaves every entry in the conflict out; it never picks a winner. |
| A pool or harness fails validation or conflicts | Leaves it out with every entry that grants that pool. When the catalog lists harnesses, a pool left without one is left out too, so the harness check is never switched off. |
| The document cannot be decoded at all (truncated, or a new top-level section) | Logs `broker catalog version rejected` and keeps the last good catalog. |
| Vault cannot serve the catalog at startup | Starts from the last version this store accepted (each accepted version is kept in the `broker_catalog` table) and reloads from Vault when it answers. With no stored copy, it starts with an empty catalog that refuses everything, reports `catalog` not ready on `GET /ready`, and loads the first version Vault serves. |
| The Vault login or audit key read fails at startup | Retries with backoff for `AGENT_VAULT_STARTUP_RETRY_SECONDS` (default 120, inside a 150 s startup probe), then exits. A missing or invalid setting fails at once. |

Alert on `broker catalog part left out` and `broker catalog version rejected`. A stored copy is used only while Vault is unreachable, and every grant it holds still needs Vault at request time for its key or credential.

The broker's Vault policy needs `read` on `<mount>/data/<prefix>/head` and `<mount>/data/<prefix>/entries/*`, and `list` on `<mount>/metadata/<prefix>/entries`; with Automations in buckets, also `read` on `<mount>/data/<prefix>/automations/*`. Reads run 64 at a time; that sets reload speed, not how many entries the catalog may hold. The tests load 20,000 entries.
