# Broker catalog

The broker catalog is the one list of everything workers may reach through the broker: databases, HTTP services, git repositories and the GitHub pull request API, each granted to named worker pools. Adding a destination is one entry in one reviewed file. Terraform writes the catalog to Vault, and the broker picks up the new version within 30 seconds, with no restart.

## Where it lives and how it loads

- **Source:** a YAML file in trm-infra, next to the Vault roles and key paths its entries use, so one Atlantis pull request creates both. The `gatehouse-catalog` module validates it at plan time and writes it as JSON to the KV version 2 secret `gatehouse/catalog`, field `catalog`.
- **Broker:** `AGENT_VAULT_CATALOG_VAULT_PATH=gatehouse/catalog`. The broker polls every 30 seconds. A new version replaces the old one atomically, and the next request or connection uses it. See [When a catalog is bad or Vault is down](#when-a-catalog-is-bad-or-vault-is-down) for what happens to a bad entry and to a start without Vault.
- **One secret per entry:** `AGENT_VAULT_CATALOG_VAULT_PREFIX=gatehouse/catalog` reads the same catalog split so no single secret holds all of it, which is how a catalog grows past Vault's size limit for one secret. The layout is below. Set this or `AGENT_VAULT_CATALOG_VAULT_PATH`, never both; the single document stays accepted while catalogs move.
- **Fixed file:** `AGENT_VAULT_HTTP_CATALOG_FILE` still works for local fixtures. It is read once at start.

## Format

```yaml
pools:
  - {name: cursor-agents, namespace: cursor-agents, serviceAccount: cursor-worker}
entries:
  - name: b2bcore                     # the database name a worker connects to
    kind: postgres
    host: p.abc.db.postgresbridge.com
    pools: [cursor-agents]
    postgres: {database: core, mount: database, role: staging.us.crunchy.core-readonly}
  - name: serpapi
    host: serpapi.com
    pathPrefixes: [/search]
    methods: [GET]
    header: X-Api-Key
    placeholder: __vault_SERPAPI_KEY__
    key: {mount: gatehouse, path: vendors/serpapi, field: key}
    pools: [cursor-agents]
```

Entry kinds: `postgres` (port 5432 by default; `sslmode` is `verify-full`, the only mode the catalog accepts; `access` is `read` by default and must be `write` exactly for a `-readwrite` role; the broker needs `AGENT_VAULT_CATALOG_ENVIRONMENT`, and `validate` needs `--environment`, such as `staging`, and every role must then be `staging.<region>.<cluster>.<name>-readonly` or `-readwrite`; with no environment set, a catalog with any `postgres` entry is refused), HTTP (no kind; see the HTTP header adapter guide), `git` and `github-api` (see the git adapter guide). When `pools` is defined, an entry can grant only defined pool names. Grants match the scope's pool, which the broker's attestation sets from the worker Pod's approved controller. The agent ID stays the broker's own identifier for revocation, Vault roles, cleanup and audit. A scope with no pool matches no grant. Audit rows carry both `pool` and `agent`.

## External pools

A pool with `ceiling: external` is below T0: its workers serve people outside the company, so it reaches nothing. The catalog refuses any entry that grants it, and an external pool takes no verified identity. It exists so a harness for customer-facing sandboxes can be declared before entries can be scoped to a tenant.

## Harness profiles

A harness is one kind of agent runtime: Cursor workers, Claude sessions, agent-sandbox. Each is one `harnesses` entry that answers three questions: how its agents prove who they are, how they reach the broker, and whether access is decided for the pool, for the person, or for the Automation that started the run. A new runtime needs a new entry, and code only if it brings a new identity kind.

```yaml
harnesses:
  - name: cursor
    trustDomain: {issuer: https://container.googleapis.com/v1/projects/P/locations/L/clusters/C, keys: in-cluster, audience: gatehouse}
    identity: {kind: pod-token, ownerKind: ReplicaSet, namespaces: [cursor-agents], imageDigests: [sha256:...]}
    path: {kind: sidecar}
    authorization: {mode: pool, poolName: cursor-agents}
    client: {proxyEnv: GATEHOUSE_HTTPS_PROXY, caFileEnv: GATEHOUSE_CA_FILE, caSpkiEnv: GATEHOUSE_CA_SPKI}
```

| Field | Values |
|---|---|
| `trustDomain` | `issuer` (HTTPS), `keys` (`in-cluster`: the broker's own cluster API; `remote`: the issuer's published keys; `pinned`: the issuer's public keys held in the broker's identity configuration, no fetch), `audience` |
| `identity.kind` | `pod-token` (the Pod's own token, live Pod and source address), `session-jwt` (the same, plus a runner session naming the person, pinned to its first Pod), `proxy-attested` (a shared proxy in the agent's cluster checks the Pod and presents its own token) |
| `identity` | `ownerKind` (the controller kind that must own the agent Pod), `namespaces`, `imageDigests`, optional `imagePrefix` (proxy-attested only: an agent-sandbox repository or tenant path ending in `/`; `imageDigests` may then be empty or list platform containers; two harnesses may not overlap), optional `requester` (`session-jwt` for Claude, `cursor-oidc` for Cursor, `pod-annotation` for agent-sandbox in person mode, or `signed-assertion`) |
| `path` | `kind` (`sidecar` or `shared-proxy`), `crossCluster` |
| `authorization` | `mode` (`pool`, `person` or `automation`), `poolName` |
| `client` | Environment variable names the worker render sets: `proxyEnv` (Gatehouse's proxy URL), `caFileEnv` (its CA file), optional `caSpkiEnv` (the CA's SPKI hash, for a browser launched with a trust flag). Cursor keeps `HTTPS_PROXY` for its own gateway, so it uses the `GATEHOUSE_` names; harnesses that leave the standard names free use `HTTPS_PROXY` and `SSL_CERT_FILE`. Every harness sets `caSpkiEnv` to `GATEHOUSE_CA_SPKI`, because Chromium on Linux trusts only its own certificate store: browsers trust Gatehouse by key hash everywhere, with no `certutil` in the image. The broker does not read these |

Every field is required except `requester`, `crossCluster` and `caSpkiEnv`, and the catalog is refused when an entry is incomplete or contradictory: a `pod-token` harness runs a sidecar and decides for the pool; `session-jwt` decides for the person; `proxy-attested` runs a shared proxy, and decides for the person exactly when its requester is `pod-annotation`; a cross-cluster path uses remote keys and is proxy-attested; `person` needs a requester. `automation` is a `session-jwt` sidecar with requester `cursor-oidc`. `signed-assertion` is refused until the broker verifies assertions. Once a catalog declares harnesses, each pool belongs to exactly one, its namespace is listed, and its `identity` agrees with the mode (`claude-session`, `cursor-session` or `attested-person` exactly for `person`, `cursor-automation` exactly for `automation`), and a person pool's requester is its own kind's (`session-jwt` for `claude-session`, `cursor-oidc` for `cursor-session`, `pod-annotation` for `attested-person`). A catalog without harnesses keeps today's behavior: each pool's profile is derived from its `identity`.

### Who a Claude session names

A `session-jwt` harness verifies the Claude runner's session token (`CLAUDE_CODE_SESSION_ACCESS_TOKEN`, `sk-ant-cc-` prefix) against Anthropic's published keys, as Anthropic's [Verify session identity in self-hosted environments](https://code.claude.com/docs/en/self-hosted-environments-identity) describes: issuer `ccr`, role `session_worker`, the runner pool's `ccpool_` ID in the audience. The creator is in `act`: `act.sub` is `user:<id>` for a person or `agent:<id>` for the organization's service identity, and `act.email` is the person's address when the creating surface recorded one. `act.attested_by` is reserved by Anthropic and not read.

A session names a person only when `act.sub` is `user:<id>` and `act.email` is in a domain listed in `AGENT_VAULT_RUNNER_PERSON_DOMAINS`. The person is that email, which the directory looks up as the Entra user principal name. A session without a recorded email (one dispatched from the CLI can lack it), with an email in another domain, or with no domains configured names no person: it gets T0 entries only, and every entry above T0 is refused. An `agent:` session never names a person. Any other `sk-ant-` token, such as a hosted session's, is refused.

### Who a Cursor run names

A `session-jwt` harness with requester `cursor-oidc` and a `cursor-session` pool verify the Cursor run's identity token, as Cursor's [OIDC tokens](https://cursor.com/docs/cloud-agent/identity) page describes. A self-hosted worker started with `--identity-socket` serves one socket per claimed run, and Cursor fills the token's claims from that run, so code on the worker cannot mint a token for another run or another owner. The sidecar mints the token itself, for each connection, from the one socket under the worker's `<data dir>/identity/` (relay settings `sessionSocketDir` and `sessionAudience`), so the agent never chooses which token is sent. No claim, or two sockets, sends nothing.

The broker checks the RS256 signature against Cursor's published keys (`https://api.cursor.com/keys`), issuer `https://api.cursor.com`, an audience exactly equal to `AGENT_VAULT_CURSOR_AUDIENCE` (Cursor does not allowlist audiences), `agent_runtime: self_hosted`, a `team_id` in `AGENT_VAULT_CURSOR_TEAM_IDS`, a `cloud_agent_id`, and a lifetime of at most an hour (Cursor's is five minutes). A run names a person only when `sub` is `user:<id>` and `owner_email` is in a domain listed in `AGENT_VAULT_CURSOR_PERSON_DOMAINS`; the person is that email, looked up as the Entra user principal name. A `service_account:` run never names a person. On a `cursor-session` pool every request must name a person, T0 included: a request with no run token is refused (`session_missing`), and so is one whose run names no person, such as a service account's, an owner without a known email or in another domain, or any run when no domains are configured (`no_person`). A run an Automation started is refused too (`automation_on_person_pool`) unless the pool opts in; see [What an Automation's run may use](#what-an-automations-run-may-use). The refusal is that one request's: other Pods, and later requests that carry a good token, are decided on their own. `CURSOR_USER_ID` in the worker's environment is never read: the agent can rewrite it.

Any process on a worker can mint a token for that worker's run, and a token copied elsewhere would otherwise still verify. So a token counts only on the Pod the spawn hook created for its run: its `cloud_agent_id` must equal the Pod's `gatehouse.trmlabs.com/cursor-request-id` annotation, which the hook writes from `CURSOR_REQUEST_ID` (the same `bc-` ID; the worker cannot change its own Pod) and the broker reads from the live Pod at each admission. A Pod without that annotation names nobody (`session_run`). Each token is also pinned to the first Pod that presents it, and, since runs on one Pod share its workspace, each Pod to its first run owner (`sub`) for a day: a run by anyone else on that Pod is refused (`session_pod_owner`).

### What an Automation's run may use

A pool with `identity: cursor-automation` (harness mode `automation`) decides each request for the Cursor Automation that started the run, not for the pool or a person. Access is catalog data: one `automations` block per Automation, so a new Automation needs no pool, image or deployment.

```yaml
automations:
  - id: <automation_id from the run token>
    name: explorer                 # a label for audit rows
    owner: owner@example.com       # the accountable person
    entries: [tracker, repo-read]  # entries it may use; each also granted to the pool
```

The run token is verified exactly as on a `cursor-session` pool (run, Pod and owner pins included). Then every request on the pool, T0 included, must come from an Automation the catalog lists, run by its owner:

| Check | Refusal |
|---|---|
| `source` is `AUTOMATIONS` with an `automation_id`, so a person's run routed here gets nothing | `not_automation` |
| The id is listed | `automation_unlisted` |
| The run names a person (`sub` `user:` with an `owner_email` in a configured domain) | `automation_no_person` |
| The entry is one the Automation lists, even when the pool is granted it | `automation_not_granted` |
| The run's person is the `owner` | `automation_not_owner` |
| The owner's account is enabled, at every tier, so an offboarded owner's Automation stops. T0 on this pool therefore needs the directory | `account_disabled`, or `entitlement_unavailable` once the account is deleted and the directory no longer answers for it |

Above T0 the entry is then decided on the owner's account, as a person's would be, so the Automation never reaches what its owner could not. A run whose token names anyone other than the owner is refused. The broker sees only the person the run token names, never who edited the Automation or set off its trigger: a run Cursor attributes to the owner is served on the owner's account, so whoever can edit or trigger an Automation that runs as its owner acts with the owner's access. Treat anyone who can edit or trigger an Automation as able to use its entries.

`runnerGroup` is refused at load. It would limit who runs an Automation only if Cursor named the person who set off each run, and the run tokens seen so far name only the owner, so it could not be an access limit. It stays refused until a run set off by someone other than the owner shows which person Cursor names.

An Automation's run on a `cursor-session` (person) pool is refused (`automation_on_person_pool`), so the `automations` list is the only way an Automation gets a person's access. A pool that names no person, such as `cursor-agents` above, cannot tell an Automation's run from anyone else's: it serves every run its T0 entries. A run counts as an Automation's when its token's `source` is `AUTOMATIONS` or it carries an `automation_id`; a new automated source that sets neither would be served as its person. A pool opts in to serving them with `automationRunsAsPerson: true` (`cursor-session` pools only; on any other pool the catalog refuses it): an Automation's run there is then served as the person its token names, with every entry that pool grants and that person's groups, not the Automation's list. A person's own run, from the web, Slack or the API, is unaffected.

Directory lookups are budgeted, 60 a minute each, as for a person. The owner's check is charged to the Automation's own budget, not the owner's, so busy runs use up neither the owner's own sessions' budget nor another Automation's. At T2 every request asks the directory about the owner now; at T0 and T1 the answer may come from the cache. A run that is not the owner's is refused before any lookup. Past a budget, an answer up to 5 seconds old is reused; otherwise the request is refused (`entitlement_rate_limited`).

Every audit row from a Cursor run that reaches the authorization check (one for a matched entry or database) records the token's `source` and `automation`, on any pool and on refusals; on an automation pool, a listed Automation's `automationName` and `automationOwner` too, `requester` is the person the run's token names, and the decision fields describe the decision on the owner's account. Automations are indexed by id at load, so a lookup costs the same at 100,000 as at one. An `id`, `name` and entry names are plain identifiers; `owner` is a lower-case email. A tolerant load drops an Automation that is invalid, repeats another's id, or names an entry that was dropped, and keeps the rest.

### Who an agent-sandbox Pod names

A `proxy-attested` harness with requester `pod-annotation` and an `attested-person` pool take the person from the shared proxy's attestation. For a namespace listed in the proxy's `requesterNamespaces`, the proxy reads the agent Pod's `gatehouse.trmlabs.com/requester` annotation and attests it as `requester`. Admission policy sets that annotation to the login of whoever created the Sandbox and freezes it, and the controller copies it onto the Pod. The proxy admits no Pod there without one, and ends an open connection if it changes.

The person is that login, looked up as the Entra user principal name, when its domain is listed in `AGENT_VAULT_SANDBOX_PERSON_DOMAINS`. A login in another domain names no person and gets T0 only. With no domains configured, every request on such a pool is refused (`requester_unverifiable`). A person-mode pool whose attestation carries no requester is refused (`requester_missing`). A requester attested for any other pool, pool-mode agent-sandbox namespaces included, is refused (`requester_unexpected`), so a proxy fault cannot lend a person to a pool.

## Validation

`agent-vault broker-catalog validate catalog.yaml --require-pools --allowed-host-suffix .postgresbridge.com --allowed-host-suffix serpapi.com` runs the broker's own parser. It checks the schema, exact hosts with no wildcards or IP addresses, unique routes, methods, key locations and pool grants, and keeps every host inside the allowed domains. Run it in CI before Atlantis applies. For CI without access to this repository, `Dockerfile.catalog-validator` builds the same command into a small image (glibc base with a shell, so it can serve as a CI job container), at the broker's reviewed commit, through the same build, review, publish and Artifact Registry mirror path as the broker image; pin it by digest.

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

A broker that predates Automations knows neither the `cursor-automation` identity nor the `automation` mode. Reading Vault, it drops a `cursor-automation` pool as an unknown identity, with its harness and every entry that grants the pool, including an entry the pool shares with person pools, so those people lose that entry too. A file catalog, and a catalog validator pinned to an older commit, refuse the whole catalog. An older broker also refuses any catalog document that carries `automations`, including the copy the broker stores for a Vault outage. A new broker puts bucketed Automations in that stored copy whether or not any pool uses them. An older broker also drops a pool that sets `automationRunsAsPerson`, as an unknown field, with every entry that grants it. So deploy a broker that reads them to every replica, and repin the catalog validator, before the catalog gets its first `cursor-automation` pool, `automation` harness, Automation or `automationRunsAsPerson`, and write Automations only in buckets: an older broker reading Vault ignores `automations_buckets`. Once this broker is deployed, an Automation's run on a `cursor-session` pool is refused until that pool sets `automationRunsAsPerson`, which can be written only after every replica runs this broker. To roll back, first remove every `cursor-automation` pool, `automation` harness, Automation and `automationRunsAsPerson` from the catalog (an older broker serves none of them anyway) and let every replica load that version. Rolling back is then safe while Vault answers, because an older replica's first load rewrites the stored copy; one that starts during a Vault outage before then cannot read the copy and refuses every destination until Vault answers.

## When a catalog is bad or Vault is down

One bad input never stops the broker or freezes the catalog, and nothing fails open:

| Event | What the broker does |
|---|---|
| One entry fails validation (an unknown field from a newer format, a bad host, grant or tier) | Leaves that entry out and logs `broker catalog part left out` with the version, kind, name and reason. The rest of the version applies, so removals in it take effect. The left-out entry is unreachable. |
| Entries conflict (a duplicate name, a shared route, host, test user or repository) | Leaves every entry in the conflict out; it never picks a winner. |
| A pool or harness fails validation or conflicts | Leaves it out with every entry that grants that pool. When the catalog lists harnesses, a pool left without one is left out too, so the harness check is never switched off. |
| The document cannot be decoded at all (truncated, or a new top-level section) | Logs `broker catalog version rejected` and keeps the last good catalog. |
| Vault cannot serve the catalog at startup | Starts from the last version this store accepted (each accepted version is kept in the `broker_catalog` table) and reloads from Vault when it answers. With no stored copy, it starts with an empty catalog that refuses everything, reports `catalog` not ready on `GET /ready`, and loads the first version Vault serves. |
| The Vault login or audit key read fails at startup | Retries with backoff for `AGENT_VAULT_STARTUP_RETRY_SECONDS` (default 120, inside a 150 s startup probe), then exits. A missing or invalid setting fails at once. |

Alert on `broker catalog part left out` and `broker catalog version rejected`. A stored copy is used only while Vault is unreachable, and every grant it holds still needs Vault at request time for its key or credential.

The broker's Vault policy needs `read` on `<mount>/data/<prefix>/head` and `<mount>/data/<prefix>/entries/*`, and `list` on `<mount>/metadata/<prefix>/entries`. Reads run 64 at a time; that sets reload speed, not how many entries the catalog may hold. The tests load 20,000 entries.
