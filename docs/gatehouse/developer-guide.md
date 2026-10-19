# Building against Gatehouse

Gatehouse lets an agent use a database, an HTTP API, a GitHub repository, a
Cloud Storage prefix or a web app without ever holding the password, key or
token. Each destination is one entry in one catalog file. The agent connects
to a local address and sends a placeholder where the credential would go;
Gatehouse swaps in the real one on the way out. Anything not in the catalog is
refused, and every request lands in a signed audit trail that names the person
behind the agent when there is one.

## Add a destination with one catalog entry

Keep the catalog in a reviewed repository and have your deployment pipeline
write it to Vault (see [broker catalog](broker-catalog.md) for where the broker
reads it). You add one entry in one pull request, grant the broker read on the
entry's Vault paths in the same change, and Gatehouse picks up the change
within 30 seconds with no restart. Check an entry locally first, with an `agent-vault`
binary built from this repository:

```sh
agent-vault broker-catalog validate --require-pools --environment staging catalog.yaml
```

| To reach | `kind` | You also need |
|---|---|---|
| A PostgreSQL database | `postgres` | A Vault database role for it, ending `-readonly` or `-readwrite` |
| A Memgraph graph database, read-only or with writes | `memgraph` | A login for the broker in a Vault key-value secret. See [graph databases](graph-databases.md). |
| An HTTP API with a key | (leave unset) | The key, written by an operator to a Vault key-value mount the broker can read |
| A GitHub repository (clone, push) | `git` | A GitHub App, installed on the repository |
| Opening and commenting on GitHub pull requests | `github-api` | The same App |
| A Cloud Storage prefix or a BigQuery dataset | `gcp` | Google Cloud access grants for the broker. See [Google Cloud tokens](gcp-tokens.md). |
| A web app as a test user | `browser-session` | A test user and an Auth0 login client. See [browser sessions](browser-session.md). |

A catalog defines its pools, then its entries. This example passes
`agent-vault broker-catalog validate --require-pools --environment staging`
once the `REPLACE` value and the group ID are real:

```yaml
pools:
  - {name: example-agents, namespace: example-agents, serviceAccount: example-worker}
  - name: claude-developers                # sessions that name a person
    namespace: claude-developers
    serviceAccount: worker
    identity: claude-session
    ccpoolID: ccpool_REPLACE               # the runner pool's ID
    ceiling: T1

entries:
  - name: appdb                            # a database
    kind: postgres
    host: db.example.com
    pools: [example-agents]
    postgres: {database: app, mount: database, role: staging.us.example.app-readonly}

  - name: search-api                       # an HTTP API; tier T0 by default
    host: api.example.com
    pathPrefixes: [/search]
    methods: [GET]
    header: X-Api-Key
    placeholder: __vault_SEARCH_KEY__
    key: {mount: gatehouse, path: vendors/search-api, field: key}
    pools: [example-agents]

  - name: example-repo                     # a repository; pushes only under cursor/
    kind: git
    host: github.com
    pools: [example-agents]
    # appID and installationID come from the GitHub App installation
    git: {appID: 123456, installationID: 7890123, repos: [{repo: example-org/example-repo, access: write, refPrefixes: [refs/heads/cursor/]}]}

  - name: team-files                       # one Cloud Storage prefix, people only
    kind: gcp
    host: storage.googleapis.com
    tier: T1
    requires: [00000000-0000-0000-0000-000000000000]   # the directory group's object ID
    placeholder: __vault_GCP__
    pools: [claude-developers]
    gcp: {bucket: example-agent-files, prefix: teams/analytics/, role: roles/storage.objectViewer}
```

## Tiers decide who may use an entry

Every entry has a tier and every pool has a ceiling, the highest tier it may
reach. Gatehouse refuses a grant above a pool's ceiling when it loads the
catalog, and checks again on every request.

| Tier | Who may use it |
|---|---|
| T0 (default) | Any worker in a granted pool, including a pool with no person behind its agents |
| T1 | A verified person in every group the entry `requires`, from a person pool (a Claude session, a Cursor run or an agent-sandbox Pod that names the person); or a workload pool whose fixed groups include them all. Never a pool with no person behind it. |
| T2 | As T1, from a person pool only, with the groups granted for a limited time |

The table covers person and workload pools. A Cursor Automation, on a
`cursor-automation` pool, may use the entries the catalog lists for it, at
any tier up to that pool's ceiling, with no group check, whoever's run it is.
See [broker catalog](broker-catalog.md).

`gcp` entries are always T1 or T2. Gatehouse looks up a person's groups in
Microsoft Entra ID once a deployment turns that lookup on, and caches them for
at most 5 minutes, so adding or removing someone takes effect within 5 minutes.

## Time-limited access through group grants

Any access-request tool that adds a person to a group for a limited time and
removes them afterwards works with T1 and T2 entries:

1. Find the entry's `requires` groups in the catalog.
2. Request the group, with the reason and how long you need it.
3. After approval, Gatehouse sees the group within 5 minutes. No restart is needed.
4. When the grant expires and the group membership is removed, Gatehouse refuses within 5 minutes.

## Agents connect to the sidecar on loopback

Each worker has a Gatehouse sidecar listening on its loopback address. Your
pool's worker template sets the real addresses; the values below are the
end-to-end test harness's.

| Destination | Point the client at | Credential to send |
|---|---|---|
| HTTP API | `HTTPS_PROXY=http://127.0.0.1:14443` | The entry's `header` set to its `placeholder` (after its `scheme`, if set), or no header |
| GitHub pull requests | The same proxy | `GH_TOKEN=__vault_GITHUB_TOKEN__`, or no token |
| Git | `git clone https://github.com/<org>/<repo>` through the proxy | Nothing. Any `Authorization` header is refused. |
| Google | The same proxy, with `CLOUDSDK_AUTH_ACCESS_TOKEN=__vault_GCP__` | `Authorization: Bearer` and the entry's placeholder |
| PostgreSQL | `host=127.0.0.1`, one port per database (15000 for the harness's first, 15001 for the next), with that binding's `dbname` and `user` (`workload` in the harness) | The binding's placeholder password (`gatehouse-relay-placeholder` in the harness) |
| PostgreSQL, routed | `host=127.0.0.1` and the pool's routed port, with `dbname` set to the catalog entry's name, so one port serves every database the pool is granted and a new catalog database needs no change to the worker. A sidecar that reaches more than one broker has one routed port per broker. The port declines the client's TLS request, so libpq's default `sslmode=prefer` connects in plaintext on loopback. | The listener's placeholder password |
| Graph database | `bolt://127.0.0.1:<port>` or `neo4j://127.0.0.1:<port>` with a stock driver, and the catalog entry's name as the user. One port serves every graph database the pool is granted. | The port's placeholder password. Refusals are Bolt failures with a `Gatehouse.` code; see [graph databases](graph-databases.md#refusals). |
| Web app | A Playwright storage state from `https://<api host>/.gatehouse/browser-seed` | Nothing |

- **Trust:** the worker must trust Gatehouse's interception certificate authority, at `/public/mitm-ca.crt` in the harness. Point `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE` or `REQUESTS_CA_BUNDLE` at it.
- **Database startup settings:** `application_name`, `client_encoding`, `DateStyle`, `extra_float_digits`, `search_path`, `standard_conforming_strings`, `statement_timeout` and `TimeZone` (so `PGTZ` works) are accepted. Anything else, including `options`, is refused; use `SET` after connecting.

## From a Cursor self-hosted worker

Pick the Gatehouse pool in Cursor's environment picker and use the standard
connection strings and environment variables the pool's worker template sets;
there is no SDK.

- **Worker pools (`pod-token`):** Gatehouse checks the worker Pod but not who
  started the task, so the pool has no person behind it and a ceiling of T0.
  A catalog that grants such a pool an entry above T0 is refused when
  Gatehouse loads it.
- **No group control on a worker pool:** anyone on the self-hosted machines
  can pick any pool unless the deployment restricts it, so grant a worker pool
  only data every such person may read.
- **Person pools (`cursor-session`):** Gatehouse names the person who started
  each run from Cursor's signed identity token (see
  [who a Cursor run names](broker-catalog.md#who-a-cursor-run-names)), so the
  pool may hold T1 and T2 entries. Every request must name a person, T0
  included.

## Every refusal names its cause

HTTP refusals carry an `X-Request-Id` header. Give it to the team that runs
Gatehouse to find the exact audit row. Gatehouse's own HTTP refusals also carry an
`X-Gatehouse-Refusal` header with a fixed reason code, and a one-line body
naming the code and the next step; the agent protocol page lists the codes. A
response without that header came from the service itself, apart from the 502
below. Database refusals reach the client from the sidecar with the
fixed text below, at connect time and inside a session; Gatehouse's own text
never reaches the worker. Refusing one query inside a session leaves the
session open, unless earlier messages of the same batch had already reached
the database; then the session ends. Errors from PostgreSQL itself, such as
a syntax error or a PostgreSQL permission error, pass through unchanged. For
anything unclear, give the team that runs Gatehouse the pool and the time to
find the audit row.

| You see | Usually means | Fix |
|---|---|---|
| 403 | The host or path is not in the catalog, your pool has no grant, or the tier check refused: no person behind the session, no directory account for that person (`not_in_directory`), not in the group, or a session from another pool | Add the entry or the grant, or request the group; for `not_in_directory`, tell the Gatehouse operators |
| 405 | The method is not listed for that path | Add the method to the entry |
| 400 | Something other than the exact placeholder in the key header, a placeholder anywhere else, plain HTTP, or an unsupported request (an upgrade, a compressed body) | Send only the placeholder, in the entry's header, over HTTPS |
| 413 | The request is larger than the entry allows | Raise `maxRequestBytes` |
| 429 | This worker's rate limit for that entry (`rate_limited`), or too many group checks for one person in a minute (`entitlement_rate_limited`) | Slow down; wait the `Retry-After` seconds; after three refused retries, tell the Gatehouse operators |
| 502 | The service could not be reached, or its response was refused, for example because it echoed the credential | Check the service |
| 503 with `Retry-After` | Gatehouse could not get the credential or a token, the group lookup is unavailable (`entitlement_unavailable`), no run token reached it on this connection yet (`session_missing`), or its audit trail is down | Retry after the stated seconds; after three refused retries, tell the Gatehouse operators |
| 503 without `Retry-After` | The key was deleted or emptied in Vault (`key_deleted`), the stored key cannot be sent in a header (`key_not_header_safe`) or is not the `user:password` pair a Basic pair entry sends (`key_not_basic_pair`), the client certificate the broker presents is deleted, invalid, expired or refused by the service (`client_cert_deleted`, `client_cert_invalid`, `client_cert_expired`, `client_cert_rejected`), Gatehouse is not set up for this kind of entry (`broker_misconfigured`), or the worker ends too soon for a browser session (`seed_deadline`) | Fix the key in Vault, start a new run, or tell the Gatehouse operators; retrying does not help |
| Postgres 53300 "this worker reached its session cap" | This worker has as many sessions open as it may | Close idle sessions, or retry |
| Postgres 53300 "the database's Gatehouse connection budget is full; retry shortly" | The database's connection budget is in use, at connect time or on a query | Retry shortly |
| Postgres 53300 "Gatehouse is at capacity; retry shortly" | Gatehouse's overall connection cap is reached | Retry shortly |
| Postgres 53300 "no session-mode database connection is free for session state (SET, temp tables, LISTEN, advisory locks); retry shortly" | The query needs session state and no dedicated connection is free | Retry, or avoid session state |
| Postgres 57P03 "Gatehouse is starting; retry in a few seconds" | The Gatehouse replica you reached is not ready yet | Retry; another replica answers |
| Postgres 3D000 "this database isn't in the Gatehouse catalog for your pool" | No catalog entry for that database, or it is not granted to your pool | Add the entry or the grant |
| Postgres 28000 "Gatehouse could not verify this worker" | Gatehouse refused the worker's Pod identity, or the sidecar could not read its identity proof | Retry; tell the Gatehouse operators if it persists |
| Postgres 42501 "Gatehouse: this session's person is not authorized for this database" | The tier check refused this database for this session | Request the group, or use a pool with a person behind it |
| Postgres 25006 "this database login is read-only: Gatehouse allows only reads, transaction control and a few settings such as search_path, and refuses temporary tables" | A read-only login sent something other than a read: a write, a temporary table, `DO`, `set_config`, or a `SET` outside the allowed settings. Pooled, the session continues; unpooled, it ends | Use a read; use a CTE or subquery instead of a temporary table; reconnect if the session ended |
| Postgres 42501 "Gatehouse refuses changing standard_conforming_strings or client_encoding mid-session; only on and UTF8 at connect" | The session tried to change how the server reads text, which could hide a statement from Gatehouse | Leave both at their defaults; set client_encoding at connect |
| Postgres 0A000 "Gatehouse refuses a statement with a backslash after an Execute in the same batch; send Sync first" | A pipelined batch ran a statement, then sent one containing a backslash before Sync | Send Sync between them; most drivers already do |
| Postgres 28P01 "Gatehouse: wrong placeholder password for this binding" | Wrong placeholder password | Use the binding's placeholder |
| Postgres 08006 "Gatehouse could not reach the database; retry" | The database is unreachable, at connect time or on a query | Retry; tell the Gatehouse operators if it persists |
| Postgres 08006 "Gatehouse could not get a database credential; retry shortly" | Gatehouse could not obtain a credential for the database | Retry shortly; tell the Gatehouse operators if it persists |
| Postgres 08006 "Gatehouse ended the session (deadline or revocation)" | The worker is past its deadline, or Gatehouse ended the session (revocation, or a failed recheck) | Reconnect; a worker past its deadline is not admitted again |
| Postgres 08001 "cannot reach Gatehouse" | The sidecar could not reach Gatehouse | Retry; tell the Gatehouse operators if it persists |
| Postgres 08004 "Gatehouse: connection refused: use this binding's database and user, and only the ... startup parameters" | A database or user other than the binding's, or a startup setting outside the accepted list | Use the binding's database and user; set other settings with `SET` |
| Postgres 08004 "Gatehouse: the broker refused this connection" | Any other refusal | Retry; tell the Gatehouse operators the pool and time if it persists |
| Connection closed with no error | The worker's task was withdrawn | Start a new task |
