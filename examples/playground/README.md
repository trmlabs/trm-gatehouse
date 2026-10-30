# Gatehouse playground

Use a payments service, search logs and query a database without holding their credentials. Then try to steal a key. This local challenge runs the real Gatehouse broker against disposable services, with a guided walkthrough, a browser terminal and an attacker's mailbox.

## Start and stop

From the repository root, with Docker running and Docker Compose available:

```sh
make playground
```

Open <http://127.0.0.1:8787>. **Show me how it works** opens seven guided experiments. Each explains the service type, what should happen and what the live run actually returned. **Play all 7 steps** runs the walkthrough automatically. **Let me break it** switches to free play in place, with an open terminal. The commands, decision log and attacker mailbox are expandable in the guided view.

```sh
make playground-shell       # another shell in the same sandbox
make playground-autoplay    # command-line autoplay
make playground-down        # remove this lab's containers, networks and volumes
```

**Restart demo** resets the story, displayed activity, mailbox and browser terminal. This starts a new run shared by every open tab. Refreshing a page keeps the current run. The full signed audit history, lab credentials and custom sandbox files are retained; `make playground` performs a complete rebuild/reset with fresh keys. Background signing checkpoints are excluded from the displayed activity counts. Browser and command-line autoplay take about 90 seconds and cover the unprotected comparison, protected missions and rotation. The browser runs commands in its expandable terminal; the command-line version prints shell output in your terminal.

Only the web port is published, on the host's loopback interface. All data, credentials and certificates are synthetic. No model or external service account is required. The lab makes no model calls: you act as the agent.

## Play

The fictional shop expected 92 refunds, one for each order, but issued 184. The agent investigates two sample order records and the job logs, discovers an extra scheduled run, disables it through an approved Gatehouse API action and verifies a fresh batch with 92 refunds. Yesterday's records stay unchanged; the fix prevents a repeat. The shell includes `request`, a small HTTP client, and `psql`:

```sh
request -H 'Authorization: Bearer __vault_PAYMENTS_KEY__' https://payments.example/refunds
PGPASSWORD=orders-placeholder psql 'host=127.0.0.1 port=15432 dbname=orders user=workload sslmode=disable' -c 'select current_user; select * from refunds;'
```

The database connection above is plaintext only to a sandbox-local tunnel. That tunnel verifies the relay's certificate; the relay connects over verified TLS to Gatehouse, which verifies TLS to PostgreSQL.

`request` supports `-H`, `-X`, `-d` and `-L`. It always uses the assigned relay. It is not curl. Arbitrary shell commands still work, and attempts to bypass the relay are part of the challenge. The browser provides a persistent bash terminal. Its transcript clears when changing steps or modes; the shell and its files remain. Commands have one visible prompt, and raw service replies omit the internal demo run identifier. It is a text terminal, without full-screen editor rendering.

The free-play command hints range from inspecting files to testing redirects, request rules, direct connections and database permissions. Each says what it tests and what result to expect. Find the payments key, logs token or relay's HTTP login. Paste a candidate into the claim box, or deliver it to the attacker. Raw values, base64, hex and URL encoding are recognized. Placeholders and the planted backup key do not count. The public value `gatehouse-demo-claim-example` previews a recognized-value response; the server marks it as an example, returns no protected matches and never counts it as a win. Reading protected containers or volumes through Docker on your own host is outside the challenge.

Report a suspected break privately using [SECURITY.md](../../SECURITY.md), with the tested revision and reproducible steps. Never send production credentials.

## What is real, and what is a fixture

- The HTTP broker, catalog enforcement, credential screening, signed audit chain, PostgreSQL broker and database task relay are the repository's existing code. This example changes no production broker code.
- HTTP uses a static agent token held by the separate relay. Its TLS front supplies the source address to Gatehouse's dedicated token listener.
- PostgreSQL uses a local identity fixture. It signs short-lived service-account proofs and supplies public signing keys and synthetic Pod records. The unchanged broker verifies those proofs and the unchanged database relay checks its configured sandbox. This does not establish Kubernetes admission, live container identity or deployment isolation on another machine.
- Vault creates a temporary database login per session. The example grants only reads and configures synchronous revocation after disconnect.
- The MCP mission demonstrates server-token brokering. It does not demonstrate per-tool authorization.
- After the malicious ticket, rotation is a precaution, separate from repairing the scheduler. The walkthrough first makes a successful request, then the separate operator replaces the payments key through Vault’s API, and the agent requests again. The terminal shows a confirmed, sanitized operator action between those requests and labels the equivalent Vault CLI as an illustration. Catalog credentials are cached. Rotation can cause one request to receive 401; that clears the cache, and a retry uses the new key. Nothing restarts. The demo does not claim request-time Vault reads for every call.
- The unprotected agent follows a fixed poisoned-ticket script and has a separate key. No model is deciding whether to obey the ticket.

A hijacked agent can still perform every permitted operation. Response screening detects common encodings, not every transformation. An empty inbox is an observation, not a proof that all exfiltration is impossible. Gatehouse, the relay, the local operator and the identity fixture are trusted.

A successful `/redirect` response means the approved service returned a new address. The destination is checked separately and refused; the decision log labels the 302 as a redirect, not a successful end-to-end request. Redirects are excluded from the successful-response counter.

## Original single-container verification

The blog’s existing `examples/credential-proxy/Dockerfile` remains a separate automated verification image. It starts test Vault and PostgreSQL in one container and runs with `--network none`. The interactive playground uses multiple isolated Compose containers for its separate trust boundaries.

```sh
docker build -f examples/credential-proxy/Dockerfile -t credential-proxy-verification .
docker run --rm --network none credential-proxy-verification
```

Behind corporate TLS inspection, add `--secret "id=demo_ca,src=$SSL_CERT_FILE"` to that build. The runtime command stays the same.

## Boundaries and secret custody

The sandbox has only its relay and terminal networks, public certificates and placeholders. The web server binds its publishing interface, separately from its connection to the sandbox, and validates browser Host and Origin. The attacker, payments service and logs service run in separate containers. The web server reads audit, inbox and operator status through separate read-only mounts.

The operator creates and distributes all bootstrap secrets. Vault holds service keys and the database administrator password. The relevant fake service also holds its own key. Gatehouse holds its limited Vault token, its master key and private interception CA, and temporarily handles service keys and database credentials. The relay holds its HTTP token and database identity proof. PostgreSQL holds its administrator and temporary account material. The web server receives target hashes, never the target values, except when a player intentionally submits a candidate for comparison. An inbox match records the target name and withholds the protected value. Mission 0 intentionally displays its separate key.

All containers run without added capabilities or a Docker socket. The sandbox is unprivileged. Memory and process counts are bounded; Docker logs rotate. At the audit-feed size limit, the broker stops and the lab must be restarted. Internal Docker networks and local DNS configuration are tested by `verify.sh`; behavior on other Docker platforms still needs testing.

## Verify

With the lab running, on a development host with Python 3:

```sh
go test -race ./examples/playground/app
bash examples/playground/verify.sh
```

The integration checks exercise real requests, refusals, database write denial and account removal, rotation, browser guards, direct-network bypass attempts, credential scans and target recognition. Detector checks deliberately populate the inbox with synthetic positives; the final check restarts the demo and verifies that the displayed activity, mailbox and story reset.

The scan covers protected values in the sandbox and web home directories and public mounts, their main-process environments, every container's logs and the public feed. It is not a proof about arbitrary encodings, every process's memory or every volume's contents. Audit rows are checked for MAC and sequence fields; the example does not independently verify the complete cryptographic chain. The underlying repository tests cover its signer and verifier.

A CI job builds and exercises the same lab. Local checks do not establish that the CI job has run.

## Troubleshooting

- **Corporate TLS inspection:** set `SSL_CERT_FILE` to a readable PEM bundle containing the proxy's CA. The launcher passes it as the `build_ca` build secret. Runtime trust contains only this lab's certificates.
- **Port busy:** stop the other listener on port 8787, or stop an earlier copy with `make playground-down`.
- **Compose missing:** Docker Desktop includes it. With a standalone Docker installation, install the Compose plugin. The local development launcher also recognizes the temporary pinned Compose binary used to build this draft.
- **Shell disconnected:** the page tries to reconnect without replaying commands. Use **Reconnect terminal** for a fresh shell. Close other playground tabs if all four terminal slots are occupied. Custom files survive until a complete `make playground` reset.
- **Keys or identities expired:** restart the lab. It is intended for short local sessions, not persistent hosting.
