# Agent tokens

An agent token lets a client with no Kubernetes identity use the broker: an agent on another platform's machines, reaching the broker over a private link. Every other way to prove who an agent is, a Pod's token or a shared proxy that looks the Pod up, is a Kubernetes proof. This one is a per-agent random secret, checked against a hash in that agent's catalog block.

It is a bearer secret, so it departs from the rule that an agent's proof comes from short-lived evidence the platform or cluster issues. Use it only when the platform cannot issue such evidence, and only within these limits:

- One token is worth one agent's short list of entries, and nothing more. Its block is reviewed like any catalog change.
- It is accepted only on its own listener, reachable only over a private link, never on the listeners Pods use.
- It always expires, and never more than 90 days after the catalog loads. The catalog refuses a token block with no `expires`, one further out than that, or the zero time, so a hand-written or templated block cannot skip the limit. Renewal is a new token minted with `--keep-hash`.
- Revoking it is deleting the block: the next request on any open tunnel is refused, once every replica loads the new catalog (30 seconds for a catalog in Vault). A response already streaming runs until it ends, at most the tunnel's write timeout.
- Every use, and every refusal, is a row in the signed audit chain.
- The real credential stays in Vault. The agent holds a placeholder, its token and the public CA certificate.

The check sits behind one interface (`agenttoken.Verifier`), the shape the Cursor run-token verifier has. A token the platform signs can replace the static one without changing how the verified agent is authorized.

## The token

`<agent-id>.<secret>`: the agent's id in the catalog, a dot, and 256 random bits as 43 base64url characters. The agent sends it as the proxy userinfo, with no colon:

```text
HTTPS_PROXY=http://<token>@host:port
```

The broker splits the id at the last dot, finds that agent's block, hashes the whole token with SHA-256 and compares the hash with each listed value in constant time. The broker never stores a token. A refusal never says which part was wrong.

## The catalog

An agent is an Automation block with `tokenSHA256`, on the same pool as every other Automation (`identity: cursor-automation`, harness mode `automation`). A pool is who decides access; a harness is how an agent proves it is one, so a second harness on that pool is not a second pool.

```yaml
harnesses:
  - name: token-agents
    identity: {kind: static-token}
    path: {kind: direct}
    authorization: {mode: automation, poolName: example-automations}
    client: {proxyEnv: GATEHOUSE_HTTPS_PROXY, caFileEnv: GATEHOUSE_CA_FILE, caSpkiEnv: GATEHOUSE_CA_SPKI}

automations:
  - id: example-agent
    name: example-agent
    owner: example-team
    entries: [example-entry]
    write: []                      # optional, as for any Automation
    tokenSHA256: ["<64 hex characters>"]
    expires: "2027-01-01T00:00:00Z"  # required, at most 90 days from when the catalog loads
```

| Field | Meaning |
|---|---|
| harness `identity.kind: static-token` | Takes no trust domain, owner kind, namespaces, images or requester: none applies. `path.kind` is `direct`, `authorization.mode` is `automation`. At most one such harness per catalog. It may share its pool with that pool's one Kubernetes harness. |
| `tokenSHA256` | One lower-case hex SHA-256 of the token, or two while a token rotates. A block with it is reached only by that token; a block without it only by a Cursor run, so a vendor's ids and agent ids never alias. |
| `expires` | Required with `tokenSHA256`: an RFC 3339 time no more than 90 days after the catalog loads (`httpcatalog.MaxTokenLifetime`). A missing value, the zero time (`0001-01-01T00:00:00Z`) and a time past the limit each refuse the block. After it the token is refused, even with the right secret. A block loaded with a time already past is accepted and refuses its token, so an expired block can stay in the catalog until it is removed. |

Authorization is the Automation's: its `entries`, `write` and `owner`, the pool's grants and ceiling, and no person. See [What an Automation's run may use](broker-catalog.md#what-an-automations-run-may-use).

## Minting a token

```bash
agent-vault broker-catalog mint-agent-token example-agent \
  --owner example-team --entry example-entry --expires-in 720h
```

`--expires-in` defaults to 2160h (90 days), the longest the catalog accepts, and the command refuses a longer time or one that is not positive. It prints the token once and the block to paste under `automations:`, with the hash. It writes nothing. Put the token in the platform's secret store, never in the catalog, a commit or a ticket. The block is checked as the catalog's own parser would check it before it prints.

To rotate, and to renew before the expiry passes: mint again with `--keep-hash <old hash>`. The block lists both hashes and the new expiry. Give the agent the new token, then remove the old hash in a later change. To revoke: delete the block.

Renewal always mints a new token. A catalog change that moves `expires` on a block whose hashes stay the same extends a token nobody reissued, so flag it in review.

## The listener

Set `AGENT_VAULT_STATIC_TOKEN_PORT` (for example 14326). The broker listens on 127.0.0.1 only, behind a TLS front in the same Pod that sends a PROXY header (for example on 16444), and needs the credential proxy and `AGENT_VAULT_MITM_PROXY_PROTOCOL`. It carries HTTP CONNECT only: after the PROXY header, any other start is closed within 5 seconds, and a later request on a connection that is not a CONNECT is refused and ends the connection. Each connection is tagged `static-token`, and the HTTP proxy admits that kind only there. The cross-cluster listener keeps admitting `proxy-attested` only, and no listener admits both. An accept error that clears by itself (the process out of file descriptors, a connection dropped before it was accepted) is logged and retried with a growing wait of up to a second; any other accept error is logged and stops the broker, so the Pod restarts instead of refusing every agent with the port still open. The cross-cluster listener behaves the same. The front and its link must admit only the platform's network.

The TLS front's certificate must be one the agent trusts for the front's name or address, apart from the broker's interception CA, which the agent also trusts for the hosts it reaches through the tunnel.

## Refusals

Each refusal happens at the CONNECT, before a tunnel opens and before any credential is read, and again on every request inside an open tunnel. The caller sees a plain 403. The audit row records `denied` with `decision` `identity_<reason>`, `kid` set to the agent id the token claimed (in the safe form used for any name the caller chose), and the connection's `peer`. Never any part of the token.

| Reason | Meaning |
|---|---|
| `token_malformed` | Not `<id>.<43 characters>`, or sent with a vault hint |
| `agent_unknown` | No block with a token hash has that id |
| `agent_removed` | The block was there when the tunnel opened and is gone now |
| `token_mismatch` | The id is listed and the secret is not |
| `token_expired` | The secret matches and `expires` has passed, or the block reached the verifier with no expiry |
| `token_unverifiable` | No verifier is configured, or it failed |
| `listener_kind` | A scope of this kind reached a listener that does not admit it |

Failed attempts count against a pre-authentication budget (`AGENT_VAULT_RATELIMIT_AUTH_MAX`) keyed on the peer address the TLS front named in its PROXY header, never on the agent id the caller wrote. Past the budget a further failed attempt is refused with a 429, and its row (`identity_rate_limited`) names the agent id it claimed and the peer. A token that verifies is never counted or held back: it is one SHA-256 against the live catalog, so one caller's failures, or a flood of invented ids, never lock out the agent that holds the right token. Callers behind one shared address (a private link with source NAT shows every client as the NAT address) share one failure budget, and only their failed attempts are slowed. The audit row's `peer` then does not tell such clients apart; the claimed agent id is the field to rely on.

Allowed requests carry the usual Automation fields in their rows: `pool`, `agent` and `automation` (the id), `automationName`, `automationOwner`, and `source` `STATIC_TOKEN`.

## Deploying

Deploy a broker that reads `tokenSHA256` to every replica before any catalog uses `static-token` or `tokenSHA256`. An older broker reading a catalog from Vault drops a harness or block it does not know, so a token agent is refused entirely; an older broker started on a catalog file, and a catalog validator pinned to an older commit, refuse the whole catalog. Repin the validator at the same reviewed commit as the broker. A token block with no `expires`, or one past the 90-day limit, refuses the whole catalog (a tolerant load drops that block, so its agent is refused), so give every existing token block an expiry in the same change. Nothing changes for a catalog that sets neither.
