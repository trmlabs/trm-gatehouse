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

## Gumloop ID tokens

A Gumloop agent can prove itself with the ID token Gumloop signs for it, so the platform holds no long-lived secret. The same static-token listener reads it: a token shaped like `<agent-id>.<secret>` is checked as above, any other as an ID token. Set `AGENT_VAULT_GUMLOOP_JWKS_URL` and `AGENT_VAULT_GUMLOOP_AUDIENCE` to turn it on.

The broker checks the signature against the issuer's signing keys (RS256 or ES256, cached for an hour and refetched when a token names a new key), the issuer, that the audience includes the configured one, that the token has not expired and expires within an hour, and any not-before time. It then reads `gumloop_org_id` and `gumloop_owner_id` (an owner that is not a user, by `gumloop_owner_type`, is refused as `oidc_owner_type`) and serves the Automation whose block names them. Any failure is refused with a reason code (`oidc_*`) and an audit row; the audit row's source is `GUMLOOP_OIDC`.

```yaml
automations:
  - id: example-gumloop-agent
    name: example-gumloop-agent
    owner: example-team
    entries: [example-entry]
    gumloop:
      orgID: "<the organization id>"
      ownerID: "<optional: one owner in that organization>"
```

A block with `ownerID` serves only that owner; a block without it serves any other owner in the organization. One organization and owner pair belongs to one block. A block has `gumloop` or `tokenSHA256`, never both, and neither can be reached by a Cursor run naming its id. Access is the block's `entries`, as for any Automation, and the token lives only as long as Gumloop issues it, so there is nothing to rotate or revoke here beyond removing the block.

## Signed-token platforms: add one by config

A platform that issues signed ID tokens (an OIDC-style JWT with an issuer, a published key set and an audience) joins Gatehouse by a catalog entry. No Go changes, no new environment variables. The platform team adds two blocks in one catalog PR: a harness that says how its tokens are checked, and one Automation block per agent that says which token is that agent.

```yaml
harnesses:
  - name: platform-a
    identity:
      kind: signed-token
      token:
        issuer: https://tokens.platform-a.example
        jwksURL: https://tokens.platform-a.example/keys   # or discovery: true, never both
        audiences: [gatehouse]
        algorithms: [ES256]                                # RS256, ES256 or both
        maxLifetimeSeconds: 3600
        subjectClaim: sub
        groupsClaim: groups                                # optional
    path: {kind: direct}
    authorization: {mode: automation, poolName: example-automations}
    client: {proxyEnv: GATEHOUSE_HTTPS_PROXY, caFileEnv: GATEHOUSE_CA_FILE}

automations:
  - id: example-agent
    name: example-agent
    owner: example-team
    entries: [example-entry]
    signedToken:
      harness: platform-a
      subject: agent-1@platform-a.example   # the value of subjectClaim in this agent's token
      groups: [team-a]                      # optional: the token must carry at least one
```

| Field | Meaning |
|---|---|
| `issuer` | The `iss` a token must carry; it may not equal any Kubernetes harness's `trustDomain.issuer`, and a token for a configured Gumloop issuer always goes to the Gumloop verifier (the broker logs an error if a harness names it). One harness per issuer: the broker picks the harness by the token's issuer and then checks the token in full against that harness only. |
| `jwksURL` or `discovery` | Where the issuer publishes its keys (HTTPS, no redirect), or `discovery: true` to read the `jwks_uri` from the issuer's `/.well-known/openid-configuration`, which must name the same issuer and an HTTPS key URL (no userinfo or fragment, no redirect on either fetch). Exactly one. |
| `audiences` | A token must name at least one. |
| `algorithms` | `RS256` and `ES256` only (RSA keys of 2048 bits or more, P-256 for ES256). `none` and HMAC algorithms are refused at load. |
| `maxLifetimeSeconds` | Required, 1 to 86400. A token is refused when `exp` minus `iat` is longer, or when it expires further ahead than this from now. `exp` and `iat` must both be present. |
| `clockSkewSeconds` | Optional, 0 to 300 (60 when unset; an explicit 0 means no skew). Forgives a fast clock for `iat`, `nbf` and how far ahead `exp` may be, never for `exp` itself. |
| `subjectClaim`, `groupsClaim` | The claims that name the agent and, optionally, its groups: a string, or for groups a string or list of strings. The subject is matched to one Automation's `signedToken.subject`; a block's `groups` then gate it. The subject must be assigned by the issuer and unique across every tenant and audience it serves: `audiences` is not a tenant boundary, so a platform that lets a tenant choose its own subject lets that tenant claim another's. |
| `requiredClaims` | Optional, at most 8: claim name to a plain string a token must carry exactly, checked together with the subject, for example `tenant: example-tenant`. A missing, non-string or different value is refused as `oidc_claim_missing`. Use it when the issuer serves several tenants. |
| `keyMaxAgeSeconds`, `refreshBackoffSeconds` | Optional key cache settings (3600 and 30 by default); twice the backoff may not exceed the key age, so a cached key set cannot expire before a refetch is allowed. Keys are fetched once and shared by every request; an unknown key id triggers at most one refetch per backoff, and an issuer outage keeps serving the last good keys until their age runs out. |

The harness shares its pool with that pool's other harnesses, and a pool may host any number of signed-token harnesses. The pool's grants and ceiling, and the block's `entries` and `write`, decide access exactly as for any Automation. A signed-token block cannot also set `tokenSHA256`, `gumloop` or `googleServiceAccount`, or `subagents`.

Tokens arrive on the same listener as agent tokens, so the platform's network must reach it over the same private link. The audit row's source is `SIGNED_TOKEN` and its Automation is the block's id.

Everything unproven is refused and recorded with a reason code, never admitted by default: `oidc_signature`, `oidc_key_unknown`, `oidc_keys_unavailable` (the key set could not be fetched), `oidc_issuer`, `oidc_audience`, `oidc_expired`, `oidc_lifetime`, `oidc_not_yet_valid`, `oidc_algorithm`, `oidc_claim_missing` (no `exp`, `iat` or subject, or a `requiredClaims` mismatch), `oidc_subject_unlisted` (no block names the subject), `oidc_group_missing` and `oidc_malformed`.

Not covered: a platform whose token names a person rather than an agent. A signed-token harness authorizes the Automation only. The Cursor and Gumloop verifiers keep their own settings and paths.

## Google service account ID tokens

A workload that runs as a Google service account can prove itself with an ID token Google signs for that account, so it holds no long-lived secret. The static-token listener reads it like a Gumloop ID token: a token shaped like `<agent-id>.<secret>` is checked as above, any other as an ID token, and when both Gumloop and Google are on, the token's `iss` only chooses which verifier checks it. Set `AGENT_VAULT_GOOGLE_AUDIENCE` and `AGENT_VAULT_GOOGLE_JWKS_URL` (https, Google's published signing keys) to turn it on.

The broker checks an RS256 signature (keys cached for an hour and refetched when a token names a new key, with the same outage behavior as the Gumloop keys), that the issuer is exactly `https://accounts.google.com`, that the audience is exactly the configured string, that the token has not expired, expires within an hour plus 60 seconds of clock skew, and is not before its `nbf` or `iat`. The token's `sub`, the service account's numeric unique ID, selects the block. If the token carries an `email`, `email_verified` must be true and the email must be the one the block lists. Any failure is refused with a reason code and an audit row; the row's source is `GOOGLE_OIDC`.

```yaml
automations:
  - id: example-google-agent
    name: example-google-agent
    owner: example-team
    entries: [example-entry]
    googleServiceAccount:
      email: example-agent@example-project.iam.gserviceaccount.com
      uniqueID: "<the service account's numeric unique ID>"
```

`email` is a lower-case service account email: user-managed, the default Compute Engine account or the App Engine account. `uniqueID` is the account's numeric ID, which a deleted and recreated account does not keep. One unique ID and one email belong to one block. A block has `googleServiceAccount`, `gumloop` or `tokenSHA256`, never more than one; none can set `subagents`, a Cursor run cannot name the block's id, and a block with `googleServiceAccount` needs an `owner` that names a team, not an email address. Authorization is the block's `entries`, `write` and `owner`, the pool's grants and ceiling, and no person; the audit row names no run person.

Anyone who can get an ID token for the bound service account is this Automation. That is `iam.serviceAccounts.getOpenIdToken`, granted by Service Account OpenID Connect Identity Token Creator or Service Account Token Creator on the account, its project, folder or organization, to workload identity federation principals allowed to impersonate it, or to anyone who can deploy code that runs as it. The audience limits which service a token is for, not who can mint it. Review who holds those roles before binding an account.

Pick an audience only the broker accepts, never one a cloud workload identity pool also accepts. The audience is what keeps a token minted for the broker apart from a token minted for another service. A token is bearer for up to an hour and carries no `jti`, so lifetime is the replay window; revoking access is removing the block, refused on the next request once every replica loads the new catalog.

| Reason | Meaning |
|---|---|
| `oidc_malformed`, `oidc_algorithm`, `oidc_signature`, `oidc_key_unknown` | Not a well-formed token, not RS256, not signed by a published key, or its `kid` is not in the published set |
| `oidc_keys_unavailable` | The signing keys could not be fetched, or the cached set is over an hour old; retry after the `Retry-After` |
| `oidc_issuer`, `oidc_audience` | Signed by a published key but issued by another issuer or for another audience |
| `oidc_expired`, `oidc_lifetime`, `oidc_not_yet_valid` | Past `exp`, expiring more than an hour (plus skew) out, or before `nbf` or `iat` |
| `oidc_subject_missing` | `sub` is not a numeric unique ID |
| `oidc_email_malformed`, `oidc_email_unverified` | An `email` that is not plain, or whose `email_verified` is not true |
| `oidc_service_account_unlisted` | A verified unique ID no block lists |
| `oidc_email_mismatch` | The unique ID is listed, and the token's `email` is not the block's |

Deploy a broker that reads `googleServiceAccount` to every replica before any catalog uses it. An older broker reading a catalog from Vault drops a block with a field it does not know, so that agent is refused; an older broker started on a catalog file, and a catalog validator pinned to an older commit, refuse the whole catalog.

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
