# Decoy credentials

Each worker pool's sessions can hold decoy credentials: values that look like real keys, kept where an agent would look for secrets, and accepted by no service. A worker never needs a credential, because the broker adds every real one. So a request that presents a decoy means the session went looking for secrets and tried one. The broker refuses that request, never forwards it, and records a signed audit row with outcome `decoy_credential`. Alert on that outcome as an incident.

No outside service is involved. The decoys live in Vault, and the broker recognizes them on its own.

## What the broker checks

The broker keeps only SHA-256 digests of the decoys. It hashes each value as it loads and holds no value afterwards, so a log, a stored row or an error never carries one. To check a request, it splits the text into runs of decoy characters, hashes each run that is as long as some decoy, looks the digest up by its first eight bytes and confirms it with a constant-time compare. A check costs the same at any number of decoys, and a broker with none loaded skips it.

| Where | When |
| --- | --- |
| Every header value of every request in a tunnel, and the URL's path, query and user info | After the worker's identity is checked and before the request is routed. So it covers every entry kind (HTTP, git, GitHub API, Google Cloud and browser sessions) and a path no entry lists. |
| The headers of a CONNECT or plain-HTTP proxy request, including `Proxy-Authorization` | When the request arrives. If identity fails, as it does for a decoy sent as the proxy password, the row names no pool. |
| Request bodies | Wherever an entry already reads the body: HTTP header entries, GitHub API writes, Google Cloud and browser sessions. |
| The PostgreSQL password | Before the token reaches the authenticator. The client sees an ordinary authentication failure. |

A Basic credential is decoded, and percent-encoding and JSON `\u` escapes are undone, before the check. A GitHub API write is checked again as rebuilt, since that is what GitHub reads. Only a whole decoy matches: not part of one, and not one inside a longer run of the same characters.

Out of reach:
- A git push's pack data, which is compressed and streamed.
- Any host outside the pool's catalog. The broker refuses that CONNECT before TLS, so it never sees the request.
- Behind the [task relay](../../examples/credential-proxy/task-relay/README.md), the CONNECT headers and the PostgreSQL password. The relay sends the broker its own CONNECT and proof, and refuses any sandbox password but the placeholder (recorded as `denied:placeholder`), so alert on the relay's refusals for relayed sandboxes. Requests inside a relayed tunnel are checked as above.

Give decoys the shape of credentials for hosts the pool does reach through the broker.

## The audit row

| Field | Value |
| --- | --- |
| `event`, `outcome` | `denied`, `decoy_credential` |
| `binding` | `decoy/<owning pool>/<name>`: which decoy, and so where it was planted. A pool other than the session's own means a decoy moved between sessions. |
| `decision` | Where it was found: `header`, `path`, `query`, `userinfo`, `body` or `password`. |
| `pool`, `agent`, `podUID`, `session` | The session that presented it, when identity was established. |
| `target`, `operation`, `database` | What the request asked for. |

The worker gets the same 403 (or PostgreSQL authentication failure) as any refusal, so it learns nothing about the decoy.

## Model traffic

A model API's request body is the agent's conversation, which quotes whatever the agent read. An agent that runs `env` while debugging would otherwise put every decoy into its next model call. Mark such an entry `"transcript": true`: its bodies are not checked, while its headers and URL still are. Only HTTP header entries take the field.

Mark every model entry before loading decoys. An unmarked one refuses every call after the agent first reads a decoy, since each call resends the conversation, so the session stops and every retry pages.

## Storing decoys

Set `AGENT_VAULT_DECOY_VAULT_PREFIX=<mount>/<prefix>`. The layout is in a KV version 2 mount:

| Secret | Field | Holds |
| --- | --- | --- |
| `<prefix>/head` | `names` | The pools that have decoys, as a JSON array or a string holding one. Other fields are ignored. |
| `<prefix>/pools/<pool>` | any lower-case name | One decoy per field, labelled `<pool>/<field>`. |

Write the pools' decoys first and the head last. The head's KV version is the set's version: each 30-second poll reads only the head, and the broker reads every pool when that version changes. It also rereads everything every 10 minutes. A pool whose secret is deleted has no decoys.

A decoy value is 20 to 256 characters of `A-Z`, `a-z`, `0-9`, `_` and `-`, and never holds `__vault_`. Any other value is left out and logged as `decoy credential left out` with its label and reason, never its value. Generate values from that alphabet with a vendor-like prefix, and keep them out of anything that is logged or committed.

Decoys never stop the broker. A load that fails is logged as `decoy credentials unavailable; keeping the last set`, and the last good set stays in force, or none before the first load. Alert on both log lines.

Grant the broker read on `<mount>/data/<prefix>/head` and `<mount>/data/<prefix>/pools/*`.

## Planting decoys

Put decoys where an agent hunting for secrets would look, and where no tool sends them on its own:

- Environment variable names that no CLI or SDK reads. Never the names a client reads as its key, such as the one the broker's placeholder sits in.
- A credentials file at a conventional path, with no tool configured to use it. For example, a `~/.git-credentials` entry with no git credential helper set.

A decoy that a tool sends by itself pages for nothing.
