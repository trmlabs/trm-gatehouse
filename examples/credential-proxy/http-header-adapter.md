# HTTP header adapter

The header adapter lets a worker call an approved vendor or internal API without ever holding its key. The worker sends its request through the broker with a placeholder, or with no key at all. The broker checks that the destination, path and method are in an operator catalog and that the worker's pool is granted it. It then adds the key from Vault and records the call in the signed audit trail. Anything not in the catalog is refused.

## What the worker does

Point the worker's HTTPS proxy at its local relay, trust the broker's CA, and either omit the key header or set it to the catalog placeholder:

```
Authorization: Bearer __vault_LLM_KEY__
```

SDKs that insist on a key get the placeholder as their key value. The worker never sees the real key, so it cannot reach a transcript, a log or a commit.

## Catalog

Set `AGENT_VAULT_HTTP_CATALOG_FILE` to a JSON file. One entry per binding:

```json
{"entries": [{
  "name": "litellm",
  "host": "litellm.example.internal",
  "pathPrefixes": ["/v1/chat/completions", "/v1/models"],
  "methods": ["GET", "POST"],
  "header": "Authorization",
  "scheme": "Bearer",
  "placeholder": "__vault_LLM_KEY__",
  "key": {"mount": "gatehouse", "path": "vendors/litellm", "field": "key"},
  "pools": ["<pool agent ID>"],
  "forwardHeaders": ["OpenAI-Beta"]
}]}
```

| Field | Rule |
| --- | --- |
| `host`, `port` | One exact DNS name; no wildcards or IP addresses. Port defaults to 443. A tunnel to any other host is refused before it opens. |
| `pathPrefixes` | Matched on whole path segments: `/v1/chat` allows `/v1/chat/completions`, not `/v1/chatx`. The longest matching prefix wins. A path with `;`, a segment starting with `..`, or `.` is refused before matching. |
| `methods` | Any of GET, HEAD, POST, PUT, PATCH, DELETE. |
| `header`, `scheme`, `placeholder` | Where the key goes. A worker may send exactly the placeholder there, or nothing. A worker's own value is refused. |
| `basicUser` | The key is an HTTP Basic user name with an empty password, as axios `auth.username` and `curl -u key:` send it. The header is `Authorization` and `scheme` is unset. The worker sends its placeholder encoded the same way (set the client's key to the placeholder), or nothing. |
| `basicPair` | The key is stored as `user:password` and sent as HTTP Basic credentials, for vendors that issue a key pair, such as a public and a secret key. The header is `Authorization` and `scheme` is unset; it excludes `basicUser`. The worker sends the placeholder as both user name and password (set both of the client's keys to the placeholder), or nothing. A stored key without a non-empty user and password is never sent (503, `key_unavailable`). Responses that echo the encoded pair or the password alone are cut off. The user half is not screened, so store only a non-secret user name there, such as a public key. A client that also sends the user name in another header cannot use the entry: with the placeholder there it is refused (`placeholder_misplaced`), and with the real user name its `Authorization` no longer matches (`credential_header`). Langfuse's Python SDK is one, since it also sends its public key in `x-langfuse-public-key`. Use a client that sends only `Authorization`. |
| `key` | A KV version 2 secret on the `gatehouse` mount, at a path under `vendors/` (lower-case segments, at most 127 characters). Writing a new version rotates the key. |
| `pools` | Broker agent IDs of the worker pools granted this entry. |
| `forwardHeaders` | Extra caller headers the vendor needs. Only Accept, Accept-Language, Content-Type and User-Agent pass otherwise; routing headers such as `X-Forwarded-Host` or `X-HTTP-Method-Override` can never be listed. |
| `maxRequestBytes`, `maxResponseBytes` | Default 1 MiB and 32 MiB. |
| `requestFields` | Request parameters limited to listed values, as `[{"name": "channel", "values": ["C0123456789"]}]`. Each listed parameter must appear exactly once in the whole request (query string, JSON object body or form body) as a string equal to a listed value. A request with the parameter missing, repeated, in both the query and the body, a duplicate JSON key, a body that is not a JSON object or form, or two `Content-Type` headers is refused (403, `request_field` in the audit trail). So is any query, form or top-level JSON key holding whitespace, a control byte or a bracket, since a vendor's parser may read ` channel`, `channel%00` or `channel[]` as `channel`. An entry for `slack.com` (or a subdomain) must limit `channel` to channel IDs (`C...`) and list only the paths `/api/chat.postMessage`, `/api/chat.update`, `/api/reactions.add`, `/api/conversations.history` and `/api/conversations.replies`, each of which names its one conversation in `channel`; an ID not starting with `C` is refused at load, which keeps out direct message (`D`), group (`G`) and person (`U`, `W`) IDs. A Slack request may use only the parameters Slack documents for its method, spelled exactly, and never `token` (the key goes in the header); any other key, such as the `team_id` a client set up with a team ID adds, or a path that is not exactly a listed method, is refused. List the verbs your client sends: Python's `slack_sdk` `WebClient` sends every method, reads included, as a POST with a form body, while its `AsyncWebClient` and a raw HTTP caller may send a read as a GET with a query string. The checks are the same either way. Slack does not promise a conversation's type from its prefix, so list only channels you have checked. A Slack entry without both rules fails at load. Other Slack methods are not listable; some name a person or another conversation in a different parameter, which the `channel` rule would not see. Each audit row of a Slack entry names its method as the `operation`, such as `slack.conversations_history` or `slack.reactions_add`, so a channel read, a post and a reaction can be told apart. |

## Guarantees

- **No key to the worker.** A placeholder anywhere other than the catalog header, including the body or query, is refused, so it can never reach the vendor verbatim. Responses stream to the worker, including server-sent events, but the broker holds back any tail that could be the start of the key. A response that echoes the key in any of nine encodings is cut off before that part is sent, and is recorded as `secret_echo`.
- **Signed audit.** Each call records an `http_request` row before the vendor is contacted and an `http_response` row with the status and outcome. Each refusal records a `denied` row with its reason: `unlisted`, `method`, `pool`, `request_shape`, `placeholder_misplaced` and the rest. Rows name the pool, the Pod, the binding and a request ID returned to the worker as `X-Request-Id`.
- **Fail closed.** No catalog entry, no pool grant, no key from Vault, or an overdue audit checkpoint: the call is refused before the vendor is contacted.

## Keys and rotation

The broker reads each key from Vault at most once a minute and shares that read across concurrent requests. A new KV version takes effect within a minute, or at once when the vendor answers 401 or 403, which drops the cached key. Deleting the key in Vault revokes it within a minute: deleting or destroying the current version, deleting the secret, or removing or emptying the field makes the next read refuse the destination and drop the cached key. Only when Vault does not answer (unreachable, sealed, a server error or permission denied) does a cached key keep working, for five minutes past its minute, then calls are refused.

Grant the broker read on each key path, for example `gatehouse/data/vendors/*`. In TRM's Vault this is a trm-infra change.

## Requirements

`AGENT_VAULT_CREDENTIAL_PROXY=true`, workload identity, a Vault client and `AGENT_VAULT_AUDIT_CHAIN` (see the signed audit guide). The broker refuses to start with a catalog but without any of these.
