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
  "forwardHeaders": ["OpenAI-Beta"],
  "transcript": true
}]}
```

| Field | Rule |
| --- | --- |
| `host`, `port` | One exact DNS name; no wildcards or IP addresses. Port defaults to 443. A tunnel to any other host is refused before it opens. |
| `pathPrefixes` | Matched on whole path segments: `/v1/chat` allows `/v1/chat/completions`, not `/v1/chatx`. The longest matching prefix wins. A path with `;`, a segment starting with `..`, or `.` is refused before matching. |
| `methods` | Any of GET, HEAD, POST, PUT, PATCH, DELETE. |
| `header`, `scheme`, `placeholder` | Where the key goes. A worker may send exactly the placeholder there, or nothing. A worker's own value is refused. |
| `basicUser` | The key is an HTTP Basic user name with an empty password, as axios `auth.username` and `curl -u key:` send it. The header is `Authorization` and `scheme` is unset. The worker sends its placeholder encoded the same way (set the client's key to the placeholder), or nothing. |
| `basicPair` | The key is stored as `user:password` and sent as HTTP Basic credentials, for vendors that issue a key pair, such as a public and a secret key. The header is `Authorization` and `scheme` is unset; it excludes `basicUser`. The worker sets the client's secret key to the placeholder, and its public key to the real one or to the placeholder; the client then sends the stored user name or the placeholder as user name, the placeholder as password, or nothing. Any other user name is refused (`credential_header`). A stored key without a non-empty user and password is never sent: it is refused as `key_not_basic_pair`, a 503 without `Retry-After`, since only rewriting the value clears it. Responses that echo the encoded pair or the password alone are cut off. The user half is not screened and a worker may hold it, so store only a non-secret user name there, such as a public key. |
| `pairUserHeader` | For a `basicPair` client that also sends the user name in a header of its own, such as Langfuse's `X-Langfuse-Public-Key`. The value there must be the stored user name exactly: another value is refused (`credential_header`), and the placeholder there as `placeholder_misplaced`. The broker forwards it to the vendor. Without this field the header is dropped like any unlisted one. It may not be a reserved header or one the broker forwards anyway: Accept, Accept-Language, Content-Type, User-Agent, or one listed in `forwardHeaders`. |
| `key` | A KV version 2 secret on a KV mount (`gatehouse` in these examples), at a path under `vendors/` (lower-case segments, at most 127 characters). `AGENT_VAULT_CATALOG_KEY_PREFIX` (`validate --key-prefix`) names another prefix, such as `agents/keys`. Writing a new version rotates the key. |
| `clientCertificate` | A client certificate the broker presents to the host in the TLS handshake, for a service that accepts only client certificates (mutual TLS): `{"mount": "gatehouse", "path": "vendors/<name>"}`, under the same prefix as `key`, a KV version 2 secret whose `cert` field holds the PEM certificate and whose `key` field holds its PEM private key. An entry with one may leave out `header`, `scheme`, `placeholder` and `key`, and the worker then sends no credential. See [Client certificates](#client-certificates-mutual-tls). |
| `pools` | Broker agent IDs of the worker pools granted this entry. |
| `forwardHeaders` | Extra caller headers the vendor needs. Only Accept, Accept-Language, Content-Type and User-Agent pass otherwise; routing headers such as `X-Forwarded-Host` or `X-HTTP-Method-Override` can never be listed. |
| `http2` | The worker may speak HTTP/2 to this host, which gRPC needs. See [HTTP/2 and gRPC](#http2-and-grpc). Every entry on one host and port must agree; the broker leaves out every entry on a host where they disagree. |
| `maxRequestBytes`, `maxResponseBytes` | Default 1 MiB and 32 MiB. |
| `transcript` | The entry is a model API: its request bodies carry the agent's conversation, which quotes whatever the agent read. A decoy credential found only in such a body is not refused; its headers and URL are still checked. See [decoy credentials](decoy-credentials.md). |
| `requestFields` | Request parameters limited to listed values, as `[{"name": "channel", "values": ["C0123456789"]}]`. Each listed parameter must appear exactly once in the whole request (query string, JSON object body or form body) as a string equal to a listed value. A request with the parameter missing, repeated, in both the query and the body, a duplicate JSON key, a body that is not a JSON object or form, or two `Content-Type` headers is refused (403, `request_field` in the audit trail). So is any query, form or top-level JSON key holding whitespace, a control byte or a bracket, since a vendor's parser may read ` channel`, `channel%00` or `channel[]` as `channel`. An entry for `slack.com` (or a subdomain) must limit `channel` to channel IDs (`C...`) and list only the paths `/api/chat.postMessage`, `/api/chat.update`, `/api/reactions.add`, `/api/conversations.history` and `/api/conversations.replies`, each of which names its one conversation in `channel`; an ID not starting with `C` is refused at load, which keeps out direct message (`D`), group (`G`) and person (`U`, `W`) IDs. A Slack request may use only the parameters Slack documents for its method, spelled exactly, and never `token` (the key goes in the header); any other key, such as the `team_id` a client set up with a team ID adds, or a path that is not exactly a listed method, is refused. List the verbs your client sends: Python's `slack_sdk` `WebClient` sends every method, reads included, as a POST with a form body, while its `AsyncWebClient` and a raw HTTP caller may send a read as a GET with a query string. The checks are the same either way. Slack does not promise a conversation's type from its prefix, so list only channels you have checked. A Slack entry without both rules fails at load. Other Slack methods are not listable; some name a person or another conversation in a different parameter, which the `channel` rule would not see. Each audit row for a listed Slack method names it as the `operation`, such as `slack.conversations_history` or `slack.reactions_add`, so a channel read, a post and a reaction can be told apart. |

### Langfuse

Langfuse issues a public and a secret key per project, and its Python and JavaScript SDKs send the public key twice: in `Authorization` and in `X-Langfuse-Public-Key`. The Python SDK also writes it into every trace it exports, so a placeholder in its place would be refused as `placeholder_misplaced`. Give the client the real public key, which Langfuse treats as non-secret, and the placeholder as its secret key:

```
LANGFUSE_HOST=https://us.cloud.langfuse.com
LANGFUSE_PUBLIC_KEY=pk-lf-...
LANGFUSE_SECRET_KEY=__vault_LANGFUSE_SECRET_KEY__
```

Store `pk-lf-...:sk-lf-...` in Vault and list the header:

```json
{"name": "langfuse-us", "host": "us.cloud.langfuse.com", "pathPrefixes": ["/api/public"], "methods": ["GET"],
 "header": "Authorization", "basicPair": true, "pairUserHeader": "X-Langfuse-Public-Key",
 "placeholder": "__vault_LANGFUSE_SECRET_KEY__", "key": {"mount": "gatehouse", "path": "vendors/langfuse-us", "field": "key"},
 "forwardHeaders": ["X-Langfuse-Sdk-Name", "X-Langfuse-Sdk-Version", "X-Langfuse-Ingestion-Version"], "pools": ["<pool agent ID>"]}
```

A Langfuse key can read and write its whole project, so the entry's methods and paths are the only limit: `GET` on `/api/public` reads; trace export needs `POST` on `/api/public/otel/v1/traces`. Clients that send only `Authorization`, such as the Langfuse CLI or a plain OpenTelemetry exporter with `Authorization=Basic <base64 of public key:placeholder>` in `OTEL_EXPORTER_OTLP_HEADERS`, work with the same entry. Node's OpenTelemetry exporter makes its own HTTP agent, which ignores `HTTPS_PROXY` even with `NODE_USE_ENV_PROXY=1`; give it the proxy with `httpAgentOptions: {proxyEnv: process.env}`, or export from Python.

### groundcover

groundcover's hosted MCP server (`mcp.groundcover.com`) takes every tool as a JSON-RPC message on one path, `/api/mcp`, with the key sent as `Authorization: Bearer`. A groundcover key's data scope limits what most tools read, but groundcover does not apply it to every tool: monitor issues, for one, come back for every cluster and backend the tenant has. So for this host the broker reads each request's message itself, whatever the entry lists, and forwards only what a query client sends to run the log and metric tools:

- `initialize` and the `notifications/initialized` notification, which open a session;
- a `tools/call` naming `query_logs` or `query_metrics`, with only `name` and `arguments` in its `params`.

Every other method or tool is refused (403, `mcp_tool`), `tools/list`, `ping` and every other notification included. So is a request the broker cannot read as exactly one such message (400, `mcp_shape`): a batch, a key repeated at any depth, including through an escape, a key the message does not take (such as `Method` beside `method`, or `_meta` in a tool call), a value of the wrong type, a body that is not valid UTF-8, a string holding a control byte other than tab, newline or carriage return, or U+FFFD (what a lone surrogate escape decodes to), nesting deeper than 32, a `Content-Type` other than one `application/json`, a query string, or any path other than `/api/mcp`. A `GET` (the server's event stream) and a `DELETE` (ending the session) carry no message and pass with no body, if the entry lists them. Each forwarded message's row names it as the `operation`: `groundcover.initialize`, `groundcover.initialized`, `groundcover.query_logs` or `groundcover.query_metrics`.

```json
{"name": "groundcover", "host": "mcp.groundcover.com", "pathPrefixes": ["/api/mcp"], "methods": ["DELETE", "GET", "POST"],
 "header": "Authorization", "scheme": "Bearer", "placeholder": "__vault_GROUNDCOVER_KEY__",
 "key": {"mount": "gatehouse", "path": "vendors/groundcover", "field": "key"},
 "forwardHeaders": ["Mcp-Session-Id", "Mcp-Protocol-Version", "Last-Event-Id", "X-Backend-Id", "X-Tenant-UUID", "X-Timezone"],
 "pools": ["<pool agent ID>"]}
```

The rule is keyed on the host, so the entry needs no field for it, and a broker without it forwards every tool. A client that lists tools first, as most MCP clients do, is refused; give it the two tool names instead.

## HTTP/2 and gRPC

A tunnel offers HTTP/2 only to a host whose entries set `http2`; every other host keeps HTTP/1.1. A request that arrives over HTTP/2 goes upstream over HTTP/2 only, on connections the broker reuses; a vendor that does not offer HTTP/2 fails the call. Path prefixes scope a gRPC entry by service or method, since a call's path is `/package.Service/Method`:

```json
{"name": "reads-api", "http2": true, "host": "grpc.example.com",
 "pathPrefixes": ["/example.v1.Reads/"], "methods": ["POST"],
 "header": "Authorization", "scheme": "Bearer", "placeholder": "__vault_READS_KEY__",
 "key": {"mount": "gatehouse", "path": "vendors/reads-api", "field": "key"}, "pools": ["<pool agent ID>"]}
```

- **Calls that work:** unary and server-streaming calls. The broker reads the whole request before it contacts the vendor, as it does for HTTP/1.1, so a call whose client waits for answers before it finishes sending (bidirectional streaming) does not complete.
- **Streaming:** each response message reaches the worker as it arrives. The tail held back for screening is released at every message boundary, so a stream never waits for the next message. Trailers are screened too; a key in a message or a trailer ends the call with `INTERNAL`, recorded as `secret_echo`.
- **Headers:** the broker sets `te: trailers` and asks for uncompressed responses. `grpc-timeout` passes on an `http2` entry. A request compressed with gzip, which some clients send unasked (Temporal's Rust-based SDKs, Python's among them), is decompressed, checked and forwarded uncompressed, and `maxRequestBytes` applies to it decompressed; a request compressed any other way is refused as `request_shape`, and a compressed response, which could not be screened, as `response_refused`. A call's authority may name the host without its port, as a client that sets a TLS server name sends it; the call still goes to the tunnel's port.
- **Refusals:** a gRPC client never reads an HTTP status, so a refused call answers with a gRPC status in trailers and the refusal text in `grpc-message`. `X-Gatehouse-Refusal` still names the code, and a `Retry-After` is also sent as `grpc-retry-pushback-ms`.

| Refusal or upstream HTTP status | gRPC status |
| --- | --- |
| 400 | `INVALID_ARGUMENT` |
| 401, 407 | `UNAUTHENTICATED` |
| 403, 405 | `PERMISSION_DENIED` |
| 404 | `UNIMPLEMENTED` |
| 413, or a response past `maxResponseBytes` | `RESOURCE_EXHAUSTED` |
| 429, 502, 504, a passing 503 (with `Retry-After`), or an upstream that fails mid-stream | `UNAVAILABLE` |
| 503 without `Retry-After` | `FAILED_PRECONDITION` |
| A key or a compressed message in the response | `INTERNAL` |
| Any other status | `UNKNOWN` |

- **Limits:** `maxRequestBytes` and `maxResponseBytes` apply per call. One tunnel carries at most `AGENT_VAULT_MITM_HTTP2_MAX_STREAMS` concurrent calls (default 1000); a client past it waits for a free stream.
- **Proxy hop:** gRPC clients do not speak TLS to a proxy, so gRPC needs a plain `http://` hop to the local relay, usually as `grpc_proxy`, and the broker's CA as the client's TLS roots (`GRPC_DEFAULT_SSL_ROOTS_FILE_PATH` for gRPC C-core clients such as Python's).

## Client certificates (mutual TLS)

Some services take no key at all: they accept a client only by the certificate it presents in the TLS handshake. An entry's `clientCertificate` names one in Vault, and the broker presents it to that entry's host whenever the host asks for one. The worker holds no certificate and no key and sends no credential; it trusts the broker's CA as it does for any other host. A read-only gRPC entry lists each method it allows as a path prefix, so every other method, every write included, is refused with `PERMISSION_DENIED` (`unlisted`) before it reaches the service:

```json
{"name": "workflow-reads", "http2": true, "host": "temporal.example.com", "port": 7233,
 "pathPrefixes": ["/temporal.api.workflowservice.v1.WorkflowService/GetSystemInfo",
                  "/temporal.api.workflowservice.v1.WorkflowService/ListWorkflowExecutions",
                  "/temporal.api.workflowservice.v1.WorkflowService/CountWorkflowExecutions",
                  "/temporal.api.workflowservice.v1.WorkflowService/DescribeWorkflowExecution",
                  "/temporal.api.workflowservice.v1.WorkflowService/GetWorkflowExecutionHistory"],
 "methods": ["POST"], "clientCertificate": {"mount": "gatehouse", "path": "vendors/workflow-reads"},
 "pools": ["<pool agent ID>"]}
```

Those five methods are every call the Temporal Python SDK and the Temporal CLI make to connect, list, count, describe a workflow and read its history; starting, signalling and terminating a workflow are refused. Store the certificate and key with `vault kv put gatehouse/vendors/workflow-reads cert=@client.pem key=@client.key`.

- **What is presented:** the first certificate in `cert`, with any that follow as its chain, and the matching `key` (RSA, ECDSA or Ed25519, as PKCS #1, PKCS #8 or SEC 1 PEM). A CA certificate is refused as `client_cert_invalid`: its key can sign new certificates, which a broker presenting one identity never needs. Ask whoever issues the service's client certificates for an end-entity certificate made for this entry.
- **One certificate per entry:** each certificate gets connections of its own. A connection opened with one certificate never carries a request that should present another, and a host whose entries name no certificate never receives one. Entries on different hosts can carry different certificates. An entry may also carry a header key, for a service that asks for both.
- **Rotation without a restart:** write a new KV version with both fields. The broker reads each certificate at most once a minute and presents the new one from its next connection, including a new chain under the same certificate and key, such as a renewed intermediate; calls in flight finish on the old one. A TLS alert from the host refusing the certificate, or a 401, 403, `UNAUTHENTICATED` or `PERMISSION_DENIED` answer, drops the cached copy, so a fixed certificate is read on the next call.
- **Never to the worker:** the key signs the handshake inside the broker and is sent nowhere else, so no response can echo it. Neither field is logged or written to the audit trail, and errors name what is wrong, never the value.
- **Clients:** gRPC needs a plain `http://` hop to the broker, as above. Temporal's Python SDK takes one as `http_connect_proxy_config` and trusts the broker's CA through `TLSConfig(server_root_ca_cert=...)`, with no client certificate of its own; the Temporal CLI takes `HTTPS_PROXY` and `--tls-ca-path`.

| Refusal | When | Status |
| --- | --- | --- |
| `client_cert_unavailable` | Vault could not be read and no cached copy is under five minutes past its minute. | 503 with `Retry-After` (`UNAVAILABLE`) |
| `client_cert_deleted` | The secret, its current version, or either field is deleted or empty. | 503 (`FAILED_PRECONDITION`) |
| `client_cert_invalid` | Not a PEM certificate with its matching key, over 64 KiB (16 KiB for the key), or a CA certificate. | 503 (`FAILED_PRECONDITION`) |
| `client_cert_expired` | The certificate has expired or is not yet valid. | 503 (`FAILED_PRECONDITION`) |
| `client_cert_rejected` | The host refused the certificate in the handshake, for example one from a CA it does not trust. | 503 (`FAILED_PRECONDITION`) |

Under TLS 1.3 a host refuses a certificate just after the handshake. When the connection closes before the broker reads that refusal, the call fails as `upstream_error` (502) instead, and the cached certificate is read again within a minute as usual.

Grant the broker read on each certificate path, as for keys. A broker older than this field leaves out any entry that lists it, so deploy the broker before the catalog change.

## Guarantees

- **No key to the worker.** A placeholder anywhere other than the catalog header, including the body or query, is refused, so it can never reach the vendor verbatim. Responses stream to the worker, including server-sent events, but the broker holds back any tail that could be the start of the key. A response that echoes the key in any of nine encodings is cut off before that part is sent, and is recorded as `secret_echo`.
- **Signed audit.** Each call records an `http_request` row before the vendor is contacted and an `http_response` row with the status and outcome. Each refusal records a `denied` row with its reason: `unlisted`, `method`, `pool`, `request_shape`, `placeholder_misplaced` and the rest. Rows name the pool, the Pod, the binding, the method, the path once the caller is authenticated (never the query, and never on a browser-session host), and a request ID returned to the worker as `X-Request-Id`.
- **Fail closed.** No catalog entry, no pool grant, no key or client certificate from Vault, or an overdue audit checkpoint: the call is refused before the vendor is contacted.

## Keys and rotation

The broker reads each key from Vault at most once a minute and shares that read across concurrent requests. A new KV version takes effect within a minute, or at once when the vendor answers 401 or 403, which drops the cached key. Deleting the key in Vault revokes it within a minute: deleting or destroying the current version, deleting the secret, or removing or emptying the field makes the next read refuse the destination as `key_deleted` and drop the cached key. Only when Vault does not answer (unreachable, sealed, a server error or permission denied) does a cached key keep working, for five minutes past its minute, then calls are refused as `key_unavailable`. A stored key with a byte outside printable ASCII (0x21 to 0x7e), such as a trailing newline or a space, or longer than 8192 bytes, is refused the same way as a deleted one but recorded as `key_not_header_safe`, so the fix is to rewrite the value. Every refusal names its reason to the agent in the `X-Gatehouse-Refusal` header. `key_unavailable` is passing (503 with `Retry-After`); `key_deleted`, `key_not_header_safe` and, for a `basicPair` entry, `key_not_basic_pair` answer 503 without it, since only an operator can clear them (see the agent protocol page).

Grant the broker read on each key path, for example `gatehouse/data/vendors/*`.

## Requirements

`AGENT_VAULT_CREDENTIAL_PROXY=true`, workload identity, a Vault client and `AGENT_VAULT_AUDIT_CHAIN` (see the signed audit guide). The broker refuses to start with a catalog but without any of these.
