# Google Cloud tokens per catalog entry

An agent can read a bucket prefix or query a BigQuery dataset without ever
holding a Google credential. The worker sends at most a placeholder. Gatehouse
mints a short-lived token for that one catalog entry from its own Google
identity and adds it on the entry's host and paths only. Each entry gets its
own narrow token, so an agent allowed one prefix or dataset cannot reach
another, even with the token Gatehouse used.

## Two ways to mint

| Mode | Set | What the token can do | How |
|---|---|---|---|
| Downscope | `bucket`, `prefix`, `role` | Objects under one prefix of one bucket, with one object role (viewer, creator or user) | A Credential Access Boundary on the broker's own token, through Google STS. Google supports boundaries for Cloud Storage only. |
| Impersonate | `serviceAccount`, `scopes` | Whatever that one service account holds, such as reader on one dataset | `generateAccessToken` for the entry's own service account |

- Tokens are used for `lifetimeSeconds` (default 900, at most 3600). They are cached until a quarter of that is left, and dropped after Google answers 401 or 403.
- A downscoped token also ends when the broker's own token ends, at most an hour.
- Every response is screened for the token.

## Catalog entries

```json
{"name": "team-files", "kind": "gcp", "host": "storage.googleapis.com", "tier": "T1",
 "requires": ["<directory group object ID>"], "placeholder": "__vault_GCP__", "pools": ["claude"],
 "gcp": {"bucket": "example-agent-files", "prefix": "teams/analytics/", "role": "roles/storage.objectViewer"}}

{"name": "bq-cases", "kind": "gcp", "host": "bigquery.googleapis.com", "tier": "T1",
 "requires": ["<directory group object ID>"], "placeholder": "__vault_GCP__", "pools": ["claude"],
 "pathPrefixes": ["/bigquery/v2/projects/example-analytics/"],
 "gcp": {"serviceAccount": "bq-cases@example-analytics.iam.gserviceaccount.com",
         "scopes": ["https://www.googleapis.com/auth/bigquery"]}}
```

- **Tier:** gcp entries are T1 or T2. Under the authorization model they are never granted to a pool without a person behind it, such as the Cursor pool, and every request needs a verified person in the `requires` groups.
- **Hosts:** `storage.googleapis.com`, `bigquery.googleapis.com` or `bigquerystorage.googleapis.com`. Hosts that mint or manage credentials (STS, IAM Credentials, IAM, OAuth) are refused.
- **Paths:** downscoped entries default to the bucket's JSON API paths. Impersonating entries must list their paths.
- **On the worker:** give the client the placeholder as its access token and send HTTPS through the Gatehouse sidecar. See [Worker setup](#worker-setup).

## BigQuery Storage Read API

`google-cloud-bigquery` reads query results and tables through the BigQuery Storage Read API by default, for example in `to_dataframe()`. That API is gRPC, so its entry sets `http2` (see the HTTP header adapter guide) and lists the read service:

```json
{"name": "bq-cases-read", "kind": "gcp", "http2": true, "host": "bigquerystorage.googleapis.com", "tier": "T1",
 "requires": ["<directory group object ID>"], "placeholder": "__vault_GCP__", "pools": ["claude"],
 "pathPrefixes": ["/google.cloud.bigquery.storage.v1.BigQueryRead/"],
 "gcp": {"serviceAccount": "bq-cases@example-analytics.iam.gserviceaccount.com"}}
```

- A read session streams the table as many `ReadRows` messages; each reaches the client as it arrives, screened for the token.
- `x-goog-request-params`, which routes a call to its session or stream, passes on every gcp entry.
- The entry's service account needs `roles/bigquery.readSessionUser` on the project that runs the session, besides read on the data.

## Worker setup

The worker holds only the placeholder; the broker replaces it with the entry's token.

- **bq and gcloud:** write the placeholder to a file and set `CLOUDSDK_AUTH_ACCESS_TOKEN_FILE` to it. gsutil ignores that setting, so use `gcloud storage`. Set `CLOUDSDK_COMPONENT_MANAGER_DISABLE_UPDATE_CHECK=true`, since the update check reaches a host outside the catalog.
- **Client libraries:** `google.auth.default()` finds no credential without a key file. Either pass the placeholder as a token (`google.oauth2.credentials.Credentials("__vault_GCP__")`), or run a local metadata server that answers with it, with `GCE_METADATA_HOST` and `GCE_METADATA_IP` pointing at it and that address in `NO_PROXY`. Such a server answers with `Metadata-Flavor: Google` and serves the token, the account, the project ID and the universe domain under both `default` and the account's email, which clients use after their first refresh. No client contacts the OAuth or STS endpoints with either.
- **CA:** `REQUESTS_CA_BUNDLE` for the REST half and `GRPC_DEFAULT_SSL_ROOTS_FILE_PATH` for gRPC, both naming the broker's CA.
- **Proxy:** gRPC clients do not speak TLS to a proxy, so set `grpc_proxy` to a plain `http://` hop to the relay.

## Google Cloud IAM

The service accounts and grants are Google Cloud IAM, usually managed in a
different repository from the catalog. Each new entry is an IAM change there,
then a catalog change.

**One identity pool per project.** Clusters in the same project share its
Workload Identity pool. A member is named only by namespace and service
account, never by cluster:
`serviceAccount:PROJECT_ID.svc.id.goog[<namespace>/<service account>]`, using
the broker's own namespace and service account. A production broker must use a
different namespace (or project) from a non-production one, or it would inherit
the non-production grants.

1. **Broker identity:**
   - Create a broker service account, bound with `roles/iam.workloadIdentityUser` to the member above, on that service account only.
2. **Impersonating entry:**
   - Create one service account per entry, holding only the entry's role on the entry's resource (for example `roles/bigquery.dataViewer` on one dataset, plus `roles/bigquery.jobUser` where queries run and `roles/bigquery.readSessionUser` where Storage Read API sessions run).
   - Grant the broker service account `roles/iam.serviceAccountTokenCreator` on that service account alone, for example with `google_service_account_iam_member`.
   - **Never grant TokenCreator at project or folder level.** The broker may mint only for the accounts the catalog names.
3. **Downscoped entry:**
   - A boundary only narrows what the broker already holds. Grant the broker the entry's object role on that bucket alone, for example with `google_storage_bucket_iam_member`, never at project level.
   - Keep each such bucket for agent data only, because the broker's base grant covers the whole bucket.

## Deferred: AWS

AWS requests are signed per request (SigV4), so Gatehouse would have to
re-sign each request rather than add a header, from an STS AssumeRole session
with a session policy. This waits for demand.
