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
- **Hosts:** must be `*.googleapis.com`. Hosts that mint or manage credentials (STS, IAM Credentials, IAM, OAuth) are refused.
- **Paths:** downscoped entries default to the bucket's JSON API paths. Impersonating entries must list their paths.
- **On the worker:** set the client's access token to the placeholder, for example `CLOUDSDK_AUTH_ACCESS_TOKEN=__vault_GCP__`, and send HTTPS through the Gatehouse sidecar.

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
   - The broker takes up this identity when a catalog version first holds a gcp entry, and lets it go when the last one is removed, with no restart. A broker with no Google identity still starts and serves every other entry; its gcp entries answer 503 until the identity appears, then mint again with no restart.
2. **Impersonating entry:**
   - Create one service account per entry, holding only the entry's role on the entry's resource (for example `roles/bigquery.dataViewer` on one dataset, plus `roles/bigquery.jobUser` where queries run).
   - Grant the broker service account `roles/iam.serviceAccountTokenCreator` on that service account alone, for example with `google_service_account_iam_member`.
   - **Never grant TokenCreator at project or folder level.** The broker may mint only for the accounts the catalog names.
3. **Downscoped entry:**
   - A boundary only narrows what the broker already holds. Grant the broker the entry's object role on that bucket alone, for example with `google_storage_bucket_iam_member`, never at project level.
   - Keep each such bucket for agent data only, because the broker's base grant covers the whole bucket.

## Deferred: AWS

AWS requests are signed per request (SigV4), so Gatehouse would have to
re-sign each request rather than add a header, from an STS AssumeRole session
with a session policy. This waits for demand.
