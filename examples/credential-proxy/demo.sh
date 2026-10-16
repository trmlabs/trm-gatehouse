#!/usr/bin/env bash
# Disposable fixture runner. The container supplies real Vault and PostgreSQL.
set -euo pipefail
cd "$(dirname "$0")/../.."
printf '\nHTTP: request-time rotation, deletion, authorization and strict forwarding\n'
bash examples/credential-proxy/verify-required.sh
printf '\nPostgreSQL: permissions, lifecycle and durable cleanup\n'
bash examples/postgres-broker/verify.sh
cat <<'SUMMARY'

PASS: local HTTP and PostgreSQL fixtures.

What this proved (real Vault and PostgreSQL where they are involved; the reply, audit and method checks use test doubles):
  - A placeholder is swapped for the real key only for the configured host and path, and only on GET or HEAD; anything else is refused.
  - A key rotated in Vault is used on the next request, and a deleted key is never sent (this run's strict profile; catalog entries take up to a minute).
  - A reply that echoes the key, in plain text or a common encoding, is cut off.
  - Every attempt is recorded before the request leaves; a dropped connection is recorded as unknown, never replayed.
  - Without pooling, each database connection gets a fresh login, removed when it closes, even after the broker is killed.
  - A broker that loses its own Vault login stops serving and ends running queries.
Lines that say SKIP or "set AV_TEST_..." are optional tests that need setup this container does not include.

Deployment acceptance still requires the actual runtime identity, encrypted ingress and bypass checks.
SUMMARY
