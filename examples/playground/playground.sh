#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
compose() {
  if docker compose version >/dev/null 2>&1; then docker compose -f examples/playground/compose.yaml "$@"
  elif command -v docker-compose >/dev/null; then docker-compose -f examples/playground/compose.yaml "$@"
  elif [[ -x /private/tmp/gatehouse-tools/docker-compose ]]; then /private/tmp/gatehouse-tools/docker-compose -f examples/playground/compose.yaml "$@"
  else echo 'Docker Compose is required. Install its plugin, then rerun.' >&2; exit 1; fi
}
case "${1:-up}" in
  up)
    opts=(-f examples/playground/Dockerfile -t agent-vault-playground:local)
    if [[ -n "${SSL_CERT_FILE:-}" ]]; then opts+=(--secret "id=build_ca,src=$SSL_CERT_FILE"); fi
    docker build "${opts[@]}" .
    compose down --volumes --remove-orphans
    compose up -d
    ready=false
    for ((attempt=0;attempt<120;attempt++)); do
      if compose exec -T sandbox sh -c 'test -f /public/interception.crt && test -f /public/run.json' >/dev/null 2>&1; then ready=true; break; fi
      sleep 1
    done
    if [[ "$ready" != true ]]; then echo 'Startup failed. Inspect with: bash examples/playground/playground.sh logs' >&2; exit 1; fi
    if [[ -z "${CI:-}" ]] && command -v open >/dev/null; then open http://127.0.0.1:8787 || true; fi
    echo 'Open http://127.0.0.1:8787. The lab is ready.'
    ;;
  shell) compose exec sandbox /bin/bash --noprofile --norc ;;
  autoplay)
    compose exec -T web /bin/sh -c 'printf requested > /control/run'
    echo 'The unprotected agent is leaking its separate key. See the browser inbox.'
    sleep 7
    compose exec -T sandbox /bin/bash -s < examples/playground/autoplay.sh
    compose exec -T web /bin/sh -c 'printf requested > /control/rotate'
    sleep 1
    for attempt in 1 2; do
      compose exec -T sandbox request -H 'Authorization: Bearer __vault_PAYMENTS_KEY__' https://payments.example/refunds
    done
    sleep 11
    compose exec -T sandbox request -X POST -H 'Authorization: Bearer __vault_PAYMENTS_KEY__' https://payments.example/scheduler/disable-duplicate
    compose exec -T sandbox request -X POST -H 'Authorization: Bearer __vault_PAYMENTS_KEY__' https://payments.example/scheduler/test-run
    echo 'The extra schedule is disabled. The new test batch has one refund per order; historical refunds remain unchanged. Your turn: try to get a key out.'
    ;;
  down) compose down --volumes --remove-orphans ;;
  *) compose "$@" ;;
esac
