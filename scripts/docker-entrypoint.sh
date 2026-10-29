#!/bin/sh
set -e

# AGENT_VAULT_MASTER_PASSWORD is read natively by the agent-vault binary.
# This entrypoint just forwards arguments to agent-vault.
exec /usr/local/bin/agent-vault "$@"
