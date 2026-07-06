#!/bin/bash
# Attacker container entrypoint — infrastructure only, no attack logic
set -euo pipefail
CONTAINER_NAME="attacker"
LOG_PATH="${DT_LOG_PATH:-/logs/attacker.jsonl}"
log() { echo "{\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)\",\"level\":\"INFO\",\"container\":\"${CONTAINER_NAME}\",\"msg\":\"$1\"}" >&2; }
log "entrypoint_starting status=infrastructure_only"
mkdir -p "$(dirname "${LOG_PATH}")"
log "log_directory_ready"
PYTHON=$(command -v python3 || command -v python3.11)
log "starting_reconnaissance_scaffold"
exec "${PYTHON}" /app/tools/reconnaissance.py
