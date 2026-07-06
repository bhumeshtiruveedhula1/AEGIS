#!/bin/bash
set -euo pipefail
CONTAINER_NAME="ot-node"
LOG_PATH="${DT_LOG_PATH:-/logs/ot_node.jsonl}"
log() { echo "{\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)\",\"level\":\"INFO\",\"container\":\"${CONTAINER_NAME}\",\"msg\":\"$1\"}" >&2; }
log "entrypoint_starting"
mkdir -p "$(dirname "${LOG_PATH}")"
log "log_directory_ready"
PYTHON=$(command -v python3)
log "starting_generator"
exec "${PYTHON}" /app/generator.py
