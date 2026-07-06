#!/bin/bash
set -euo pipefail
CONTAINER_NAME="domain-controller"
LOG_PATH="${DT_LOG_PATH:-/logs/domain_controller.jsonl}"
log() { echo "{\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)\",\"level\":\"INFO\",\"container\":\"${CONTAINER_NAME}\",\"msg\":\"$1\"}" >&2; }
log "entrypoint_starting"
LOG_DIR=$(dirname "${LOG_PATH}")
mkdir -p "${LOG_DIR}"
log "log_directory_ready dir=${LOG_DIR}"
PYTHON=$(command -v python3 || command -v python3.11)
log "starting_generator"
exec "${PYTHON}" /app/generator.py
