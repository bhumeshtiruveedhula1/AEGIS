#!/bin/bash
# =============================================================================
# Hospital Server Container — Entrypoint
# =============================================================================
# Startup sequence:
#   1. Validate environment
#   2. Create log directories
#   3. Start health server (background thread in generator)
#   4. Start telemetry generator
# =============================================================================

set -euo pipefail

CONTAINER_NAME="hospital-server"
LOG_PATH="${DT_LOG_PATH:-/logs/hospital_server.jsonl}"
HEALTH_PORT="${DT_HEALTH_PORT:-9002}"

log() {
    echo "{\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)\",\"level\":\"INFO\",\"container\":\"${CONTAINER_NAME}\",\"msg\":\"$1\"}" >&2
}

log "entrypoint_starting"
log "container=${CONTAINER_NAME} log_path=${LOG_PATH} health_port=${HEALTH_PORT}"

# ---------------------------------------------------------------------------
# Create log directory
# ---------------------------------------------------------------------------
LOG_DIR=$(dirname "${LOG_PATH}")
mkdir -p "${LOG_DIR}"
log "log_directory_ready dir=${LOG_DIR}"

# ---------------------------------------------------------------------------
# Validate Python
# ---------------------------------------------------------------------------
PYTHON=$(command -v python3 || command -v python3.11)
if [ -z "${PYTHON}" ]; then
    echo '{"level":"ERROR","msg":"python3 not found"}' >&2
    exit 1
fi
log "python_found path=${PYTHON}"

# ---------------------------------------------------------------------------
# Start generator (includes embedded health server thread)
# ---------------------------------------------------------------------------
log "starting_generator"
exec "${PYTHON}" /app/generator.py
