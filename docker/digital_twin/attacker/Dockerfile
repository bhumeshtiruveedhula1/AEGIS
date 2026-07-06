# =============================================================================
# Attacker Container — Digital Twin
# =============================================================================
# PURPOSE: Infrastructure scaffold for future attack simulation modules.
#          NO attack scripts are present. NO attack logic runs.
#
# Represents: Controlled attack source (Attacker segment — ISOLATED)
# Network:    172.20.3.10 (Attacker Segment — no inbound ports)
# Logs to:    /logs/attacker.jsonl
#
# Future modules (2.x, 3.x) will ADD attack scripts to this container.
# This Dockerfile installs common security tooling so it's ready.
# =============================================================================

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Install Python + network utilities (for future attack scripts)
# nmap/curl are included as infrastructure — they run NO commands in this module
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3.11 \
    python3.11-minimal \
    ca-certificates \
    curl \
    nmap \
    netcat-openbsd \
    iputils-ping \
    iproute2 \
    && update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.11 1 \
    && rm -rf /var/lib/apt/lists/*

# Attacker runs as root intentionally (future scripts need raw socket access)
# This is the ONLY container that runs as root — documented as a known exception.
WORKDIR /app

COPY docker/digital_twin/attacker/tools/ /app/tools/
COPY docker/digital_twin/attacker/entrypoint.sh /app/entrypoint.sh

RUN mkdir -p /logs /tmp && \
    chmod +x /app/entrypoint.sh

ENV DT_LOG_PATH=/logs/attacker.jsonl \
    DT_CONTAINER_HOSTNAME=attacker-kali \
    DT_ATTACK_TARGET_IT_IP=172.20.1.10 \
    DT_ATTACK_TARGET_DC_IP=172.20.1.20 \
    DT_ATTACK_TARGET_OT_IP=172.20.2.10 \
    DT_ATTACKER_KEEPALIVE_INTERVAL=60

# NO HEALTHCHECK — no inbound ports by design
# NO EXPOSE — no listening services

ENTRYPOINT ["/app/entrypoint.sh"]
