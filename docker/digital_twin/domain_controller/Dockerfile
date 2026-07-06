# =============================================================================
# Domain Controller Container — Digital Twin
# =============================================================================
# Represents: Centralised identity infrastructure (IT segment)
# Network:    172.20.1.20 (IT Segment)
# Port:       9001 (health check — starts first)
# Logs to:    /logs/domain_controller.jsonl
# =============================================================================

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3.11 \
    python3.11-minimal \
    ca-certificates \
    && update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.11 1 \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 1001 csgen && \
    useradd --uid 1001 --gid csgen --no-create-home --shell /bin/false csgen

WORKDIR /app

COPY docker/digital_twin/shared/ /app/shared/
COPY docker/digital_twin/domain_controller/generator.py /app/generator.py
COPY docker/digital_twin/domain_controller/health_server.py /app/health_server.py
COPY docker/digital_twin/domain_controller/entrypoint.sh /app/entrypoint.sh

RUN mkdir -p /logs /tmp && \
    chown -R csgen:csgen /app /logs /tmp && \
    chmod +x /app/entrypoint.sh

USER csgen

ENV DT_LOG_PATH=/logs/domain_controller.jsonl \
    DT_HEALTH_FILE_PATH=/tmp/generator_health.json \
    DT_HEALTH_PORT=9001 \
    DT_CONTAINER_HOSTNAME=dc-01 \
    DT_DOMAIN_NAME=CORP.HOSPITAL.LOCAL \
    DT_DC_IP=172.20.1.20 \
    DT_ACCELERATED_MODE=false \
    DT_ACCELERATION_FACTOR=1440 \
    DT_EVENTS_PER_HOUR=62 \
    DT_DC_SUCCESSFUL_LOGINS_PER_HOUR=12 \
    DT_DC_FAILED_LOGINS_PER_HOUR=5 \
    DT_DC_PRIVILEGE_EVENTS_PER_HOUR=3 \
    DT_DC_USER_MGMT_PER_HOUR=2 \
    DT_DC_KERBEROS_PER_HOUR=30 \
    DT_BUFFER_SIZE=50 \
    DT_RANDOM_SEED=43

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python3 -c "import urllib.request; r = urllib.request.urlopen('http://localhost:9001/health', timeout=5); exit(0 if r.status == 200 else 1)"

EXPOSE 9001

ENTRYPOINT ["/app/entrypoint.sh"]
