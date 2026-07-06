# =============================================================================
# OT Node Container — Digital Twin
# =============================================================================
# Represents: Modbus PLC / ICS sensor node (OT segment)
# Network:    172.20.2.10 (OT Segment — isolated from IT)
# Port:       9003 (health check)
# Logs to:    /logs/ot_node.jsonl
# =============================================================================

FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN groupadd --gid 1001 csgen && \
    useradd --uid 1001 --gid csgen --no-create-home --shell /bin/false csgen

WORKDIR /app

COPY docker/digital_twin/shared/ /app/shared/
COPY docker/digital_twin/ot_node/generator.py /app/generator.py
COPY docker/digital_twin/ot_node/health_server.py /app/health_server.py
COPY docker/digital_twin/ot_node/entrypoint.sh /app/entrypoint.sh

RUN mkdir -p /logs /tmp && \
    chown -R csgen:csgen /app /logs /tmp && \
    chmod +x /app/entrypoint.sh

USER csgen

ENV DT_LOG_PATH=/logs/ot_node.jsonl \
    DT_HEALTH_FILE_PATH=/tmp/generator_health.json \
    DT_HEALTH_PORT=9003 \
    DT_CONTAINER_HOSTNAME=plc-01 \
    DT_SUPERVISORY_HOST=192.168.1.100 \
    DT_OT_READ_INTERVAL_SECONDS=5 \
    DT_OT_WRITE_INTERVAL_SECONDS=60 \
    DT_OT_HEARTBEAT_INTERVAL_SECONDS=30 \
    DT_OT_READ_REG_START=10 \
    DT_OT_READ_REG_END=20 \
    DT_OT_WRITE_REG_START=30 \
    DT_OT_WRITE_REG_END=40 \
    DT_ACCELERATED_MODE=false \
    DT_ACCELERATION_FACTOR=1440 \
    DT_EVENTS_PER_HOUR=120 \
    DT_BUFFER_SIZE=20 \
    DT_RANDOM_SEED=44

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python3 -c "import urllib.request; r = urllib.request.urlopen('http://localhost:9003/health', timeout=5); exit(0 if r.status == 200 else 1)"

EXPOSE 9003

ENTRYPOINT ["/app/entrypoint.sh"]
