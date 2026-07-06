# =============================================================================
# Hospital Server Container — Digital Twin
# =============================================================================
# Represents: Critical hospital application server (IT segment)
# Network:    172.20.1.10 (IT Segment)
# Port:       9002 (health check)
# Logs to:    /logs/hospital_server.jsonl
#
# Normal telemetry generated:
#   - Process creation (IIS, SQL Server, Windows services)
#   - Network connections (to DC, SQL, external)
#   - File access (patient records, IIS logs)
#   - Authentication events (service account logons)
#   - Database queries (stored procedures)
# =============================================================================

FROM ubuntu:22.04

# Prevent interactive prompts during apt installs
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Install Python 3.11 and minimal utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3.11 \
    python3.11-minimal \
    ca-certificates \
    curl \
    && update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.11 1 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN groupadd --gid 1001 csgen && \
    useradd --uid 1001 --gid csgen --no-create-home --shell /bin/false csgen

# Application directory
WORKDIR /app

# Copy shared generator utilities (build context = cybershield/ root)
COPY docker/digital_twin/shared/ /app/shared/

# Copy hospital server specific files
COPY docker/digital_twin/hospital_server/generator.py /app/generator.py
COPY docker/digital_twin/hospital_server/health_server.py /app/health_server.py
COPY docker/digital_twin/hospital_server/entrypoint.sh /app/entrypoint.sh

# Create log directory with correct ownership
RUN mkdir -p /logs /tmp && \
    chown -R csgen:csgen /app /logs /tmp

# Make entrypoint executable
RUN chmod +x /app/entrypoint.sh

# Switch to non-root
USER csgen

# Environment defaults (overridden by docker-compose.yml or .env)
ENV DT_LOG_PATH=/logs/hospital_server.jsonl \
    DT_HEALTH_FILE_PATH=/tmp/generator_health.json \
    DT_HEALTH_PORT=9002 \
    DT_CONTAINER_HOSTNAME=hospital-server-01 \
    DT_ACCELERATED_MODE=false \
    DT_ACCELERATION_FACTOR=1440 \
    DT_EVENTS_PER_HOUR=295 \
    DT_PROCESS_CREATES_PER_HOUR=75 \
    DT_NETWORK_CONNECTS_PER_HOUR=150 \
    DT_FILE_EVENTS_PER_HOUR=50 \
    DT_AUTH_EVENTS_PER_HOUR=20 \
    DT_BUFFER_SIZE=50 \
    DT_RANDOM_SEED=42 \
    DT_DC_IP=172.20.1.20

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD python3 -c "import urllib.request; r = urllib.request.urlopen('http://localhost:9002/health', timeout=5); exit(0 if r.status == 200 else 1)"

EXPOSE 9002

ENTRYPOINT ["/app/entrypoint.sh"]
