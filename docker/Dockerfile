# =============================================================================
# CyberShield — Production Docker Image (Multi-stage)
# =============================================================================
# Stages:
#   builder  — installs Python dependencies in isolated layer
#   runtime  — minimal runtime image (no build tools)
#
# Usage:
#   docker build -f docker/Dockerfile -t cybershield:latest .
#   docker run -p 8000:8000 --env-file .env cybershield:latest
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1: Builder — dependency installation
# ---------------------------------------------------------------------------
FROM python:3.11-slim AS builder

# Prevent .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy only requirements first (layer cache optimisation)
COPY requirements.txt .

# Install production dependencies into /build/venv
RUN python -m venv /build/venv && \
    /build/venv/bin/pip install --upgrade pip && \
    /build/venv/bin/pip install -r requirements.txt

# ---------------------------------------------------------------------------
# Stage 2: Runtime — minimal production image
# ---------------------------------------------------------------------------
FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/venv/bin:$PATH" \
    # Production defaults (override via --env-file or environment variables)
    APP_ENV=production \
    LOG_LEVEL=INFO \
    LOG_FORMAT=json \
    APP_HOST=0.0.0.0 \
    APP_PORT=8000

# Non-root user for security
RUN groupadd --gid 1001 cybershield && \
    useradd --uid 1001 --gid cybershield --no-create-home --shell /bin/false cybershield

WORKDIR /app

# Copy virtualenv from builder stage
COPY --from=builder /build/venv ./venv

# Copy application source code
COPY backend/ ./backend/
COPY pyproject.toml .

# Create required runtime directories with correct ownership
RUN mkdir -p /app/data /app/models /app/reports && \
    chown -R cybershield:cybershield /app

# Switch to non-root user
USER cybershield

# Health check for container orchestrators
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

EXPOSE 8000

# Production server: 4 workers, no reload
CMD ["uvicorn", "backend.api.app:create_app", \
     "--factory", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "4", \
     "--log-level", "warning"]
