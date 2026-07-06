"""
backend.api.routes.health — Health, Readiness, and Version Endpoints
====================================================================
Provides the standard operational endpoints consumed by load balancers,
container orchestrators (Kubernetes liveness/readiness probes), and
monitoring systems.

Endpoints
---------
GET /health   — Liveness probe: is the process alive?
GET /ready    — Readiness probe: is the process ready to serve traffic?
GET /version  — Version and environment information

Design Notes
------------
- /health returns 200 even if components are degraded (process is alive).
- /ready returns 503 if any component is not operational (not ready for traffic).
- Both responses include component-level detail for debugging.
- Future modules register their own health checks by calling
  register_health_check() from their startup code.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from backend.core.constants import APP_NAME, APP_VERSION, HTTP_503_SERVICE_UNAVAILABLE
from backend.core.health import ComponentHealth, HealthReport, HealthStatus
from backend.core.logging import get_logger
from backend.shared.utils.datetime_utils import utcnow

router = APIRouter()
logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Health Check Registry
# ---------------------------------------------------------------------------
# Future modules register their health checks here at startup:
#
#   from backend.api.routes.health import register_health_check
#
#   async def check_db() -> ComponentHealth:
#       ...
#   register_health_check("database", check_db)
#
_health_checks: dict[str, Any] = {}


def register_health_check(name: str, check_fn: Any) -> None:
    """
    Register a health check function for a named component.

    Parameters
    ----------
    name:
        Unique component name (e.g., "database", "isolation_forest").
    check_fn:
        Async callable returning ComponentHealth.
    """
    _health_checks[name] = check_fn
    logger.info("health_check_registered", component=name)


# ---------------------------------------------------------------------------
# Foundation Health Check
# ---------------------------------------------------------------------------
async def _check_foundation() -> ComponentHealth:
    """Built-in health check for the foundation module itself."""
    return ComponentHealth(
        name="foundation",
        status=HealthStatus.HEALTHY,
        details={
            "version": APP_VERSION,
            "module": "foundation",
        },
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@router.get(
    "/health",
    summary="Liveness probe",
    description=(
        "Returns the current health status of the platform and all registered "
        "components. Always returns HTTP 200 if the process is running "
        "(liveness probe — suitable for container restart decisions)."
    ),
    response_model=None,
    tags=["Health"],
)
async def health_check(request: Request) -> JSONResponse:
    """
    Liveness probe endpoint.

    Returns HTTP 200 for any status — including DEGRADED or UNHEALTHY.
    The container orchestrator uses this to decide whether to RESTART the process.
    Since a degraded process is still running, it should not be restarted.
    """
    settings = request.app.state.settings
    request_id = getattr(request.state, "request_id", "")

    components = [await _check_foundation()]

    for name, check_fn in _health_checks.items():
        try:
            result = await check_fn()
            components.append(result)
        except Exception as exc:
            logger.error(
                "health_check_failed",
                component=name,
                error=str(exc),
                request_id=request_id,
            )
            components.append(
                ComponentHealth(
                    name=name,
                    status=HealthStatus.UNHEALTHY,
                    error=f"Health check raised exception: {type(exc).__name__}",
                )
            )

    report = HealthReport.from_components(
        components=components,
        version=APP_VERSION,
        environment=settings.app_env,
    )

    return JSONResponse(
        status_code=200,   # Always 200 for liveness (process is alive)
        content=report.model_dump(mode="json"),
    )


@router.get(
    "/ready",
    summary="Readiness probe",
    description=(
        "Returns HTTP 200 if all registered components are operational. "
        "Returns HTTP 503 if any component is not ready. "
        "Used by load balancers to decide whether to route traffic to this instance."
    ),
    response_model=None,
    tags=["Health"],
)
async def readiness_check(request: Request) -> JSONResponse:
    """
    Readiness probe endpoint.

    Returns HTTP 503 if any component is UNHEALTHY.
    The load balancer uses this to decide whether to SEND TRAFFIC to this instance.
    """
    settings = request.app.state.settings
    request_id = getattr(request.state, "request_id", "")

    components = [await _check_foundation()]

    for name, check_fn in _health_checks.items():
        try:
            result = await check_fn()
            components.append(result)
        except Exception as exc:
            logger.error(
                "readiness_check_exception",
                component=name,
                error=str(exc),
                request_id=request_id,
            )
            components.append(
                ComponentHealth(
                    name=name,
                    status=HealthStatus.UNHEALTHY,
                    error=f"Check raised: {type(exc).__name__}",
                )
            )

    report = HealthReport.from_components(
        components=components,
        version=APP_VERSION,
        environment=settings.app_env,
    )

    status_code = 200 if report.is_ready else HTTP_503_SERVICE_UNAVAILABLE

    if not report.is_ready:
        unhealthy = [c.name for c in report.components if not c.is_operational]
        logger.warning(
            "readiness_check_failed",
            unhealthy_components=unhealthy,
            request_id=request_id,
        )

    return JSONResponse(
        status_code=status_code,
        content=report.model_dump(mode="json"),
    )


@router.get(
    "/version",
    summary="Version information",
    description="Returns application version, active module, and deployment environment.",
    tags=["Health"],
)
async def version_info(request: Request) -> dict[str, str]:
    """Return version and environment metadata."""
    settings = request.app.state.settings
    return {
        "name": APP_NAME,
        "version": APP_VERSION,
        "module": "foundation",
        "environment": settings.app_env,
        "timestamp": utcnow().isoformat(),
    }
