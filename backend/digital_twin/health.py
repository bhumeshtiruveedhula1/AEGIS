"""
backend.digital_twin.health — Digital Twin Health Check Integration
===================================================================
Provides health check functions for each Digital Twin container that
integrate with the Module 1.1 health check registration system.

Each function conforms to the HealthCheckFn signature:
    async def check_fn() -> ComponentHealth

These are registered at application startup via:
    register_health_check("digital_twin", check_digital_twin)

Design
------
- Health checks are HTTP probes to each container's /health endpoint.
- All probes are independent and run concurrently via asyncio.gather().
- A container is HEALTHY only if its HTTP probe returns 200.
- The overall digital_twin check is HEALTHY iff all probes succeed.
- Non-critical infrastructure (attacker node) is treated as advisory.

Timeout Behaviour
-----------------
Each probe respects DT_HEALTH_CHECK_TIMEOUT_SECONDS (default: 5s).
If the probe times out, the container is marked UNREACHABLE.
The health check itself never raises — it always returns a ComponentHealth.

Usage (called automatically by Module 1.1 health subsystem)
------------------------------------------------------------
    # In backend/api/app.py lifespan:
    from backend.core.health import register_health_check
    from backend.digital_twin.health import check_digital_twin

    register_health_check("digital_twin", check_digital_twin)

    # GET /health will then include:
    # { "name": "digital_twin", "status": "healthy", ... }
"""

from __future__ import annotations

import asyncio
from typing import Any

import structlog

from backend.core.health import ComponentHealth, HealthStatus
from backend.digital_twin.config import get_digital_twin_settings
from backend.digital_twin.models import ContainerHealthStatus, ContainerRole
from backend.digital_twin.registry import get_registry
from backend.shared.utils.datetime_utils import utcnow

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Per-Container HTTP Health Probe
# ---------------------------------------------------------------------------

async def _probe_container(
    role: ContainerRole,
    url: str | None,
    timeout_seconds: int,
) -> tuple[ContainerRole, ContainerHealthStatus, str | None]:
    """
    Probe a container's health endpoint over HTTP.

    Returns
    -------
    (role, status, error_message)
        role:          The container being probed
        status:        HEALTHY | UNHEALTHY | UNREACHABLE | UNKNOWN
        error_message: None on success, error detail on failure
    """
    if url is None:
        # Attacker container has no health endpoint — it's always advisory
        logger.debug("container_probe_skipped_no_endpoint", role=role.value)
        return (role, ContainerHealthStatus.UNKNOWN, "No health endpoint configured")

    try:
        import urllib.request  # stdlib — no additional deps  # noqa: PLC0415

        loop = asyncio.get_event_loop()
        response = await asyncio.wait_for(
            loop.run_in_executor(
                None,
                lambda: urllib.request.urlopen(url, timeout=timeout_seconds),
            ),
            timeout=timeout_seconds + 1,
        )
        if response.status == 200:
            return (role, ContainerHealthStatus.HEALTHY, None)
        return (
            role,
            ContainerHealthStatus.UNHEALTHY,
            f"HTTP {response.status} from {url}",
        )

    except asyncio.TimeoutError:
        logger.warning("container_probe_timeout", role=role.value, url=url)
        return (role, ContainerHealthStatus.UNREACHABLE, f"Probe timeout after {timeout_seconds}s")

    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "container_probe_failed",
            role=role.value,
            url=url,
            error=str(exc),
        )
        return (role, ContainerHealthStatus.UNREACHABLE, str(exc))


# ---------------------------------------------------------------------------
# Aggregate Digital Twin Health Check
# ---------------------------------------------------------------------------

async def check_digital_twin() -> ComponentHealth:
    """
    Aggregate health check for the entire Digital Twin environment.

    Probes all four containers concurrently and returns a ComponentHealth
    that is HEALTHY only when all critical containers are reachable.

    Critical containers: hospital-server, domain-controller, ot-node
    Advisory containers: attacker (no health endpoint)
    """
    settings = get_digital_twin_settings()
    registry = get_registry()
    timeout = settings.health_check_timeout_seconds

    endpoints = {
        ContainerRole.HOSPITAL_SERVER: registry.get_endpoint(ContainerRole.HOSPITAL_SERVER),
        ContainerRole.DOMAIN_CONTROLLER: registry.get_endpoint(ContainerRole.DOMAIN_CONTROLLER),
        ContainerRole.OT_NODE: registry.get_endpoint(ContainerRole.OT_NODE),
        ContainerRole.ATTACKER: registry.get_endpoint(ContainerRole.ATTACKER),
    }

    # Run all probes concurrently
    probe_tasks = [
        _probe_container(
            role=role,
            url=ep.health_check_url if ep else None,
            timeout_seconds=timeout,
        )
        for role, ep in endpoints.items()
    ]
    results = await asyncio.gather(*probe_tasks, return_exceptions=False)

    # Update registry with probe results
    details: dict[str, Any] = {}
    critical_failures = 0
    CRITICAL_ROLES = {
        ContainerRole.HOSPITAL_SERVER,
        ContainerRole.DOMAIN_CONTROLLER,
        ContainerRole.OT_NODE,
    }

    for role, status, error_msg in results:
        await registry.update_container_status(
            role=role,
            status=status,
            error_message=error_msg,
        )
        details[role.value] = {
            "status": status.value,
            "error": error_msg,
        }
        if role in CRITICAL_ROLES and status != ContainerHealthStatus.HEALTHY:
            critical_failures += 1

    # Overall status
    if critical_failures == 0:
        overall = HealthStatus.HEALTHY
    else:
        # All containers unreachable = likely Docker not running
        all_unreachable = all(
            st == ContainerHealthStatus.UNREACHABLE
            for _, st, _ in results
            if _ in CRITICAL_ROLES
        )
        overall = HealthStatus.DEGRADED if not all_unreachable else HealthStatus.UNHEALTHY

    # Aggregate events generated
    dt_health = await registry.get_digital_twin_health()
    details["total_events_generated"] = dt_health.total_events_generated

    return ComponentHealth(
        name="digital_twin",
        status=overall,
        details=details,
        checked_at=utcnow(),
    )


# ---------------------------------------------------------------------------
# Individual Container Health Checks
# For direct registration of per-component checks if desired.
# ---------------------------------------------------------------------------

async def check_hospital_server() -> ComponentHealth:
    """Health check for the hospital server container only."""
    settings = get_digital_twin_settings()
    registry = get_registry()
    endpoint = registry.get_endpoint(ContainerRole.HOSPITAL_SERVER)

    url = endpoint.health_check_url if endpoint else None
    _, status, error = await _probe_container(
        ContainerRole.HOSPITAL_SERVER, url, settings.health_check_timeout_seconds
    )
    await registry.update_container_status(
        ContainerRole.HOSPITAL_SERVER, status=status, error_message=error
    )

    hs = HealthStatus.HEALTHY if status == ContainerHealthStatus.HEALTHY else HealthStatus.UNHEALTHY
    return ComponentHealth(
        name="hospital_server",
        status=hs,
        details={"ip": settings.hospital_server_ip, "error": error},
        checked_at=utcnow(),
    )


async def check_domain_controller() -> ComponentHealth:
    """Health check for the domain controller container only."""
    settings = get_digital_twin_settings()
    registry = get_registry()
    endpoint = registry.get_endpoint(ContainerRole.DOMAIN_CONTROLLER)

    url = endpoint.health_check_url if endpoint else None
    _, status, error = await _probe_container(
        ContainerRole.DOMAIN_CONTROLLER, url, settings.health_check_timeout_seconds
    )
    await registry.update_container_status(
        ContainerRole.DOMAIN_CONTROLLER, status=status, error_message=error
    )

    hs = HealthStatus.HEALTHY if status == ContainerHealthStatus.HEALTHY else HealthStatus.UNHEALTHY
    return ComponentHealth(
        name="domain_controller",
        status=hs,
        details={"ip": settings.domain_controller_ip, "error": error},
        checked_at=utcnow(),
    )


async def check_ot_node() -> ComponentHealth:
    """Health check for the OT node container only."""
    settings = get_digital_twin_settings()
    registry = get_registry()
    endpoint = registry.get_endpoint(ContainerRole.OT_NODE)

    url = endpoint.health_check_url if endpoint else None
    _, status, error = await _probe_container(
        ContainerRole.OT_NODE, url, settings.health_check_timeout_seconds
    )
    await registry.update_container_status(
        ContainerRole.OT_NODE, status=status, error_message=error
    )

    hs = HealthStatus.HEALTHY if status == ContainerHealthStatus.HEALTHY else HealthStatus.UNHEALTHY
    return ComponentHealth(
        name="ot_node",
        status=hs,
        details={"ip": settings.ot_node_ip, "error": error},
        checked_at=utcnow(),
    )
