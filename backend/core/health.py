"""
backend.core.health — Health Check Primitives
=============================================
Provides the data models and check primitives for system health monitoring.

Every module can register its own health check by implementing a function
with the signature:
    async def check() -> ComponentHealth

The API layer aggregates all registered checks and returns a combined
HealthReport via GET /health and GET /ready.

Usage
-----
    from backend.core.health import ComponentHealth, HealthStatus, HealthReport

    async def check_database() -> ComponentHealth:
        try:
            await db.execute("SELECT 1")
            return ComponentHealth(
                name="database",
                status=HealthStatus.HEALTHY,
                details={"driver": "sqlite"},
            )
        except Exception as exc:
            return ComponentHealth(
                name="database",
                status=HealthStatus.UNHEALTHY,
                error=str(exc),
            )
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class HealthStatus(StrEnum):
    """Possible states for a health check component."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"       # operational but with reduced capability
    UNHEALTHY = "unhealthy"     # not operational
    UNKNOWN = "unknown"         # check could not be performed


class ComponentHealth(BaseModel):
    """
    Health status for a single platform component.

    Each module that registers a health check returns this model.
    """

    name: str = Field(description="Component identifier (e.g., 'database', 'llm_api').")
    status: HealthStatus = Field(description="Current health status of the component.")
    details: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional key-value details (e.g., version, latency_ms).",
    )
    error: str | None = Field(
        default=None,
        description="Error message if status is UNHEALTHY. Avoid leaking secrets.",
    )
    checked_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp when the check was performed.",
    )

    model_config = {"frozen": True}

    @property
    def is_healthy(self) -> bool:
        """True if the component is fully operational."""
        return self.status == HealthStatus.HEALTHY

    @property
    def is_operational(self) -> bool:
        """True if the component is healthy or only degraded (not completely down)."""
        return self.status in (HealthStatus.HEALTHY, HealthStatus.DEGRADED)


class HealthReport(BaseModel):
    """
    Aggregated health report for the entire platform.

    Returned by GET /health — includes all registered component checks.
    """

    status: HealthStatus = Field(description="Overall platform health status.")
    version: str = Field(description="Application version string.")
    environment: str = Field(description="Deployment environment (dev/staging/prod).")
    components: list[ComponentHealth] = Field(
        default_factory=list,
        description="Per-component health statuses.",
    )
    checked_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp of the health report generation.",
    )

    model_config = {"frozen": True}

    @classmethod
    def from_components(
        cls,
        components: list[ComponentHealth],
        version: str,
        environment: str,
    ) -> "HealthReport":
        """
        Build a HealthReport by aggregating component statuses.

        Overall status rules:
        - HEALTHY:   all components are healthy
        - DEGRADED:  at least one component is degraded (none unhealthy)
        - UNHEALTHY: at least one component is unhealthy
        - UNKNOWN:   no components registered
        """
        if not components:
            overall = HealthStatus.UNKNOWN
        elif any(c.status == HealthStatus.UNHEALTHY for c in components):
            overall = HealthStatus.UNHEALTHY
        elif any(c.status == HealthStatus.DEGRADED for c in components):
            overall = HealthStatus.DEGRADED
        elif any(c.status == HealthStatus.UNKNOWN for c in components):
            overall = HealthStatus.DEGRADED
        else:
            overall = HealthStatus.HEALTHY

        return cls(
            status=overall,
            version=version,
            environment=environment,
            components=components,
        )

    @property
    def is_ready(self) -> bool:
        """
        True if the application is ready to serve traffic.

        Readiness is more strict than liveness: all components must be
        at least operational (healthy or degraded).
        """
        return all(c.is_operational for c in self.components)
