"""
backend.digital_twin.registry — Digital Twin Service Registry
=============================================================
The DigitalTwinRegistry is the authoritative, in-process catalogue of
all Digital Twin containers, their network endpoints, and their telemetry
sources.

Purpose
-------
Future modules import and call `get_registry()` to:

1. Discover available telemetry log paths (for ingestion / normalization)
2. Check container health status
3. Resolve container IPs and hostnames
4. Understand the network topology
5. Query which event types each container produces

Singleton Design
----------------
The registry is a lazy singleton constructed once at application startup.
It reads from DigitalTwinSettings, which reads from environment variables.
This means the registry always reflects the current deployment configuration.

Usage
-----
    from backend.digital_twin.registry import get_registry

    registry = get_registry()

    # Discover all telemetry sources
    for source in registry.list_telemetry_sources():
        print(source.host_log_path, source.event_types)

    # Check if a specific container is reachable
    status = await registry.check_container_health(ContainerRole.HOSPITAL_SERVER)

    # Get the full topology
    topology = registry.get_topology()

Integration Points
------------------
- Module 1.3 (Normalization): calls list_telemetry_sources() to find log paths
- Module 2.1 (Detection):     calls get_container_by_role() to map alerts to containers
- Module 3.2 (Response):      calls get_endpoint() to target response actions
- Module 4 (Dashboard):       calls get_digital_twin_health() for status metrics
"""

from __future__ import annotations

import asyncio
import functools
import time
from datetime import UTC
from typing import TYPE_CHECKING

import structlog

from backend.digital_twin.config import DigitalTwinSettings, get_digital_twin_settings
from backend.digital_twin.models import (
    ContainerEndpoint,
    ContainerHealthStatus,
    ContainerRole,
    ContainerStatus,
    DigitalTwinHealth,
    LogSource,
    NetworkSegment,
    NetworkSubnet,
    NetworkTopology,
    TelemetryEventType,
    TelemetrySource,
)
from backend.shared.utils.datetime_utils import utcnow
from backend.shared.utils.id_utils import generate_id

if TYPE_CHECKING:
    pass

logger = structlog.get_logger(__name__)


class DigitalTwinRegistry:
    """
    Authoritative registry of all Digital Twin infrastructure.

    Constructs a static topology from DigitalTwinSettings and provides
    discovery, health aggregation, and service lookup for all modules.

    Thread Safety
    -------------
    The registry is read-mostly after construction. All mutations
    (status updates) are lock-protected. This is safe for FastAPI's
    async worker model.
    """

    def __init__(self, settings: DigitalTwinSettings) -> None:
        self._settings = settings
        self._lock = asyncio.Lock()
        self._container_statuses: dict[ContainerRole, ContainerStatus] = {}
        self._topology = self._build_topology()
        self._telemetry_sources = self._build_telemetry_sources()
        self._endpoints = self._build_endpoints()
        self._started_at = utcnow()

        # Initialise all statuses as STARTING
        for role in [
            ContainerRole.HOSPITAL_SERVER,
            ContainerRole.DOMAIN_CONTROLLER,
            ContainerRole.OT_NODE,
            ContainerRole.ATTACKER,
        ]:
            self._container_statuses[role] = self._build_initial_status(role)

        logger.info(
            "digital_twin_registry_initialised",
            containers=len(self._container_statuses),
            telemetry_sources=len(self._telemetry_sources),
        )

    # -----------------------------------------------------------------------
    # Static Topology Construction
    # -----------------------------------------------------------------------

    def _build_topology(self) -> NetworkTopology:
        """Build the network topology from settings."""
        return NetworkTopology(
            network_name="cybershield-net",
            description=(
                "CyberShield Digital Twin Docker Network — "
                "4-segment isolation architecture (IT / OT / Management / Attacker)"
            ),
            subnets=[
                NetworkSubnet(
                    name="management",
                    segment=NetworkSegment.MANAGEMENT,
                    cidr="172.20.0.0/24",
                    description="Management backbone — API service and service discovery.",
                    containers=["cybershield-api"],
                ),
                NetworkSubnet(
                    name="it-segment",
                    segment=NetworkSegment.IT,
                    cidr="172.20.1.0/24",
                    description=(
                        "IT environment — Hospital server and Domain Controller. "
                        "Represents corporate IT infrastructure of a hospital CNI."
                    ),
                    containers=["hospital-server", "domain-controller"],
                ),
                NetworkSubnet(
                    name="ot-segment",
                    segment=NetworkSegment.OT,
                    cidr="172.20.2.0/24",
                    description=(
                        "Operational Technology environment — PLC/sensor node. "
                        "Physically isolated from IT and Attacker segments."
                    ),
                    containers=["ot-node"],
                ),
                NetworkSubnet(
                    name="attacker-segment",
                    segment=NetworkSegment.ATTACKER,
                    cidr="172.20.3.0/24",
                    description=(
                        "Controlled attacker environment. "
                        "No inbound ports exposed. "
                        "Attack scripts are injected by future modules."
                    ),
                    containers=["attacker"],
                ),
            ],
        )

    def _build_telemetry_sources(self) -> list[TelemetrySource]:
        """Construct the complete list of telemetry sources from settings."""
        s = self._settings
        return [
            # ----------------------------------------------------------------
            # Hospital Server — multiple event type categories
            # ----------------------------------------------------------------
            TelemetrySource(
                source_id="hospital_server_main",
                container_role=ContainerRole.HOSPITAL_SERVER,
                log_source=LogSource.HOSPITAL_SERVER,
                event_types=[
                    TelemetryEventType.PROCESS_CREATE,
                    TelemetryEventType.PROCESS_TERMINATE,
                    TelemetryEventType.NETWORK_CONNECT,
                    TelemetryEventType.FILE_CREATE,
                    TelemetryEventType.FILE_ACCESS,
                    TelemetryEventType.DB_QUERY,
                    TelemetryEventType.USER_LOGON,
                    TelemetryEventType.USER_LOGON_FAILED,
                ],
                log_file_path="/logs/hospital_server.jsonl",
                host_log_path=str(s.hospital_server_log_path),
                description=(
                    "All telemetry from the hospital server including process creation, "
                    "file activity, authentication, network connections, and database queries. "
                    "Primary IT telemetry source for Week 1 baseline generation."
                ),
            ),

            # ----------------------------------------------------------------
            # Domain Controller — authentication and identity events
            # ----------------------------------------------------------------
            TelemetrySource(
                source_id="domain_controller_auth",
                container_role=ContainerRole.DOMAIN_CONTROLLER,
                log_source=LogSource.DOMAIN_CONTROLLER,
                event_types=[
                    TelemetryEventType.USER_LOGON,
                    TelemetryEventType.USER_LOGON_FAILED,
                    TelemetryEventType.USER_LOGOFF,
                    TelemetryEventType.PRIVILEGE_ASSIGNED,
                    TelemetryEventType.USER_CREATED,
                    TelemetryEventType.USER_DELETED,
                    TelemetryEventType.GROUP_MEMBERSHIP_CHANGED,
                    TelemetryEventType.KERBEROS_REQUEST,
                ],
                log_file_path="/logs/domain_controller.jsonl",
                host_log_path=str(s.domain_controller_log_path),
                description=(
                    "Authentication and identity management events from the Domain Controller. "
                    "Models Windows Event IDs: 4624 (logon), 4625 (failed), 4672 (privilege), "
                    "4720 (user created), 4726 (user deleted), 4728 (group membership). "
                    "Primary source for credential-based anomaly detection."
                ),
            ),

            # ----------------------------------------------------------------
            # OT Node — Modbus simulation events
            # ----------------------------------------------------------------
            TelemetrySource(
                source_id="ot_node_modbus",
                container_role=ContainerRole.OT_NODE,
                log_source=LogSource.OT_NODE,
                event_types=[
                    TelemetryEventType.MODBUS_READ,
                    TelemetryEventType.MODBUS_WRITE,
                    TelemetryEventType.MODBUS_HEARTBEAT,
                    TelemetryEventType.PLC_STATUS,
                ],
                log_file_path="/logs/ot_node.jsonl",
                host_log_path=str(s.ot_node_log_path),
                description=(
                    "Modbus TCP simulation events from the OT PLC node. "
                    f"Normal reads: registers {s.ot_normal_read_registers_start}-"
                    f"{s.ot_normal_read_registers_end} every {s.ot_read_interval_seconds}s. "
                    f"Normal writes: registers {s.ot_normal_write_registers_start}-"
                    f"{s.ot_normal_write_registers_end} every {s.ot_write_interval_seconds}s. "
                    "Cross-subnet connections or unusual register access are key anomaly signals."
                ),
            ),
        ]

    def _build_endpoints(self) -> dict[ContainerRole, ContainerEndpoint]:
        """Build container endpoint descriptors from settings."""
        s = self._settings
        return {
            ContainerRole.HOSPITAL_SERVER: ContainerEndpoint(
                role=ContainerRole.HOSPITAL_SERVER,
                hostname="hospital-server",
                ip_address=s.hospital_server_ip,
                network_segment=NetworkSegment.IT,
                health_check_url=f"http://{s.hospital_server_ip}:{s.hospital_server_port}/health",
                container_name="cybershield-hospital-server",
            ),
            ContainerRole.DOMAIN_CONTROLLER: ContainerEndpoint(
                role=ContainerRole.DOMAIN_CONTROLLER,
                hostname="domain-controller",
                ip_address=s.domain_controller_ip,
                network_segment=NetworkSegment.IT,
                health_check_url=(
                    f"http://{s.domain_controller_ip}:{s.domain_controller_port}/health"
                ),
                container_name="cybershield-domain-controller",
            ),
            ContainerRole.OT_NODE: ContainerEndpoint(
                role=ContainerRole.OT_NODE,
                hostname="ot-node",
                ip_address=s.ot_node_ip,
                network_segment=NetworkSegment.OT,
                health_check_url=f"http://{s.ot_node_ip}:{s.ot_node_port}/health",
                container_name="cybershield-ot-node",
            ),
            ContainerRole.ATTACKER: ContainerEndpoint(
                role=ContainerRole.ATTACKER,
                hostname="attacker",
                ip_address=s.attacker_ip,
                network_segment=NetworkSegment.ATTACKER,
                health_check_url=None,  # No inbound ports by design
                container_name="cybershield-attacker",
            ),
        }

    def _build_initial_status(self, role: ContainerRole) -> ContainerStatus:
        """Construct the initial STARTING status for a container."""
        endpoint = self._endpoints[role]
        sources = [s for s in self._telemetry_sources if s.container_role == role]
        return ContainerStatus(
            role=role,
            container_name=endpoint.container_name,
            status=ContainerHealthStatus.STARTING,
            ip_address=endpoint.ip_address,
            network_segment=endpoint.network_segment,
            telemetry_sources=sources,
        )

    # -----------------------------------------------------------------------
    # Public Discovery API
    # -----------------------------------------------------------------------

    def list_telemetry_sources(
        self,
        role: ContainerRole | None = None,
    ) -> list[TelemetrySource]:
        """
        Return all registered telemetry sources.

        Parameters
        ----------
        role : optional
            Filter by container role. Returns all sources when None.

        Returns
        -------
        list[TelemetrySource]
            Ordered list of telemetry source descriptors.

        Usage (Module 1.3 Normalization)
        ---------------------------------
            for source in registry.list_telemetry_sources():
                for event in parse_jsonl(source.host_log_path):
                    normalise(event)
        """
        if role is None:
            return list(self._telemetry_sources)
        return [s for s in self._telemetry_sources if s.container_role == role]

    def get_endpoint(self, role: ContainerRole) -> ContainerEndpoint | None:
        """
        Return the network endpoint for a container.

        Usage (Module 3.2 Response)
        ----------------------------
            endpoint = registry.get_endpoint(ContainerRole.HOSPITAL_SERVER)
            action_target = endpoint.ip_address
        """
        return self._endpoints.get(role)

    def get_topology(self) -> NetworkTopology:
        """Return the network topology model."""
        return self._topology

    def get_container_status(self, role: ContainerRole) -> ContainerStatus | None:
        """Return the most recent health status for a container."""
        return self._container_statuses.get(role)

    def list_all_statuses(self) -> list[ContainerStatus]:
        """Return all container statuses."""
        return list(self._container_statuses.values())

    def get_all_log_paths(self) -> list[str]:
        """
        Return all host-side log file paths for all active telemetry sources.

        Usage (Module 1.3)
        -------------------
            for path in registry.get_all_log_paths():
                ingest_file(path)
        """
        return [s.host_log_path for s in self._telemetry_sources if s.is_active]

    # -----------------------------------------------------------------------
    # Health Status Updates
    # -----------------------------------------------------------------------

    async def update_container_status(
        self,
        role: ContainerRole,
        *,
        status: ContainerHealthStatus,
        events_generated: int | None = None,
        error_message: str | None = None,
        uptime_seconds: float | None = None,
    ) -> None:
        """
        Update the runtime health status of a container.

        Called by the health check subsystem after probing each container.
        Thread-safe via asyncio.Lock.
        """
        async with self._lock:
            existing = self._container_statuses.get(role)
            if existing is None:
                logger.warning("registry_update_unknown_role", role=role)
                return

            # Build updated status (models are frozen, so we replace)
            import dataclasses  # noqa: PLC0415
            update_kwargs: dict = {
                "status": status,
                "checked_at": utcnow(),
                "error_message": error_message,
            }
            if events_generated is not None:
                update_kwargs["events_generated"] = events_generated
            if uptime_seconds is not None:
                update_kwargs["uptime_seconds"] = uptime_seconds

            self._container_statuses[role] = existing.model_copy(update=update_kwargs)

            logger.debug(
                "container_status_updated",
                role=role.value,
                status=status.value,
                events_generated=events_generated,
            )

    # -----------------------------------------------------------------------
    # Aggregate Health
    # -----------------------------------------------------------------------

    async def get_digital_twin_health(self) -> DigitalTwinHealth:
        """
        Compute and return aggregate health for the entire Digital Twin.

        The overall status is:
          - HEALTHY    → all containers are healthy
          - UNHEALTHY  → one or more containers are unhealthy
          - STARTING   → at least one container is still starting
          - UNKNOWN    → no status information available
        """
        statuses = self.list_all_statuses()
        total_events = sum(s.events_generated for s in statuses)

        status_set = {s.status for s in statuses}

        if not statuses:
            overall = ContainerHealthStatus.UNKNOWN
        elif all(s.status == ContainerHealthStatus.HEALTHY for s in statuses):
            overall = ContainerHealthStatus.HEALTHY
        elif ContainerHealthStatus.STARTING in status_set:
            overall = ContainerHealthStatus.STARTING
        else:
            overall = ContainerHealthStatus.UNHEALTHY

        return DigitalTwinHealth(
            overall_status=overall,
            containers=statuses,
            topology=self._topology,
            total_events_generated=total_events,
            checked_at=utcnow(),
        )

    # -----------------------------------------------------------------------
    # Uptime
    # -----------------------------------------------------------------------

    @property
    def uptime_seconds(self) -> float:
        """Seconds since the registry was initialised."""
        return (utcnow() - self._started_at).total_seconds()


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

@functools.lru_cache(maxsize=1)
def get_registry() -> DigitalTwinRegistry:
    """
    Return the Digital Twin registry singleton.

    Constructed once at first call. Subsequent calls return the cached instance.

    All modules that need Digital Twin service discovery should import
    and call this function:

        from backend.digital_twin.registry import get_registry
        registry = get_registry()
    """
    settings = get_digital_twin_settings()
    return DigitalTwinRegistry(settings=settings)
