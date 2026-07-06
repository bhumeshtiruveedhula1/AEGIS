"""
backend.digital_twin.models — Digital Twin Pydantic Models
===========================================================
All data models describing the state, identity, and health of Digital Twin
components. These models are consumed by:

  - backend.digital_twin.registry    (aggregation)
  - backend.digital_twin.health      (health checks)
  - backend.api.routes.health        (exposed via /health endpoint)
  - tests                            (fixtures and assertions)
  - future modules                   (telemetry source discovery)

Model Hierarchy
---------------
  NetworkSegment
  TelemetrySource
  ContainerEndpoint
  ContainerStatus
  DigitalTwinHealth
  NetworkTopology
  GeneratorConfig
  TelemetryVolume
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import Field, field_validator

from backend.shared.models import BaseTimestampedModel
from backend.shared.utils.datetime_utils import utcnow


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class NetworkSegment(StrEnum):
    """Logical network segments within the Digital Twin topology."""

    MANAGEMENT = "management"   # 172.20.0.0/24 — API backbone
    IT = "it"                   # 172.20.1.0/24 — Hospital + DC
    OT = "ot"                   # 172.20.2.0/24 — PLC / Sensor
    ATTACKER = "attacker"       # 172.20.3.0/24 — Controlled attack source


class ContainerRole(StrEnum):
    """Functional role of each Digital Twin container."""

    HOSPITAL_SERVER = "hospital_server"
    DOMAIN_CONTROLLER = "domain_controller"
    OT_NODE = "ot_node"
    ATTACKER = "attacker"
    API = "api"


class ContainerHealthStatus(StrEnum):
    """Container operational status (mirrors Docker HEALTHCHECK states)."""

    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    STARTING = "starting"
    UNREACHABLE = "unreachable"
    UNKNOWN = "unknown"


class TelemetryEventType(StrEnum):
    """
    Telemetry event type categories produced by Digital Twin containers.
    Maps to the event_type field in BaseEvent.
    """
    # Hospital Server events
    PROCESS_CREATE = "ProcessCreate"
    PROCESS_TERMINATE = "ProcessTerminate"
    NETWORK_CONNECT = "NetworkConnect"
    FILE_CREATE = "FileCreate"
    FILE_ACCESS = "FileAccess"
    DB_QUERY = "DatabaseQuery"

    # Domain Controller events
    USER_LOGON = "UserLogon"
    USER_LOGON_FAILED = "UserLogonFailed"
    USER_LOGOFF = "UserLogoff"
    PRIVILEGE_ASSIGNED = "PrivilegeAssigned"
    USER_CREATED = "UserCreated"
    USER_DELETED = "UserDeleted"
    GROUP_MEMBERSHIP_CHANGED = "GroupMembershipChanged"
    KERBEROS_REQUEST = "KerberosTicketRequest"

    # OT Node events
    MODBUS_READ = "ModbusRead"
    MODBUS_WRITE = "ModbusWrite"
    MODBUS_HEARTBEAT = "ModbusHeartbeat"
    PLC_STATUS = "PLCStatus"

    # Attacker events (future — populated by attack scripts in Module 3.x)
    RECON_SCAN = "ReconScan"
    EXPLOIT_ATTEMPT = "ExploitAttempt"


class LogSource(StrEnum):
    """
    Canonical log source identifiers. Must match the `source` field in BaseEvent.
    These values are used by the normalization module to route parsing logic.
    """
    HOSPITAL_SERVER = "hospital_server"
    DOMAIN_CONTROLLER = "domain_controller"
    OT_NODE = "ot_node"
    ATTACKER = "attacker"


# ---------------------------------------------------------------------------
# Telemetry Source Descriptor
# ---------------------------------------------------------------------------

class TelemetrySource(BaseTimestampedModel):
    """
    Describes a log source produced by a Digital Twin container.

    One container may produce multiple TelemetrySources (e.g., the hospital server
    produces both process creation logs and authentication logs).

    The normalization module (Module 1.3) uses this to discover and route
    log files to the appropriate parser.
    """

    source_id: str = Field(
        description="Unique identifier for this telemetry source.",
        examples=["hospital_server_process", "dc_auth", "ot_modbus"],
    )
    container_role: ContainerRole = Field(
        description="Which container this source belongs to.",
    )
    log_source: LogSource = Field(
        description="Canonical log source identifier (maps to BaseEvent.source).",
    )
    event_types: list[TelemetryEventType] = Field(
        description="Event types this source can produce.",
    )
    log_file_path: str = Field(
        description="Absolute path to the JSONL log file inside the container.",
        examples=["/logs/hospital_server.jsonl"],
    )
    host_log_path: str = Field(
        description="Path to the JSONL log file on the Docker host (via volume mount).",
        examples=["./data/digital_twin/hospital_server/hospital_server.jsonl"],
    )
    description: str = Field(
        description="Human-readable description of what this source emits.",
    )
    is_active: bool = Field(
        default=True,
        description="Whether this source is currently generating telemetry.",
    )


# ---------------------------------------------------------------------------
# Container Endpoint
# ---------------------------------------------------------------------------

class ContainerEndpoint(BaseTimestampedModel):
    """
    Network endpoint descriptor for a Digital Twin container.
    Provides service discovery information for module-to-container communication.
    """

    role: ContainerRole
    hostname: str = Field(description="DNS name of the container within the Docker network.")
    ip_address: str = Field(description="Static IP address within the Docker network.")
    network_segment: NetworkSegment
    health_check_url: str | None = Field(
        default=None,
        description=(
            "URL of the container's health check endpoint. "
            "None for containers without HTTP health endpoints (e.g., attacker)."
        ),
    )
    container_name: str = Field(description="Docker container name.")


# ---------------------------------------------------------------------------
# Container Status
# ---------------------------------------------------------------------------

class ContainerStatus(BaseTimestampedModel):
    """
    Runtime health and operational status for a single Digital Twin container.

    This model is populated by the health check subsystem and exposed via
    the /health endpoint aggregated response.
    """

    role: ContainerRole
    container_name: str
    status: ContainerHealthStatus = ContainerHealthStatus.UNKNOWN
    ip_address: str
    network_segment: NetworkSegment
    telemetry_sources: list[TelemetrySource] = Field(default_factory=list)
    events_generated: int = Field(
        default=0,
        ge=0,
        description="Total telemetry events generated since container start.",
    )
    last_event_at: datetime | None = Field(
        default=None,
        description="UTC timestamp of the most recent telemetry event.",
    )
    uptime_seconds: float | None = Field(
        default=None,
        description="Container uptime in seconds (from container start).",
    )
    error_message: str | None = Field(
        default=None,
        description="Last error message if container is unhealthy.",
    )
    checked_at: datetime = Field(
        default_factory=utcnow,
        description="UTC timestamp when this status was last checked.",
    )

    @property
    def is_healthy(self) -> bool:
        """True if the container is in the HEALTHY state."""
        return self.status == ContainerHealthStatus.HEALTHY

    @property
    def is_generating(self) -> bool:
        """True if the container has generated at least one telemetry event."""
        return self.events_generated > 0


# ---------------------------------------------------------------------------
# Network Topology
# ---------------------------------------------------------------------------

class NetworkSubnet(BaseTimestampedModel):
    """A single subnet within the Digital Twin Docker network."""

    name: str
    segment: NetworkSegment
    cidr: str
    description: str
    containers: list[str] = Field(
        default_factory=list,
        description="Container names in this subnet.",
    )

    @field_validator("cidr")
    @classmethod
    def validate_cidr(cls, v: str) -> str:
        """Basic CIDR format validation."""
        parts = v.split("/")
        if len(parts) != 2:
            raise ValueError(f"CIDR must be in x.x.x.x/n format, got: {v}")
        prefix = int(parts[1])
        if not (0 <= prefix <= 32):
            raise ValueError(f"CIDR prefix must be 0-32, got: {prefix}")
        return v


class NetworkTopology(BaseTimestampedModel):
    """
    Complete network topology of the Digital Twin environment.

    Describes all subnets, their CIDRs, purposes, and the containers
    assigned to each. Future modules can query this to understand
    expected communication paths and flag anomalies.
    """

    network_name: str = Field(default="cybershield-net")
    subnets: list[NetworkSubnet] = Field(default_factory=list)
    description: str = Field(
        default="CyberShield Digital Twin Docker Network — 4-segment architecture",
    )

    @property
    def it_subnet(self) -> NetworkSubnet | None:
        """Return the IT segment subnet descriptor."""
        return next((s for s in self.subnets if s.segment == NetworkSegment.IT), None)

    @property
    def ot_subnet(self) -> NetworkSubnet | None:
        """Return the OT segment subnet descriptor."""
        return next((s for s in self.subnets if s.segment == NetworkSegment.OT), None)

    @property
    def attacker_subnet(self) -> NetworkSubnet | None:
        """Return the Attacker segment subnet descriptor."""
        return next((s for s in self.subnets if s.segment == NetworkSegment.ATTACKER), None)


# ---------------------------------------------------------------------------
# Generator Configuration
# ---------------------------------------------------------------------------

class GeneratorConfig(BaseTimestampedModel):
    """
    Runtime configuration snapshot for a Digital Twin telemetry generator.

    Each container generator reads its config from environment variables
    and exposes this model via its /config health endpoint for introspection.
    """

    container_role: ContainerRole
    accelerated_mode: bool
    acceleration_factor: int = Field(ge=1)
    events_per_hour_target: int = Field(ge=1)
    output_path: str
    is_running: bool = False
    started_at: datetime | None = None


# ---------------------------------------------------------------------------
# Telemetry Volume Statistics
# ---------------------------------------------------------------------------

class TelemetryVolume(BaseTimestampedModel):
    """
    Per-container telemetry volume statistics.
    Used by future monitoring and dashboard modules.
    """

    container_role: ContainerRole
    total_events: int = Field(default=0, ge=0)
    events_last_hour: int = Field(default=0, ge=0)
    error_events: int = Field(default=0, ge=0)
    last_flush_at: datetime | None = None
    bytes_written: int = Field(default=0, ge=0)

    @property
    def error_rate(self) -> float:
        """Fraction of events that are errors. Returns 0.0 if no events."""
        if self.total_events == 0:
            return 0.0
        return self.error_events / self.total_events


# ---------------------------------------------------------------------------
# Digital Twin Aggregate Health
# ---------------------------------------------------------------------------

class DigitalTwinHealth(BaseTimestampedModel):
    """
    Aggregate health model for the entire Digital Twin environment.

    This is the top-level model returned by the digital_twin health check
    and embedded in the /health endpoint response.
    """

    overall_status: ContainerHealthStatus = ContainerHealthStatus.UNKNOWN
    containers: list[ContainerStatus] = Field(default_factory=list)
    topology: NetworkTopology | None = None
    total_events_generated: int = Field(default=0, ge=0)
    checked_at: datetime = Field(default_factory=utcnow)
    environment: str = Field(
        default="digital_twin",
        description="Module identifier.",
    )

    @property
    def healthy_count(self) -> int:
        return sum(1 for c in self.containers if c.is_healthy)

    @property
    def unhealthy_count(self) -> int:
        return sum(1 for c in self.containers if not c.is_healthy)

    @property
    def is_fully_operational(self) -> bool:
        """True only when ALL registered containers are healthy."""
        return bool(self.containers) and self.unhealthy_count == 0

    def to_summary(self) -> dict[str, Any]:
        """Compact summary dict for embedding in /health response."""
        return {
            "digital_twin_status": str(self.overall_status),
            "containers_healthy": self.healthy_count,
            "containers_total": len(self.containers),
            "total_events_generated": self.total_events_generated,
            "checked_at": self.checked_at.isoformat(),
        }
