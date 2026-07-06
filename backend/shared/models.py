"""
backend.shared.models — Common Pydantic Base Models
====================================================
Shared base models used as parent classes across all platform modules.

All domain models should inherit from these bases to ensure:
  - Consistent timestamp handling (always UTC)
  - Consistent ID format (UUID v4)
  - Consistent serialisation behaviour
  - Consistent model configuration (validation, immutability)

Usage
-----
    from backend.shared.models import BaseTimestampedModel, BaseEvent

    class LogEvent(BaseEvent):
        source: LogSource
        event_type: EventType
        host: HostName
        ...

    class Alert(BaseTimestampedModel):
        alert_id: AlertId
        anomaly_score: AnomalyScore
        ...
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from backend.shared.types import AlertId, HostName, RequestId, UserName
from backend.shared.utils.id_utils import generate_id


class CyberShieldBaseModel(BaseModel):
    """
    Root base model for all CyberShield Pydantic models.

    Configuration
    -------------
    - validate_by_default: True — validators run on construction
    - frozen: False — mutable by default (override in domain models)
    - populate_by_name: True — allow both alias and original field names
    - use_enum_values: True — store enum .value, not the enum object
    - ser_json_timedelta: "iso8601" — consistent serialisation
    """

    model_config = ConfigDict(
        validate_default=True,
        populate_by_name=True,
        use_enum_values=True,
        ser_json_timedelta="iso8601",
        json_encoders={
            datetime: lambda v: v.isoformat(),
        },
    )


class BaseTimestampedModel(CyberShieldBaseModel):
    """
    Base model with automatic UTC creation and update timestamps.

    All models that need audit trails should inherit from this.
    """

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp when this record was created.",
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp when this record was last updated.",
    )

    @field_validator("created_at", "updated_at", mode="before")
    @classmethod
    def ensure_utc(cls, v: Any) -> datetime:
        """Ensure all timestamps are UTC-aware."""
        if isinstance(v, str):
            dt = datetime.fromisoformat(v)
        elif isinstance(v, datetime):
            dt = v
        else:
            msg = f"Cannot parse datetime from {type(v).__name__}"
            raise ValueError(msg)
        if dt.tzinfo is None:
            # Naively assume UTC if no timezone provided
            return dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC)

    def touch(self) -> None:
        """Update the updated_at timestamp to now (UTC)."""
        # Note: requires model to not be frozen
        object.__setattr__(self, "updated_at", datetime.now(UTC))


class BaseEvent(BaseTimestampedModel):
    """
    Base model for all ingested log events.

    This is the foundational data structure that flows through the entire
    pipeline from ingestion → normalisation → detection → graph → LLM.

    Every module that processes events receives a subclass of this model,
    ensuring a stable contract regardless of log source or event type.

    Fields
    ------
    event_id:   Globally unique event identifier (UUID v4)
    timestamp:  When the event occurred on the source system (UTC)
    source:     Log source identifier (e.g., "sysmon", "auditd")
    event_type: Normalised event type (e.g., "ProcessCreate", "UserLogin")
    host:       Hostname or IP of the monitored system
    user:       Username associated with the event (or "SYSTEM")
    resource:   Target resource (process name, file path, IP, domain)
    action:     Action performed (execute, read, write, connect, etc.)
    result:     Outcome of the action (success | failure)
    raw_log:    Original log record preserved for debugging and forensics
    """

    event_id: str = Field(
        default_factory=generate_id,
        description="Unique event identifier (UUID v4).",
    )
    timestamp: datetime = Field(
        description="UTC timestamp of the event on the source system.",
    )
    source: str = Field(
        description="Log source identifier (sysmon, windows_event, auditd, etc.).",
    )
    event_type: str = Field(
        description="Normalised event type (ProcessCreate, UserLogin, etc.).",
    )
    host: HostName = Field(
        description="Hostname or IP address of the monitored system.",
    )
    user: UserName = Field(
        description="Username associated with the event.",
    )
    resource: str = Field(
        description="Target resource: process name, file path, IP, domain, etc.",
    )
    action: str = Field(
        description="Action performed: execute, read, write, connect, query, etc.",
    )
    result: str = Field(
        description="Outcome: success | failure | unknown.",
    )
    raw_log: str | None = Field(
        default=None,
        description="Original unparsed log line. Preserved for forensic replay.",
    )

    @field_validator("timestamp", mode="before")
    @classmethod
    def ensure_timestamp_utc(cls, v: Any) -> datetime:
        """Normalise timestamp to UTC-aware datetime."""
        if isinstance(v, str):
            dt = datetime.fromisoformat(v)
        elif isinstance(v, datetime):
            dt = v
        else:
            msg = f"Cannot parse timestamp from {type(v).__name__}"
            raise ValueError(msg)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC)


class BaseAuditRecord(BaseTimestampedModel):
    """
    Base model for all audit log entries.

    Every consequential platform action (alert processing, LLM calls,
    approval decisions, action execution) generates an audit record.
    Audit records are immutable after creation.
    """

    model_config = ConfigDict(
        frozen=True,
        validate_default=True,
        populate_by_name=True,
        use_enum_values=True,
    )

    record_id: str = Field(
        default_factory=generate_id,
        description="Unique audit record identifier.",
    )
    alert_id: AlertId | None = Field(
        default=None,
        description="Associated alert ID, if applicable.",
    )
    request_id: RequestId | None = Field(
        default=None,
        description="HTTP request ID for log correlation.",
    )
    actor: str = Field(
        default="system",
        description="Who performed the action: 'system' or analyst email.",
    )
    action_description: str = Field(
        description="Human-readable description of the audited action.",
    )
    outcome: str = Field(
        description="Outcome: success | failure | pending.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional structured context for the audit record.",
    )
