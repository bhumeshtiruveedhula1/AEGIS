"""
docker/digital_twin/shared/event_schema.py
==========================================
Canonical telemetry event schema used by ALL Digital Twin generators.

This schema mirrors backend.shared.models.BaseEvent but is implemented
here as a plain dataclass/dict so it has ZERO external dependencies.
Generators run inside Docker containers that only have Python stdlib + pydantic.

Schema Contract
---------------
Every event emitted by any generator MUST have exactly these fields.
This is validated at write time by the writer module.

The normalization module (backend.normalization) expects this schema
and will raise a SchemaValidationError for any field violations.

Fields
------
event_id     : str       — UUID v4 (generated per event)
timestamp    : str       — ISO 8601 UTC with microseconds (YYYY-MM-DDTHH:MM:SS.ffffffZ)
source       : str       — Canonical log source (hospital_server|domain_controller|ot_node|attacker)
event_type   : str       — Event type (ProcessCreate|UserLogon|ModbusRead|...)
host         : str       — Hostname of the emitting container
user         : str       — User or service account (SYSTEM for no-user events)
resource     : str       — Target resource (process, file, register, IP, domain)
action       : str       — Action performed (execute|read|write|authenticate|connect|query)
result       : str       — Outcome (success|failure)
raw_log      : str       — JSON-encoded original event payload (preserved verbatim)
"""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any


# ---------------------------------------------------------------------------
# Canonical field sets
# ---------------------------------------------------------------------------

VALID_SOURCES = frozenset({
    "hospital_server",
    "domain_controller",
    "ot_node",
    "attacker",
})

VALID_ACTIONS = frozenset({
    "execute",
    "read",
    "write",
    "authenticate",
    "connect",
    "disconnect",
    "query",
    "create",
    "delete",
    "modify",
    "heartbeat",
    "scan",
})

VALID_RESULTS = frozenset({
    "success",
    "failure",
    "unknown",
})


# ---------------------------------------------------------------------------
# Event Schema
# ---------------------------------------------------------------------------

@dataclass
class TelemetryEvent:
    """
    Single telemetry event — the atomic unit of Digital Twin output.

    Instantiate via from_dict() or directly. Serialise via to_jsonl_line().

    Example (Hospital Server process create)
    -----------------------------------------
    event = TelemetryEvent(
        source="hospital_server",
        event_type="ProcessCreate",
        host="hospital-server-01",
        user="svc-iis",
        resource="w3wp.exe",
        action="execute",
        result="success",
    )
    print(event.to_jsonl_line())
    """

    # Required fields
    source: str
    event_type: str
    host: str
    user: str
    resource: str
    action: str
    result: str

    # Auto-populated fields (do not pass manually)
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(
        default_factory=lambda: datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
    )

    # Optional metadata (stored verbatim in raw_log)
    raw_log: str = field(default="")

    # Optional extended attributes (stored as JSON in raw_log if provided)
    _extra: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Validate required fields and build raw_log if not already set."""
        if not self.event_id:
            self.event_id = str(uuid.uuid4())
        if not self.timestamp:
            self.timestamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
        if not self.raw_log:
            # Build raw_log from the structured event payload
            self.raw_log = json.dumps(self._build_raw_payload(), separators=(",", ":"))

    def _build_raw_payload(self) -> dict[str, Any]:
        """Build the raw event payload for the raw_log field."""
        payload: dict[str, Any] = {
            "source": self.source,
            "event_type": self.event_type,
            "host": self.host,
            "user": self.user,
            "resource": self.resource,
            "action": self.action,
            "result": self.result,
        }
        payload.update(self._extra)
        return payload

    def to_dict(self) -> dict[str, Any]:
        """Return the event as a plain dict (all serialisable types)."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "source": self.source,
            "event_type": self.event_type,
            "host": self.host,
            "user": self.user,
            "resource": self.resource,
            "action": self.action,
            "result": self.result,
            "raw_log": self.raw_log,
        }

    def to_jsonl_line(self) -> str:
        """Return a single JSONL line (no newline — writer adds it)."""
        return json.dumps(self.to_dict(), separators=(",", ":"))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TelemetryEvent":
        """Reconstruct a TelemetryEvent from a parsed JSONL dict."""
        return cls(
            event_id=data["event_id"],
            timestamp=data["timestamp"],
            source=data["source"],
            event_type=data["event_type"],
            host=data["host"],
            user=data["user"],
            resource=data["resource"],
            action=data["action"],
            result=data["result"],
            raw_log=data.get("raw_log", ""),
        )

    def validate(self) -> list[str]:
        """
        Validate the event against the schema contract.

        Returns
        -------
        list[str]
            List of validation errors. Empty list = valid.
        """
        errors: list[str] = []

        if not self.event_id:
            errors.append("event_id is required")
        if not self.timestamp:
            errors.append("timestamp is required")
        if self.source not in VALID_SOURCES:
            errors.append(f"source '{self.source}' must be one of {sorted(VALID_SOURCES)}")
        if not self.event_type:
            errors.append("event_type is required")
        if not self.host:
            errors.append("host is required")
        if not self.user:
            errors.append("user is required")
        if not self.resource:
            errors.append("resource is required")
        if self.action not in VALID_ACTIONS:
            errors.append(f"action '{self.action}' must be one of {sorted(VALID_ACTIONS)}")
        if self.result not in VALID_RESULTS:
            errors.append(f"result '{self.result}' must be one of {sorted(VALID_RESULTS)}")

        return errors


def make_event(
    source: str,
    event_type: str,
    host: str,
    user: str,
    resource: str,
    action: str,
    result: str = "success",
    **extra: Any,
) -> TelemetryEvent:
    """
    Factory function for creating a validated TelemetryEvent.

    Extra keyword arguments are stored in _extra and serialised into raw_log.

    Raises
    ------
    ValueError
        If the event fails schema validation.

    Example
    -------
    event = make_event(
        source="hospital_server",
        event_type="ProcessCreate",
        host="hospital-server-01",
        user="svc-db",
        resource="sqlservr.exe",
        action="execute",
        pid=1234,
        parent_pid=1,
    )
    """
    event = TelemetryEvent(
        source=source,
        event_type=event_type,
        host=host,
        user=user,
        resource=resource,
        action=action,
        result=result,
        _extra=extra,
    )
    errors = event.validate()
    if errors:
        raise ValueError(f"TelemetryEvent validation failed: {'; '.join(errors)}")
    return event
