"""
backend.audit.models — Audit Ledger Data Models
================================================
Module 7.2 — Audit Ledger

Immutable Pydantic models for the append-only audit ledger.
All models are pure data — no business logic.

Model hierarchy
---------------
AuditEventType  — enum of all recordable event types
AuditActor      — who/what performed the action
AuditMetadata   — source module metadata attached to every entry
AuditEntry      — single immutable audit event (core record)
AuditQuery      — filter criteria for ledger queries
AuditResult     — paginated query response
LedgerStatistics— summary stats over stored ledger
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import ConfigDict, Field, field_validator

from backend.shared.models import CyberShieldBaseModel
from backend.shared.utils.id_utils import generate_id

# ── Schema version ────────────────────────────────────────────────────────────

AUDIT_SCHEMA_VERSION = "1.0.0"


# ── Event type enum ───────────────────────────────────────────────────────────


class AuditEventType(str, Enum):
    """Canonical set of audit-recordable event types."""

    # Detection pipeline
    DETECTION_ALERT = "detection_alert"
    DETECTION_SCORED = "detection_scored"

    # Explainability
    SHAP_EXPLANATION = "shap_explanation"

    # MITRE
    MITRE_MAPPED = "mitre_mapped"

    # Graph & chain
    ATTACK_GRAPH_BUILT = "attack_graph_built"
    ATTACK_CHAIN_DETECTED = "attack_chain_detected"

    # Context
    CONTEXT_CREATED = "context_created"

    # Orchestrator lifecycle
    ORCHESTRATION_CREATED = "orchestration_created"
    APPROVAL_PENDING = "approval_pending"
    APPROVAL_APPROVED = "approval_approved"
    APPROVAL_REJECTED = "approval_rejected"
    APPROVAL_EXPIRED = "approval_expired"
    EXECUTION_SIMULATED = "execution_simulated"

    # Dashboard
    DASHBOARD_ACCESSED = "dashboard_accessed"

    # Platform
    PLATFORM_STARTED = "platform_started"
    PLATFORM_STOPPED = "platform_stopped"
    METRIC_COLLECTED = "metric_collected"

    # Integrity
    INTEGRITY_CHECKED = "integrity_checked"

    # Generic (escape hatch — avoid overuse)
    CUSTOM = "custom"


# ── Actor ─────────────────────────────────────────────────────────────────────


class AuditActor(CyberShieldBaseModel):
    """
    Who or what performed the auditable action.

    actor_type is one of: 'system' | 'operator' | 'scheduler'.
    actor_id   is a free-form string (system module name, operator email, etc.).
    """

    model_config = ConfigDict(frozen=True)

    actor_type: str = Field(default="system")
    actor_id: str = Field(default="system")
    ip_address: str | None = Field(default=None)

    @field_validator("actor_type")
    @classmethod
    def _valid_type(cls, v: str) -> str:
        allowed = {"system", "operator", "scheduler"}
        if v not in allowed:
            msg = f"actor_type must be one of {allowed}"
            raise ValueError(msg)
        return v

    @classmethod
    def system(cls, module: str = "system") -> AuditActor:
        """Convenience constructor for automated system actors."""
        return cls(actor_type="system", actor_id=module)

    @classmethod
    def operator(cls, identity: str, ip: str | None = None) -> AuditActor:
        """Convenience constructor for human operator actors."""
        return cls(actor_type="operator", actor_id=identity, ip_address=ip)


# ── Metadata ──────────────────────────────────────────────────────────────────


class AuditMetadata(CyberShieldBaseModel):
    """
    Source-module metadata attached to every audit entry.
    Records which module produced the event and relevant correlation IDs.
    """

    model_config = ConfigDict(frozen=True)

    source_module: str = Field(description="Backend module that generated this event")
    schema_version: str = Field(default=AUDIT_SCHEMA_VERSION)

    # Correlation IDs — all optional; only set when relevant
    alert_id: str | None = Field(default=None)
    context_id: str | None = Field(default=None)
    orchestration_id: str | None = Field(default=None)
    entity_id: str | None = Field(default=None)
    host: str | None = Field(default=None)
    user: str | None = Field(default=None)

    # Arbitrary key/value pairs for module-specific data
    extra: dict[str, Any] = Field(default_factory=dict)


# ── Core audit entry ──────────────────────────────────────────────────────────


class AuditEntry(CyberShieldBaseModel):
    """
    Single immutable audit ledger entry.

    Once written, an AuditEntry is never modified.
    The ledger is append-only; edits are forbidden by contract.

    Fields
    ------
    audit_id        Unique identifier (UUID-prefixed)
    sequence_number Monotonically increasing integer within a partition
    event_type      Canonical event classification
    timestamp       UTC time the event occurred (provided by caller)
    recorded_at     UTC time the entry was written to the ledger
    actor           Who/what performed the action
    metadata        Correlation IDs and source module
    severity        Optional severity hint: critical|high|medium|low|info
    outcome         Optional outcome: success|failure|pending|unknown
    description     Human-readable summary
    payload         Arbitrary structured data from the source module
    schema_version  Ledger schema version for forward-compatibility
    """

    model_config = ConfigDict(frozen=True, populate_by_name=True, use_enum_values=True)

    audit_id: str = Field(default_factory=lambda: f"aud-{generate_id()}")
    sequence_number: int = Field(default=0, ge=0)
    event_type: AuditEventType
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    recorded_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    actor: AuditActor = Field(default_factory=AuditActor.system)
    metadata: AuditMetadata
    severity: str | None = Field(default=None)
    outcome: str | None = Field(default=None)
    description: str = Field(default="")
    payload: dict[str, Any] = Field(default_factory=dict)
    schema_version: str = Field(default=AUDIT_SCHEMA_VERSION)

    @field_validator("severity")
    @classmethod
    def _valid_severity(cls, v: str | None) -> str | None:
        if v is None:
            return v
        allowed = {"critical", "high", "medium", "low", "info"}
        if v.lower() not in allowed:
            msg = f"severity must be one of {allowed}"
            raise ValueError(msg)
        return v.lower()

    @field_validator("outcome")
    @classmethod
    def _valid_outcome(cls, v: str | None) -> str | None:
        if v is None:
            return v
        allowed = {"success", "failure", "pending", "unknown"}
        if v.lower() not in allowed:
            msg = f"outcome must be one of {allowed}"
            raise ValueError(msg)
        return v.lower()

    @field_validator("timestamp", "recorded_at", mode="before")
    @classmethod
    def _ensure_utc(cls, v: Any) -> datetime:
        if isinstance(v, datetime):
            return v if v.tzinfo is not None else v.replace(tzinfo=UTC)
        return v


# ── Query ─────────────────────────────────────────────────────────────────────


class AuditQuery(CyberShieldBaseModel):
    """
    Filter criteria submitted to the AuditQueryEngine.
    All filters are optional; omitted filters match everything.
    Multiple filters are ANDed together.
    """

    model_config = ConfigDict(frozen=True)

    # Identity filters
    audit_id: str | None = Field(default=None)
    alert_id: str | None = Field(default=None)
    context_id: str | None = Field(default=None)
    orchestration_id: str | None = Field(default=None)
    entity_id: str | None = Field(default=None)
    host: str | None = Field(default=None)
    user: str | None = Field(default=None)

    # Classification filters
    event_type: AuditEventType | None = Field(default=None)
    severity: str | None = Field(default=None)
    outcome: str | None = Field(default=None)
    actor_id: str | None = Field(default=None)
    source_module: str | None = Field(default=None)

    # Time range filters
    after: datetime | None = Field(default=None)
    before: datetime | None = Field(default=None)

    # Pagination
    limit: int = Field(default=100, ge=1, le=10_000)
    offset: int = Field(default=0, ge=0)

    # Ordering (newest-first by default)
    ascending: bool = Field(default=False)


# ── Result ────────────────────────────────────────────────────────────────────


class AuditResult(CyberShieldBaseModel):
    """Paginated response from a ledger query."""

    model_config = ConfigDict(frozen=True)

    entries: list[AuditEntry] = Field(default_factory=list)
    total_matched: int = Field(default=0, ge=0)
    offset: int = Field(default=0, ge=0)
    limit: int = Field(default=100, ge=1)
    query: AuditQuery
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


# ── Statistics ────────────────────────────────────────────────────────────────


class LedgerStatistics(CyberShieldBaseModel):
    """Summary statistics over the stored audit ledger."""

    model_config = ConfigDict(frozen=True)

    total_entries: int = Field(default=0, ge=0)
    dates_covered: list[str] = Field(default_factory=list)
    event_type_counts: dict[str, int] = Field(default_factory=dict)
    severity_counts: dict[str, int] = Field(default_factory=dict)
    outcome_counts: dict[str, int] = Field(default_factory=dict)
    oldest_entry_at: datetime | None = Field(default=None)
    newest_entry_at: datetime | None = Field(default=None)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
