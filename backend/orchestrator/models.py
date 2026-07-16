"""
backend.orchestrator.models — Response Orchestrator Data Models
===============================================================
Module 6.1 — Response Orchestrator

Pure immutable Pydantic models. Zero business logic.

Hierarchy
---------
OrchestratorRecord                 ← root object persisted per orchestration run
  ├── ResponsePlaybook             ← matched playbook definition
  │   └── list[PlaybookAction]    ← ordered action steps
  ├── BlastRadiusReport            ← affected assets derived from AttackContext
  ├── ApprovalRecord               ← PENDING→APPROVED/REJECTED/EXPIRED lifecycle
  ├── ExecutionResult              ← simulated execution output
  └── list[OrchestratorAuditEvent] ← immutable step-by-step audit trail

Schema version: 1.0.0
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import ConfigDict, Field

from backend.shared.models import CyberShieldBaseModel
from backend.shared.utils.id_utils import generate_id

ORCHESTRATOR_SCHEMA_VERSION = "1.0.0"

# Literals
ApprovalStatus = Literal["PENDING", "APPROVED", "REJECTED", "EXPIRED"]
ExecutionOutcome = Literal[
    "SIMULATED_SUCCESS", "SIMULATED_PARTIAL", "SIMULATED_FAILURE", "NOT_EXECUTED"
]
PlaybookActionType = Literal[
    "isolate_host",
    "block_account",
    "block_ip",
    "kill_process",
    "investigate",
    "ot_containment",
    "observe_only",
    "notify_soc",
    "collect_forensics",
]


# ---------------------------------------------------------------------------
# Playbook models
# ---------------------------------------------------------------------------


class PlaybookAction(CyberShieldBaseModel):
    """One discrete response action within a playbook."""

    action_type: PlaybookActionType
    description: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    rollback_description: str = Field(default="")
    estimated_duration_s: int = Field(default=0, ge=0)


class ResponsePlaybook(CyberShieldBaseModel):
    """
    Deterministic response playbook definition.

    Playbooks are reusable, configurable, and immutable once loaded.
    Selection is determined by matching trigger_conditions against
    AttackContext fields — no scoring, no randomness.
    """

    model_config = ConfigDict(protected_namespaces=())

    playbook_id: str
    name: str
    description: str
    severity_threshold: float = Field(default=0.0, ge=0.0, le=1.0)
    requires_chain: bool = Field(default=False)
    requires_mitre: bool = Field(default=False)
    trigger_tactics: list[str] = Field(default_factory=list)
    trigger_techniques: list[str] = Field(default_factory=list)
    actions: list[PlaybookAction] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Blast radius
# ---------------------------------------------------------------------------


class BlastRadiusReport(CyberShieldBaseModel):
    """
    Affected-asset report derived from AttackContext.

    Read-only. No graph construction. No inference.
    All values sourced directly from context.evidence, context.graph,
    context.chain, context.identity.
    """

    affected_hosts: list[str] = Field(default_factory=list)
    affected_users: list[str] = Field(default_factory=list)
    affected_entity_ids: list[str] = Field(default_factory=list)
    alert_ids_in_scope: list[str] = Field(default_factory=list)
    estimated_node_count: int = Field(default=0, ge=0)
    estimated_scope: Literal["SINGLE_HOST", "LATERAL", "MULTI_ENTITY", "OT", "UNKNOWN"] = Field(
        default="UNKNOWN"
    )
    evidence_sources: list[str] = Field(default_factory=list)
    baseline_available: bool = Field(default=True)


# ---------------------------------------------------------------------------
# Approval
# ---------------------------------------------------------------------------


class ApprovalRecord(CyberShieldBaseModel):
    """
    Tracks the human approval lifecycle for one orchestration run.

    States: PENDING → APPROVED | REJECTED | EXPIRED
    All transitions are recorded with actor and timestamp.
    No automatic execution — approval is always required.
    """

    approval_id: str = Field(default_factory=lambda: f"appr-{generate_id()}")
    orchestration_id: str
    status: ApprovalStatus = Field(default="PENDING")
    requested_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    decided_at: datetime | None = Field(default=None)
    decided_by: str = Field(default="")
    reason: str = Field(default="")
    ttl_seconds: int = Field(default=3600, ge=0)


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------


class SimulatedActionResult(CyberShieldBaseModel):
    """Result of one simulated action step."""

    action_type: PlaybookActionType
    description: str
    simulated: bool = Field(default=True)
    outcome: Literal["OK", "SKIPPED", "FAILED"] = Field(default="OK")
    detail: str = Field(default="")
    executed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ExecutionResult(CyberShieldBaseModel):
    """
    Structured output of a simulated playbook execution.

    Always simulated=True. No real infrastructure actions.
    """

    execution_id: str = Field(default_factory=lambda: f"exec-{generate_id()}")
    orchestration_id: str
    playbook_id: str
    simulated: bool = Field(default=True)
    outcome: ExecutionOutcome = Field(default="NOT_EXECUTED")
    actions_simulated: list[SimulatedActionResult] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = Field(default=None)
    error_detail: str = Field(default="")


# ---------------------------------------------------------------------------
# Audit event
# ---------------------------------------------------------------------------


class OrchestratorAuditEvent(CyberShieldBaseModel):
    """
    Immutable record of one orchestration lifecycle step.

    One event per step: selection, approval-requested, approved/rejected/expired,
    execution-started, execution-completed.
    """

    event_id: str = Field(default_factory=lambda: f"orch-evt-{generate_id()}")
    orchestration_id: str
    alert_id: str
    event_type: str  # e.g. "playbook_selected", "approval_requested", "approved", "executed"
    actor: str = Field(default="system")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    detail: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Root orchestrator record
# ---------------------------------------------------------------------------


class OrchestratorRecord(CyberShieldBaseModel):
    """
    Root object representing one complete orchestration run.

    Persisted atomically after each state transition.
    """

    model_config = ConfigDict(protected_namespaces=())

    orchestration_id: str = Field(default_factory=lambda: f"orch-{generate_id()}")
    schema_version: str = Field(default=ORCHESTRATOR_SCHEMA_VERSION)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    # Source context
    context_id: str
    alert_id: str
    entity_id: str
    entity_type: str

    # Orchestration state
    playbook: ResponsePlaybook
    blast_radius: BlastRadiusReport
    approval: ApprovalRecord
    execution: ExecutionResult | None = Field(default=None)

    # Audit trail — append-only
    audit_trail: list[OrchestratorAuditEvent] = Field(default_factory=list)

    def to_summary(self) -> dict[str, Any]:
        """Compact summary for logging and API responses."""
        return {
            "orchestration_id": self.orchestration_id,
            "context_id": self.context_id,
            "alert_id": self.alert_id,
            "entity_id": self.entity_id,
            "playbook_id": self.playbook.playbook_id,
            "approval_status": self.approval.status,
            "execution_outcome": self.execution.outcome if self.execution else "NOT_EXECUTED",
            "blast_radius_scope": self.blast_radius.estimated_scope,
            "audit_event_count": len(self.audit_trail),
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }
