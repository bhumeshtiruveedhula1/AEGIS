"""
backend.orchestrator.service — Response Orchestrator Service
=============================================================
Module 6.1 — Response Orchestrator

Single public entry point for the entire orchestration workflow.

Usage
-----
    from backend.orchestrator.service import OrchestratorService
    from backend.context.models import AttackContext

    svc = OrchestratorService()

    # Step 1 — Orchestrate (select playbook, compute blast radius, create pending approval)
    record = svc.orchestrate(context)

    # Step 2 — Human approves or rejects
    record = svc.approve(record.orchestration_id, decided_by="analyst@example.com")
    # or:
    record = svc.reject(record.orchestration_id, decided_by="analyst@example.com", reason="FP")

    # Step 3 — Execute (only if APPROVED)
    record = svc.execute(record.orchestration_id)

    # Query
    record = svc.get(orchestration_id)
    ids    = svc.list_ids()
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from backend.context.models import AttackContext

from backend.core.config import get_settings
from backend.orchestrator.approval import ApprovalManager
from backend.orchestrator.audit import OrchestratorAuditLogger
from backend.orchestrator.blast_radius import compute_blast_radius
from backend.orchestrator.executor import MockExecutor
from backend.orchestrator.models import OrchestratorRecord
from backend.orchestrator.playbooks import PlaybookRegistry, get_playbook_registry
from backend.orchestrator.storage import OrchestratorStore

logger = structlog.get_logger(__name__)

# Default approval TTL
_DEFAULT_TTL_SECONDS = 3600


class OrchestratorService:
    """
    Single orchestration entry point.

    Coordinates playbook selection, blast radius computation,
    approval lifecycle, mock execution, audit logging, and persistence.

    Parameters
    ----------
    store_dir      : Root directory for orchestrator storage. Defaults to
                     settings.data_dir / "orchestrator".
    audit_dir      : Directory for audit JSONL files. Defaults to
                     store_dir / "audit".
    registry       : PlaybookRegistry instance. Defaults to module singleton.
    approval_ttl_s : Seconds before a PENDING approval expires.
    """

    def __init__(
        self,
        store_dir: Path | None = None,
        audit_dir: Path | None = None,
        registry: PlaybookRegistry | None = None,
        approval_ttl_s: int = _DEFAULT_TTL_SECONDS,
    ) -> None:
        settings = get_settings()
        base = store_dir or (Path(settings.data_dir) / "orchestrator")
        self._store = OrchestratorStore(base)
        self._audit = OrchestratorAuditLogger(audit_dir or (base / "audit"))
        self._registry = registry or get_playbook_registry()
        self._executor = MockExecutor()
        self._ttl = approval_ttl_s
        logger.debug(
            "orchestrator_service_initialized",
            store_dir=str(base),
            approval_ttl_s=approval_ttl_s,
        )

    # ── Public API ────────────────────────────────────────────────────────────

    def orchestrate(self, context: AttackContext) -> OrchestratorRecord:
        """
        Full orchestration entry point.

        1. Select playbook from AttackContext.
        2. Compute blast radius.
        3. Create PENDING approval record.
        4. Persist OrchestratorRecord.
        5. Emit audit events.

        Returns
        -------
        OrchestratorRecord with status=PENDING.
        """
        playbook = self._registry.select(context)
        blast_radius = compute_blast_radius(context)
        approval = ApprovalManager.create_pending(
            orchestration_id="",  # placeholder — set after record creation
            ttl_seconds=self._ttl,
        )

        record = OrchestratorRecord(
            context_id=context.context_id,
            alert_id=context.identity.alert_id,
            entity_id=context.identity.entity_id,
            entity_type=context.identity.entity_type,
            playbook=playbook,
            blast_radius=blast_radius,
            approval=approval.model_copy(
                update={"orchestration_id": ""}  # will be fixed below
            ),
        )

        # Fix orchestration_id in approval
        record = record.model_copy(
            update={
                "approval": approval.model_copy(
                    update={"orchestration_id": record.orchestration_id}
                )
            }
        )

        # Audit — playbook selection
        evt1 = self._audit.log_event(
            orchestration_id=record.orchestration_id,
            alert_id=record.alert_id,
            event_type="playbook_selected",
            detail={
                "playbook_id": playbook.playbook_id,
                "playbook_name": playbook.name,
                "blast_radius_scope": blast_radius.estimated_scope,
            },
        )
        # Audit — approval requested
        evt2 = self._audit.log_event(
            orchestration_id=record.orchestration_id,
            alert_id=record.alert_id,
            event_type="approval_requested",
            detail={"approval_id": record.approval.approval_id, "ttl_s": self._ttl},
        )

        record = record.model_copy(
            update={
                "audit_trail": [evt1, evt2],
                "updated_at": datetime.now(UTC),
            }
        )

        self._store.save(record)
        logger.info(
            "orchestration_created",
            orchestration_id=record.orchestration_id,
            alert_id=record.alert_id,
            playbook_id=playbook.playbook_id,
        )
        return record

    def approve(
        self,
        orchestration_id: str,
        decided_by: str,
        reason: str = "",
    ) -> OrchestratorRecord:
        """
        Approve a PENDING orchestration.

        Returns the updated OrchestratorRecord with approval.status=APPROVED.
        """
        record = self._load_and_check_expiry(orchestration_id)
        updated_approval = ApprovalManager.approve(record.approval, decided_by, reason)

        audit_evt = self._audit.log_event(
            orchestration_id=orchestration_id,
            alert_id=record.alert_id,
            event_type="approved",
            actor=decided_by,
            detail={"reason": reason, "approval_id": updated_approval.approval_id},
        )

        record = record.model_copy(
            update={
                "approval": updated_approval,
                "audit_trail": [*record.audit_trail, audit_evt],
                "updated_at": datetime.now(UTC),
            }
        )
        self._store.save(record)
        logger.info(
            "orchestration_approved",
            orchestration_id=orchestration_id,
            decided_by=decided_by,
        )
        return record

    def reject(
        self,
        orchestration_id: str,
        decided_by: str,
        reason: str = "",
    ) -> OrchestratorRecord:
        """
        Reject a PENDING orchestration.

        Returns the updated OrchestratorRecord with approval.status=REJECTED.
        """
        record = self._load_and_check_expiry(orchestration_id)
        updated_approval = ApprovalManager.reject(record.approval, decided_by, reason)

        audit_evt = self._audit.log_event(
            orchestration_id=orchestration_id,
            alert_id=record.alert_id,
            event_type="rejected",
            actor=decided_by,
            detail={"reason": reason, "approval_id": updated_approval.approval_id},
        )

        record = record.model_copy(
            update={
                "approval": updated_approval,
                "audit_trail": [*record.audit_trail, audit_evt],
                "updated_at": datetime.now(UTC),
            }
        )
        self._store.save(record)
        logger.info(
            "orchestration_rejected",
            orchestration_id=orchestration_id,
            decided_by=decided_by,
        )
        return record

    def execute(self, orchestration_id: str) -> OrchestratorRecord:
        """
        Simulate execution of an APPROVED orchestration.

        Returns
        -------
        OrchestratorRecord with execution populated.

        Raises
        ------
        ExecutionError if approval is not APPROVED.
        """
        record = self._store.load(orchestration_id)

        start_evt = self._audit.log_event(
            orchestration_id=orchestration_id,
            alert_id=record.alert_id,
            event_type="execution_started",
            detail={"playbook_id": record.playbook.playbook_id},
        )

        execution = self._executor.execute(record)  # raises ExecutionError if not APPROVED

        complete_evt = self._audit.log_event(
            orchestration_id=orchestration_id,
            alert_id=record.alert_id,
            event_type="execution_complete",
            detail={
                "outcome": execution.outcome,
                "action_count": len(execution.actions_simulated),
                "execution_id": execution.execution_id,
            },
        )

        record = record.model_copy(
            update={
                "execution": execution,
                "audit_trail": [*record.audit_trail, start_evt, complete_evt],
                "updated_at": datetime.now(UTC),
            }
        )
        self._store.save(record)
        logger.info(
            "orchestration_executed",
            orchestration_id=orchestration_id,
            outcome=execution.outcome,
        )
        return record

    def get(self, orchestration_id: str) -> OrchestratorRecord:
        """Load and return an OrchestratorRecord by ID."""
        return self._store.load(orchestration_id)

    def list_ids(self) -> list[str]:
        """Return all stored orchestration IDs, newest first."""
        return self._store.list_ids()

    def list_by_alert(self, alert_id: str) -> list[OrchestratorRecord]:
        """Return all orchestration records for a given alert_id (today's partition)."""
        return self._store.load_by_alert(alert_id)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _load_and_check_expiry(self, orchestration_id: str) -> OrchestratorRecord:
        """Load record, check TTL expiry, persist if expired, return current record."""
        record = self._store.load(orchestration_id)
        updated_approval = ApprovalManager.check_expiry(record.approval)

        if updated_approval.status == "EXPIRED" and record.approval.status == "PENDING":
            # Persist the expiry transition
            exp_evt = self._audit.log_event(
                orchestration_id=orchestration_id,
                alert_id=record.alert_id,
                event_type="approval_expired",
                detail={"approval_id": updated_approval.approval_id},
            )
            record = record.model_copy(
                update={
                    "approval": updated_approval,
                    "audit_trail": [*record.audit_trail, exp_evt],
                    "updated_at": datetime.now(UTC),
                }
            )
            self._store.save(record)

        return record
