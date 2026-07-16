"""
backend.orchestrator.approval — Approval Lifecycle Manager
===========================================================
Module 6.1 — Response Orchestrator

Stateless approval logic. State is persisted in OrchestratorStore.

Lifecycle:  PENDING → APPROVED | REJECTED | EXPIRED

Rules:
- Only PENDING records can be approved or rejected.
- EXPIRED records cannot be approved or rejected.
- TTL expiry is checked at read time (no background task).
- All state transitions produce a new ApprovalRecord (immutable pattern).
"""

from __future__ import annotations

from datetime import UTC, datetime

import structlog

from backend.orchestrator.exceptions import (
    ApprovalAlreadyProcessedError,
    ApprovalExpiredError,
)
from backend.orchestrator.models import ApprovalRecord

logger = structlog.get_logger(__name__)


class ApprovalManager:
    """
    Stateless manager for ApprovalRecord lifecycle transitions.

    Every method receives and returns an ApprovalRecord — no internal state.
    Thread-safe by design (no shared mutable state).
    """

    # ── Factory ──────────────────────────────────────────────────────────────

    @staticmethod
    def create_pending(orchestration_id: str, ttl_seconds: int = 3600) -> ApprovalRecord:
        """Create a new PENDING ApprovalRecord for the given orchestration."""
        record = ApprovalRecord(
            orchestration_id=orchestration_id,
            status="PENDING",
            ttl_seconds=ttl_seconds,
        )
        logger.info(
            "approval_pending_created",
            approval_id=record.approval_id,
            orchestration_id=orchestration_id,
            ttl_seconds=ttl_seconds,
        )
        return record

    # ── Transitions ───────────────────────────────────────────────────────────

    @staticmethod
    def approve(
        record: ApprovalRecord,
        decided_by: str,
        reason: str = "",
    ) -> ApprovalRecord:
        """
        Transition PENDING → APPROVED.

        Raises ApprovalExpiredError if TTL has elapsed.
        Raises ApprovalAlreadyProcessedError if not PENDING.
        """
        ApprovalManager._assert_pending(record)
        ApprovalManager._assert_not_expired(record)

        updated = record.model_copy(
            update={
                "status": "APPROVED",
                "decided_at": datetime.now(UTC),
                "decided_by": decided_by,
                "reason": reason,
            }
        )
        logger.info(
            "approval_approved",
            approval_id=record.approval_id,
            orchestration_id=record.orchestration_id,
            decided_by=decided_by,
        )
        return updated

    @staticmethod
    def reject(
        record: ApprovalRecord,
        decided_by: str,
        reason: str = "",
    ) -> ApprovalRecord:
        """
        Transition PENDING → REJECTED.

        Raises ApprovalExpiredError if TTL has elapsed.
        Raises ApprovalAlreadyProcessedError if not PENDING.
        """
        ApprovalManager._assert_pending(record)
        ApprovalManager._assert_not_expired(record)

        updated = record.model_copy(
            update={
                "status": "REJECTED",
                "decided_at": datetime.now(UTC),
                "decided_by": decided_by,
                "reason": reason,
            }
        )
        logger.info(
            "approval_rejected",
            approval_id=record.approval_id,
            orchestration_id=record.orchestration_id,
            decided_by=decided_by,
        )
        return updated

    @staticmethod
    def check_expiry(record: ApprovalRecord) -> ApprovalRecord:
        """
        Return record unchanged if not expired, or with status=EXPIRED if TTL elapsed.

        Only affects PENDING records — already-decided records are returned as-is.
        """
        if record.status != "PENDING":
            return record

        elapsed = (datetime.now(UTC) - record.requested_at).total_seconds()
        if elapsed >= record.ttl_seconds:
            updated = record.model_copy(
                update={
                    "status": "EXPIRED",
                    "decided_at": datetime.now(UTC),
                    "reason": f"TTL of {record.ttl_seconds}s elapsed without decision.",
                }
            )
            logger.warning(
                "approval_expired",
                approval_id=record.approval_id,
                orchestration_id=record.orchestration_id,
                elapsed_s=round(elapsed, 1),
            )
            return updated

        return record

    # ── Guards ────────────────────────────────────────────────────────────────

    @staticmethod
    def _assert_pending(record: ApprovalRecord) -> None:
        if record.status != "PENDING":
            raise ApprovalAlreadyProcessedError(
                f"Approval {record.approval_id} is already {record.status}.",
                context={
                    "approval_id": record.approval_id,
                    "current_status": record.status,
                },
            )

    @staticmethod
    def _assert_not_expired(record: ApprovalRecord) -> None:
        elapsed = (datetime.now(UTC) - record.requested_at).total_seconds()
        if elapsed >= record.ttl_seconds:
            raise ApprovalExpiredError(
                f"Approval {record.approval_id} TTL expired ({elapsed:.0f}s > {record.ttl_seconds}s).",
                context={
                    "approval_id": record.approval_id,
                    "elapsed_s": round(elapsed, 1),
                    "ttl_seconds": record.ttl_seconds,
                },
            )
