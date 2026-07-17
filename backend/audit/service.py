"""
backend.audit.service — Audit Ledger Service
============================================
Module 7.2 — Audit Ledger

Single public facade for all Audit Ledger operations.

Responsibilities
----------------
- Record events from any upstream module
- Query events by filter criteria
- Retrieve individual records
- Verify ledger integrity
- Generate ledger statistics

This service orchestrates AuditLedger, AuditQueryEngine, and
AuditIntegrityChecker. Callers should use AuditService rather than
touching the submodules directly.
"""

from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING, Any

import structlog

from backend.audit.integrity import AuditIntegrityChecker, IntegrityReport
from backend.audit.ledger import AuditLedger
from backend.audit.models import (
    AuditActor,
    AuditEntry,
    AuditEventType,
    AuditMetadata,
    AuditQuery,
    AuditResult,
    LedgerStatistics,
)
from backend.audit.query import AuditQueryEngine
from backend.core.config import get_settings

if TYPE_CHECKING:
    from datetime import datetime
    from pathlib import Path

logger = structlog.get_logger(__name__)


class AuditService:
    """
    Public facade for the Audit Ledger.

    Parameters
    ----------
    store_dir : Explicit storage directory. If None, resolves to
                <data_dir>/audit from project settings.
    """

    def __init__(self, store_dir: Path | None = None) -> None:
        if store_dir is None:
            settings = get_settings()
            store_dir = settings.data_dir / "audit"
        self._store_dir = store_dir
        self._ledger = AuditLedger(store_dir)
        self._store = self._ledger._store  # shared store reference
        self._query = AuditQueryEngine(self._ledger)
        self._checker = AuditIntegrityChecker(self._store)
        logger.debug("audit_service_ready", store_dir=str(store_dir))

    # ── Write ──────────────────────────────────────────────────────────────────

    def record_event(
        self,
        event_type: AuditEventType | str,
        source_module: str,
        *,
        actor: AuditActor | None = None,
        alert_id: str | None = None,
        context_id: str | None = None,
        orchestration_id: str | None = None,
        entity_id: str | None = None,
        host: str | None = None,
        user: str | None = None,
        severity: str | None = None,
        outcome: str | None = None,
        description: str = "",
        payload: dict[str, Any] | None = None,
        timestamp: datetime | None = None,
        extra: dict[str, Any] | None = None,
    ) -> AuditEntry:
        """
        Record a single audit event.

        This is the primary API for upstream modules to write to the ledger.

        Parameters
        ----------
        event_type      : Audit event classification.
        source_module   : Originating backend module name (e.g. 'orchestrator').
        actor           : Actor identity. Defaults to system actor.
        alert_id        : Correlation ID (optional).
        context_id      : Correlation ID (optional).
        orchestration_id: Correlation ID (optional).
        entity_id       : Affected entity (optional).
        host            : Affected host (optional).
        user            : Affected user (optional).
        severity        : Severity hint.
        outcome         : Outcome string.
        description     : Human-readable summary.
        payload         : Arbitrary module-specific data.
        timestamp       : Event time (defaults to now).
        extra           : Additional metadata key-value pairs.

        Returns
        -------
        AuditEntry      : The persisted, immutable entry.
        """
        metadata = AuditMetadata(
            source_module=source_module,
            alert_id=alert_id,
            context_id=context_id,
            orchestration_id=orchestration_id,
            entity_id=entity_id,
            host=host,
            user=user,
            extra=extra or {},
        )
        return self._ledger.record(
            event_type=event_type,
            metadata=metadata,
            actor=actor,
            severity=severity,
            outcome=outcome,
            description=description,
            payload=payload,
            timestamp=timestamp,
        )

    # ── Convenience record helpers ─────────────────────────────────────────────

    def record_detection(
        self,
        alert_id: str,
        entity_id: str,
        severity: str,
        anomaly_score: float,
        *,
        host: str | None = None,
        user: str | None = None,
        context_id: str | None = None,
    ) -> AuditEntry:
        """Record a detection alert event."""
        return self.record_event(
            AuditEventType.DETECTION_ALERT,
            source_module="detection",
            alert_id=alert_id,
            context_id=context_id,
            entity_id=entity_id,
            host=host,
            user=user,
            severity=severity,
            outcome="success",
            description=f"Detection alert: score={anomaly_score:.4f}",
            payload={"anomaly_score": anomaly_score, "severity": severity},
        )

    def record_context_created(
        self,
        context_id: str,
        alert_id: str,
        entity_id: str,
    ) -> AuditEntry:
        """Record an AttackContext creation event."""
        return self.record_event(
            AuditEventType.CONTEXT_CREATED,
            source_module="context",
            alert_id=alert_id,
            context_id=context_id,
            entity_id=entity_id,
            outcome="success",
            description=f"AttackContext created for alert {alert_id}",
        )

    def record_orchestration_created(
        self,
        orchestration_id: str,
        context_id: str,
        playbook_id: str,
    ) -> AuditEntry:
        """Record an orchestration record creation event."""
        return self.record_event(
            AuditEventType.ORCHESTRATION_CREATED,
            source_module="orchestrator",
            context_id=context_id,
            orchestration_id=orchestration_id,
            outcome="success",
            description=f"Orchestration created, playbook={playbook_id}",
            payload={"playbook_id": playbook_id},
        )

    def record_approval_decision(
        self,
        orchestration_id: str,
        decision: str,
        decided_by: str,
        context_id: str | None = None,
    ) -> AuditEntry:
        """Record an approval decision (approved/rejected/expired)."""
        decision_lower = decision.lower()
        event_map = {
            "approved": AuditEventType.APPROVAL_APPROVED,
            "rejected": AuditEventType.APPROVAL_REJECTED,
            "expired": AuditEventType.APPROVAL_EXPIRED,
        }
        event_type = event_map.get(decision_lower, AuditEventType.APPROVAL_PENDING)
        return self.record_event(
            event_type,
            source_module="orchestrator",
            orchestration_id=orchestration_id,
            context_id=context_id,
            actor=AuditActor.operator(decided_by),
            outcome="success",
            description=f"Approval {decision_lower} by {decided_by}",
            payload={"decision": decision_lower, "decided_by": decided_by},
        )

    # ── Query ──────────────────────────────────────────────────────────────────

    def query(self, q: AuditQuery) -> AuditResult:
        """Execute a filtered, paginated query against the ledger."""
        return self._query.query(q)

    def get_entry(self, audit_id: str) -> AuditEntry:
        """Retrieve a single AuditEntry by its audit_id."""
        return self._ledger.get(audit_id)

    def get_by_context(self, context_id: str, *, limit: int = 100) -> list[AuditEntry]:
        """Return all entries linked to a context_id."""
        return self._query.get_by_context(context_id, limit=limit)

    def get_by_alert(self, alert_id: str, *, limit: int = 100) -> list[AuditEntry]:
        """Return all entries linked to an alert_id."""
        return self._query.get_by_alert(alert_id, limit=limit)

    def get_by_orchestration(self, orchestration_id: str, *, limit: int = 100) -> list[AuditEntry]:
        """Return all entries linked to an orchestration_id."""
        return self._query.get_by_orchestration(orchestration_id, limit=limit)

    def get_for_date(self, date: datetime | None = None) -> list[AuditEntry]:
        """Return all entries for the given UTC date (today if None)."""
        return self._ledger.get_for_date(date)

    # ── Integrity ──────────────────────────────────────────────────────────────

    def verify_integrity(self) -> IntegrityReport:
        """Run a full integrity check on the stored ledger."""
        return self._checker.verify()

    # ── Statistics ─────────────────────────────────────────────────────────────

    def get_statistics(self) -> LedgerStatistics:
        """Generate summary statistics over the entire stored ledger."""
        all_entries = self._ledger.get_all()

        if not all_entries:
            return LedgerStatistics(
                total_entries=0,
                dates_covered=self._ledger.list_dates(),
            )

        event_counts: Counter[str] = Counter()
        severity_counts: Counter[str] = Counter()
        outcome_counts: Counter[str] = Counter()

        for e in all_entries:
            event_counts[str(e.event_type)] += 1
            if e.severity:
                severity_counts[e.severity] += 1
            if e.outcome:
                outcome_counts[e.outcome] += 1

        sorted_by_ts = sorted(all_entries, key=lambda e: e.timestamp)

        return LedgerStatistics(
            total_entries=len(all_entries),
            dates_covered=self._ledger.list_dates(),
            event_type_counts=dict(event_counts),
            severity_counts=dict(severity_counts),
            outcome_counts=dict(outcome_counts),
            oldest_entry_at=sorted_by_ts[0].timestamp,
            newest_entry_at=sorted_by_ts[-1].timestamp,
        )

    def count(self) -> int:
        """Total number of persisted audit entries."""
        return self._ledger.count()
