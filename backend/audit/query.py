"""
backend.audit.query — Audit Ledger Query Engine
================================================
Module 7.2 — Audit Ledger

Efficient filtering of AuditEntry records.
All filtering is exact-match or range-based — no fuzzy matching.

Usage
-----
    engine = AuditQueryEngine(ledger)
    result = engine.query(AuditQuery(event_type=AuditEventType.DETECTION_ALERT,
                                     severity="high", limit=50))
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from backend.audit.exceptions import AuditQueryError
from backend.audit.models import AuditEntry, AuditQuery, AuditResult

if TYPE_CHECKING:
    from backend.audit.ledger import AuditLedger

logger = structlog.get_logger(__name__)


class AuditQueryEngine:
    """
    Filters AuditEntry records from the ledger according to an AuditQuery.

    Strategy
    --------
    For date-range queries, iterate only the relevant date partitions.
    For open-ended queries, load all partitions.
    Apply all filters in memory — no SQL, consistent with project pattern.

    Parameters
    ----------
    ledger : AuditLedger instance to query against.
    """

    def __init__(self, ledger: AuditLedger) -> None:
        self._ledger = ledger

    def query(self, q: AuditQuery) -> AuditResult:
        """
        Execute the query and return a paginated AuditResult.

        Filters are ANDed. None values are ignored (match all).
        """
        if q.after and q.before and q.after >= q.before:
            raise AuditQueryError(
                "AuditQuery.after must be strictly before AuditQuery.before.",
                context={"after": str(q.after), "before": str(q.before)},
            )

        # Load candidates — from specific date if possible
        candidates = self._load_candidates(q)

        # Apply all filters
        matched = [e for e in candidates if self._matches(e, q)]

        # Sort
        matched.sort(key=lambda e: e.timestamp, reverse=not q.ascending)

        total = len(matched)

        # Paginate
        page = matched[q.offset : q.offset + q.limit]

        logger.debug(
            "audit_query_executed",
            matched=total,
            returned=len(page),
            offset=q.offset,
            limit=q.limit,
        )

        return AuditResult(
            entries=page,
            total_matched=total,
            offset=q.offset,
            limit=q.limit,
            query=q,
        )

    def get_by_id(self, audit_id: str) -> AuditEntry:
        """Retrieve a single entry directly by audit_id."""
        return self._ledger.get(audit_id)

    def get_by_context(self, context_id: str, *, limit: int = 100) -> list[AuditEntry]:
        """Return all entries linked to a given context_id, newest first."""
        from backend.audit.models import AuditQuery as AuditQueryFilter

        result = self.query(AuditQueryFilter(context_id=context_id, limit=limit, ascending=False))
        return result.entries

    def get_by_alert(self, alert_id: str, *, limit: int = 100) -> list[AuditEntry]:
        """Return all entries linked to a given alert_id, newest first."""
        from backend.audit.models import AuditQuery as AuditQueryFilter

        result = self.query(AuditQueryFilter(alert_id=alert_id, limit=limit, ascending=False))
        return result.entries

    def get_by_orchestration(self, orchestration_id: str, *, limit: int = 100) -> list[AuditEntry]:
        """Return all entries linked to a given orchestration_id, newest first."""
        from backend.audit.models import AuditQuery as AuditQueryFilter

        result = self.query(
            AuditQueryFilter(orchestration_id=orchestration_id, limit=limit, ascending=False)
        )
        return result.entries

    # ── Internals ──────────────────────────────────────────────────────────────

    def _load_candidates(self, q: AuditQuery) -> list[AuditEntry]:
        """Load candidate entries — by date range if bounded, else all."""
        # If audit_id is set, load directly
        if q.audit_id:
            try:
                return [self._ledger.get(q.audit_id)]
            except Exception:
                return []

        return self._ledger.get_all()

    @staticmethod
    def _matches(entry: AuditEntry, q: AuditQuery) -> bool:
        """Return True if the entry passes all query filters."""
        m = entry.metadata

        # Identity
        if q.audit_id and entry.audit_id != q.audit_id:
            return False
        if q.alert_id and m.alert_id != q.alert_id:
            return False
        if q.context_id and m.context_id != q.context_id:
            return False
        if q.orchestration_id and m.orchestration_id != q.orchestration_id:
            return False
        if q.entity_id and m.entity_id != q.entity_id:
            return False
        if q.host and m.host != q.host:
            return False
        if q.user and m.user != q.user:
            return False

        # Classification
        if q.event_type and str(entry.event_type) != str(q.event_type):
            return False
        if q.severity and (entry.severity or "").lower() != q.severity.lower():
            return False
        if q.outcome and (entry.outcome or "").lower() != q.outcome.lower():
            return False
        if q.actor_id and entry.actor.actor_id != q.actor_id:
            return False
        if q.source_module and m.source_module != q.source_module:
            return False

        # Time range
        if q.after and entry.timestamp <= q.after:
            return False
        if q.before and entry.timestamp >= q.before:
            return False

        return True
