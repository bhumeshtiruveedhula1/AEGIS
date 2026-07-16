"""
backend.orchestrator.audit — Orchestrator Audit Logger
=======================================================
Module 6.1 — Response Orchestrator

Generates and persists immutable OrchestratorAuditEvent records.
Uses the same atomic JSONL append pattern as ContextStore.

File layout
-----------
orchestrator/audit/
├── audit_<YYYY-MM-DD>.jsonl    ← append-only, one event per line
└── (no index — events are queried by orchestration_id via full scan)
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

import structlog

from backend.orchestrator.exceptions import OrchestratorStorageError
from backend.orchestrator.models import OrchestratorAuditEvent

logger = structlog.get_logger(__name__)

_AUDIT_PREFIX = "audit"


class OrchestratorAuditLogger:
    """
    Thread-safe, append-only audit logger for orchestrator lifecycle events.

    Parameters
    ----------
    audit_dir : Directory for JSONL audit files.
    """

    def __init__(self, audit_dir: Path) -> None:
        self._dir = audit_dir
        self._dir.mkdir(parents=True, exist_ok=True)
        self._lock_map: dict[str, threading.Lock] = {}
        self._lock_map_lock = threading.Lock()
        logger.debug("orchestrator_audit_logger_initialized", audit_dir=str(audit_dir))

    # ── Write ─────────────────────────────────────────────────────────────────

    def log_event(
        self,
        orchestration_id: str,
        alert_id: str,
        event_type: str,
        actor: str = "system",
        detail: dict[str, Any] | None = None,
    ) -> OrchestratorAuditEvent:
        """
        Create and persist an immutable audit event.

        Parameters
        ----------
        orchestration_id : The orchestration run this event belongs to.
        alert_id         : Source alert identifier.
        event_type       : e.g. "playbook_selected", "approval_requested", "approved",
                           "rejected", "expired", "execution_started", "execution_complete".
        actor            : Who triggered this event ("system", or an email/ID string).
        detail           : Optional structured metadata.

        Returns
        -------
        OrchestratorAuditEvent — the persisted event.
        """
        event = OrchestratorAuditEvent(
            orchestration_id=orchestration_id,
            alert_id=alert_id,
            event_type=event_type,
            actor=actor,
            detail=detail or {},
        )
        self._append(event)
        logger.info(
            "orchestrator_audit_event",
            event_id=event.event_id,
            orchestration_id=orchestration_id,
            event_type=event_type,
            actor=actor,
        )
        return event

    def load_for_orchestration(self, orchestration_id: str) -> list[OrchestratorAuditEvent]:
        """Scan all audit files and return events matching orchestration_id."""
        events: list[OrchestratorAuditEvent] = []
        for path in sorted(self._dir.glob(f"{_AUDIT_PREFIX}_*.jsonl")):
            events.extend(self._scan_file(path, orchestration_id))
        return sorted(events, key=lambda e: e.timestamp)

    def load_for_date(self, date: datetime | None = None) -> list[OrchestratorAuditEvent]:
        """Load all audit events from a specific date's JSONL partition."""
        target = date or datetime.now(UTC)
        path = self._daily_path(target)
        if not path.exists():
            return []
        return self._scan_file(path, orchestration_id=None)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _append(self, event: OrchestratorAuditEvent) -> None:
        path = self._daily_path(event.timestamp)
        lock = self._get_lock(str(path))
        line = event.model_dump_json() + "\n"
        try:
            with lock, path.open("a", encoding="utf-8") as fh:
                fh.write(line)
        except OSError as exc:
            raise OrchestratorStorageError(
                f"Audit write failed for event {event.event_id}: {exc}",
                context={"event_id": event.event_id, "cause": str(exc)},
            ) from exc

    def _scan_file(self, path: Path, orchestration_id: str | None) -> list[OrchestratorAuditEvent]:
        results: list[OrchestratorAuditEvent] = []
        try:
            with path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        evt = OrchestratorAuditEvent.model_validate_json(line)
                        if orchestration_id is None or evt.orchestration_id == orchestration_id:
                            results.append(evt)
                    except Exception:
                        pass
        except OSError:
            pass
        return results

    def _daily_path(self, ts: datetime) -> Path:
        return self._dir / f"{_AUDIT_PREFIX}_{ts.strftime('%Y-%m-%d')}.jsonl"

    def _get_lock(self, path_str: str) -> threading.Lock:
        with self._lock_map_lock:
            if path_str not in self._lock_map:
                self._lock_map[path_str] = threading.Lock()
            return self._lock_map[path_str]
