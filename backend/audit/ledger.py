"""
backend.audit.ledger — Append-Only Audit Ledger
================================================
Module 7.2 — Audit Ledger

The Ledger is the single write gateway to audit storage.

Responsibilities
----------------
- Accept AuditEntry objects and persist them via AuditStore
- Assign deterministic, monotonically increasing sequence numbers
- Enforce append-only semantics (no deletes, no edits)
- Provide sequential retrieval

The ledger never edits history.
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import structlog

from backend.audit.exceptions import AuditLedgerError, AuditStorageError
from backend.audit.models import (
    AUDIT_SCHEMA_VERSION,
    AuditActor,
    AuditEntry,
    AuditEventType,
    AuditMetadata,
)
from backend.audit.storage import AuditStore

if TYPE_CHECKING:
    from pathlib import Path

logger = structlog.get_logger(__name__)


class AuditLedger:
    """
    Append-only audit ledger.

    The ledger wraps AuditStore and adds:
    - Thread-safe monotonic sequence numbering
    - Convenience factory method for recording events
    - Direct passthrough to AuditStore for reads

    Parameters
    ----------
    store_dir : Storage root directory (passed directly to AuditStore).
    """

    def __init__(self, store_dir: Path) -> None:
        self._store = AuditStore(store_dir)
        self._seq_lock = threading.Lock()
        # Initialise sequence counter from persisted data
        self._next_seq: int = self._store.count_all()
        logger.debug(
            "audit_ledger_initialized",
            store_dir=str(store_dir),
            next_seq=self._next_seq,
        )

    # ── Write ──────────────────────────────────────────────────────────────────

    def record(
        self,
        event_type: AuditEventType | str,
        metadata: AuditMetadata,
        *,
        actor: AuditActor | None = None,
        severity: str | None = None,
        outcome: str | None = None,
        description: str = "",
        payload: dict[str, Any] | None = None,
        timestamp: datetime | None = None,
    ) -> AuditEntry:
        """
        Create and persist a new AuditEntry.

        Parameters
        ----------
        event_type  : Event classification (AuditEventType or its string value).
        metadata    : Source module context and correlation IDs.
        actor       : Who triggered the event. Defaults to system actor.
        severity    : Optional severity hint.
        outcome     : Optional outcome string.
        description : Human-readable summary.
        payload     : Arbitrary module-specific structured data.
        timestamp   : UTC event time. Defaults to now.

        Returns
        -------
        AuditEntry  : The persisted, immutable entry.
        """
        if isinstance(event_type, str):
            event_type = AuditEventType(event_type)

        now = datetime.now(UTC)
        seq = self._next_sequence()

        entry = AuditEntry(
            sequence_number=seq,
            event_type=event_type,
            timestamp=timestamp or now,
            recorded_at=now,
            actor=actor or AuditActor.system(metadata.source_module),
            metadata=metadata,
            severity=severity,
            outcome=outcome,
            description=description,
            payload=payload or {},
            schema_version=AUDIT_SCHEMA_VERSION,
        )
        try:
            self._store.save(entry)
        except AuditStorageError:
            raise
        except Exception as exc:
            raise AuditLedgerError(
                f"Unexpected error recording audit entry: {exc}",
                context={"event_type": str(event_type), "cause": str(exc)},
            ) from exc

        logger.debug(
            "audit_entry_recorded",
            audit_id=entry.audit_id,
            event_type=str(event_type),
            seq=seq,
        )
        return entry

    def append(self, entry: AuditEntry) -> AuditEntry:
        """
        Append a pre-built AuditEntry to the ledger.

        The entry's sequence_number is overwritten with the next monotonic value
        to guarantee ordering even when callers construct entries themselves.
        """
        seq = self._next_sequence()
        # AuditEntry is frozen; reconstruct with correct sequence number
        entry = entry.model_copy(update={"sequence_number": seq})
        self._store.save(entry)
        logger.debug(
            "audit_entry_appended",
            audit_id=entry.audit_id,
            event_type=str(entry.event_type),
            seq=seq,
        )
        return entry

    # ── Read ───────────────────────────────────────────────────────────────────

    def get(self, audit_id: str) -> AuditEntry:
        """Retrieve a single AuditEntry by its ID."""
        return self._store.load(audit_id)

    def get_for_date(self, date: datetime | None = None) -> list[AuditEntry]:
        """Return all entries for the given UTC date (today if None)."""
        return self._store.load_for_date(date)

    def get_all(self) -> list[AuditEntry]:
        """Return every persisted entry across all partitions, oldest first."""
        return self._store.load_all()

    def list_ids(self) -> list[str]:
        """Return all stored audit_ids, newest first."""
        return self._store.list_ids()

    def list_dates(self) -> list[str]:
        """Return date strings for all partitions, newest first."""
        return self._store.list_dates()

    def count(self) -> int:
        """Total number of stored entries."""
        return self._store.count_all()

    # ── Internal ───────────────────────────────────────────────────────────────

    def _next_sequence(self) -> int:
        with self._seq_lock:
            seq = self._next_seq
            self._next_seq += 1
            return seq
