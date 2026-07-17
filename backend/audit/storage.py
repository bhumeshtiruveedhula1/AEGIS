"""
backend.audit.storage — Audit Ledger Persistence
=================================================
Module 7.2 — Audit Ledger

Append-only JSONL storage for AuditEntry records.

Follows the identical persistence convention used by ContextStore,
OrchestratorStore, GraphStore, and ChainStore:

File layout
-----------
audit/
├── entries_<YYYY-MM-DD>.jsonl  ← one AuditEntry per line, append-only
└── index/
    └── <audit_id>.json         ← latest record state (atomic write)
"""

from __future__ import annotations

import contextlib
import threading
from collections import defaultdict
from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

import structlog

from backend.audit.exceptions import AuditSchemaError, AuditStorageError
from backend.audit.models import AUDIT_SCHEMA_VERSION, AuditEntry

logger = structlog.get_logger(__name__)

_JSONL_PREFIX = "entries"
_INDEX_SUBDIR = "index"


class AuditStore:
    """
    Thread-safe, append-only storage for AuditEntry objects.

    Mirrors OrchestratorStore conventions exactly:
    - JSONL date-partitioned files
    - Atomic JSON index per audit_id
    - Per-file threading.Lock for safe concurrent appends

    Parameters
    ----------
    store_dir : Root storage directory for audit records.
    """

    def __init__(self, store_dir: Path) -> None:
        self._dir = store_dir
        self._index_dir = store_dir / _INDEX_SUBDIR
        self._dir.mkdir(parents=True, exist_ok=True)
        self._index_dir.mkdir(parents=True, exist_ok=True)
        self._lock_map: dict[str, threading.Lock] = {}
        self._lock_map_lock = threading.Lock()
        logger.debug("audit_store_initialized", store_dir=str(store_dir))

    # ── Write ──────────────────────────────────────────────────────────────────

    def save(self, entry: AuditEntry) -> Path:
        """Append entry to its date-partition JSONL + write atomic index."""
        jsonl_path = self._daily_jsonl_path(entry.recorded_at)
        lock = self._get_lock(str(jsonl_path))
        try:
            line = entry.model_dump_json() + "\n"
            with lock, jsonl_path.open("a", encoding="utf-8") as fh:
                fh.write(line)
        except OSError as exc:
            raise AuditStorageError(
                f"Failed to save audit entry {entry.audit_id}: {exc}",
                context={"audit_id": entry.audit_id, "cause": str(exc)},
            ) from exc

        self._write_index(entry)
        return jsonl_path

    def save_batch(self, entries: list[AuditEntry]) -> list[Path]:
        """Batch save, grouped by date partition for efficient I/O."""
        groups: dict[str, list[AuditEntry]] = defaultdict(list)
        for e in entries:
            groups[self._daily_jsonl_path(e.recorded_at).name].append(e)

        written: list[Path] = []
        for fname, group in groups.items():
            jsonl_path = self._dir / fname
            lock = self._get_lock(str(jsonl_path))
            lines = "".join(e.model_dump_json() + "\n" for e in group)
            try:
                with lock, jsonl_path.open("a", encoding="utf-8") as fh:
                    fh.write(lines)
                written.append(jsonl_path)
            except OSError as exc:
                raise AuditStorageError(
                    f"Batch write failed for {jsonl_path}: {exc}",
                    context={"file": str(jsonl_path), "cause": str(exc)},
                ) from exc
            for e in group:
                self._write_index(e)
        return list(set(written))

    # ── Read ───────────────────────────────────────────────────────────────────

    def load(self, audit_id: str) -> AuditEntry:
        """Load a single AuditEntry by ID via the index."""
        idx_path = self._index_dir / f"{audit_id}.json"
        if not idx_path.exists():
            from backend.audit.exceptions import AuditRecordNotFoundError

            raise AuditRecordNotFoundError(
                f"AuditEntry {audit_id!r} not found.",
                context={"audit_id": audit_id},
            )
        raw = idx_path.read_text(encoding="utf-8")
        try:
            entry = AuditEntry.model_validate_json(raw)
        except Exception as exc:
            raise AuditSchemaError(
                f"Schema error loading audit entry {audit_id}: {exc}",
                context={"audit_id": audit_id, "cause": str(exc)},
            ) from exc
        if entry.schema_version != AUDIT_SCHEMA_VERSION:
            raise AuditSchemaError(
                f"Schema version mismatch: got {entry.schema_version!r}, "
                f"expected {AUDIT_SCHEMA_VERSION!r}.",
                context={"audit_id": audit_id},
            )
        return entry

    def load_for_date(self, date: datetime | None = None) -> list[AuditEntry]:
        """Load all entries from a date-partition JSONL file."""
        target = date or datetime.now(UTC)
        jsonl_path = self._daily_jsonl_path(target)
        if not jsonl_path.exists():
            return []
        results: list[AuditEntry] = []
        errors = 0
        with jsonl_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    results.append(AuditEntry.model_validate_json(line))
                except Exception:
                    errors += 1
        logger.debug(
            "audit_entries_loaded",
            date=target if isinstance(target, str) else str(target)[:10],
            count=len(results),
            errors=errors,
        )
        return results

    def load_all(self) -> list[AuditEntry]:
        """Load every entry across all date partitions, oldest first."""
        all_files = sorted(self._dir.glob(f"{_JSONL_PREFIX}_*.jsonl"))
        results: list[AuditEntry] = []
        for f in all_files:
            for line in f.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                with contextlib.suppress(Exception):
                    results.append(AuditEntry.model_validate_json(line))
        return results

    def list_ids(self) -> list[str]:
        """Return all stored audit IDs, newest first."""
        return [f.stem for f in sorted(self._index_dir.glob("*.json"), reverse=True)]

    def list_dates(self) -> list[str]:
        """Return date strings for all stored partitions, newest first."""
        files = sorted(self._dir.glob(f"{_JSONL_PREFIX}_*.jsonl"), reverse=True)
        return [f.stem.removeprefix(f"{_JSONL_PREFIX}_") for f in files]

    def count_all(self) -> int:
        """Total number of entries across all partitions (by JSONL line count)."""
        total = 0
        for f in self._dir.glob(f"{_JSONL_PREFIX}_*.jsonl"):
            total += sum(1 for line in f.read_text(encoding="utf-8").splitlines() if line.strip())
        return total

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _daily_jsonl_path(self, ts: datetime) -> Path:
        return self._dir / f"{_JSONL_PREFIX}_{ts.strftime('%Y-%m-%d')}.jsonl"

    def _write_index(self, entry: AuditEntry) -> None:
        """Atomic overwrite of the index entry (idempotent for same audit_id)."""
        path = self._index_dir / f"{entry.audit_id}.json"
        tmp = path.with_suffix(".tmp")
        try:
            tmp.write_text(entry.model_dump_json(indent=2), encoding="utf-8")
            tmp.replace(path)
        except Exception as exc:
            tmp.unlink(missing_ok=True)
            raise AuditStorageError(
                f"Index write failed for {entry.audit_id}: {exc}",
                context={"audit_id": entry.audit_id, "cause": str(exc)},
            ) from exc

    def _get_lock(self, path_str: str) -> threading.Lock:
        with self._lock_map_lock:
            if path_str not in self._lock_map:
                self._lock_map[path_str] = threading.Lock()
            return self._lock_map[path_str]
