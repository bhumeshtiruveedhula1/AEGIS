"""
backend.orchestrator.storage — Orchestrator Record Persistence
==============================================================
Module 6.1 — Response Orchestrator

Persists OrchestratorRecord using the same atomic JSON/JSONL strategy
as ContextStore, BaselineStore, GraphStore, and ChainStore.

File layout
-----------
orchestrator/
├── records_<YYYY-MM-DD>.jsonl    ← one OrchestratorRecord per line, append-only
└── index/
    └── <orchestration_id>.json   ← latest record state (atomic write)
"""

from __future__ import annotations

import threading
from collections import defaultdict
from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

import structlog

from backend.orchestrator.exceptions import OrchestratorSchemaError, OrchestratorStorageError
from backend.orchestrator.models import ORCHESTRATOR_SCHEMA_VERSION, OrchestratorRecord

logger = structlog.get_logger(__name__)

_JSONL_PREFIX = "records"
_INDEX_SUBDIR = "index"


class OrchestratorStore:
    """
    Thread-safe, append-only storage for OrchestratorRecord objects.

    Identical conventions to ContextStore — JSONL date-partitioned
    + atomic JSON index per record ID.

    Parameters
    ----------
    store_dir : Root storage directory for orchestrator records.
    """

    def __init__(self, store_dir: Path) -> None:
        self._dir = store_dir
        self._index_dir = store_dir / _INDEX_SUBDIR
        self._dir.mkdir(parents=True, exist_ok=True)
        self._index_dir.mkdir(parents=True, exist_ok=True)
        self._lock_map: dict[str, threading.Lock] = {}
        self._lock_map_lock = threading.Lock()
        logger.debug("orchestrator_store_initialized", store_dir=str(store_dir))

    # ── Write ─────────────────────────────────────────────────────────────────

    def save(self, record: OrchestratorRecord) -> Path:
        """Append record to today's JSONL + write/overwrite atomic index entry."""
        jsonl_path = self._daily_jsonl_path(record.created_at)
        lock = self._get_lock(str(jsonl_path))
        try:
            line = record.model_dump_json() + "\n"
            with lock, jsonl_path.open("a", encoding="utf-8") as fh:
                fh.write(line)
        except OSError as exc:
            raise OrchestratorStorageError(
                f"Failed to save orchestration {record.orchestration_id}: {exc}",
                context={"orchestration_id": record.orchestration_id, "cause": str(exc)},
            ) from exc

        self._write_index(record)
        return jsonl_path

    def save_batch(self, records: list[OrchestratorRecord]) -> list[Path]:
        """Batch save, grouped by date partition."""
        groups: dict[str, list[OrchestratorRecord]] = defaultdict(list)
        for r in records:
            groups[self._daily_jsonl_path(r.created_at).name].append(r)

        written: list[Path] = []
        for fname, group in groups.items():
            jsonl_path = self._dir / fname
            lock = self._get_lock(str(jsonl_path))
            lines = "".join(r.model_dump_json() + "\n" for r in group)
            try:
                with lock, jsonl_path.open("a", encoding="utf-8") as fh:
                    fh.write(lines)
                written.append(jsonl_path)
            except OSError as exc:
                raise OrchestratorStorageError(
                    f"Batch write failed for {jsonl_path}: {exc}",
                    context={"file": str(jsonl_path), "cause": str(exc)},
                ) from exc
            for r in group:
                self._write_index(r)
        return list(set(written))

    # ── Read ──────────────────────────────────────────────────────────────────

    def load(self, orchestration_id: str) -> OrchestratorRecord:
        """Load a single OrchestratorRecord by ID via the index."""
        idx_path = self._index_dir / f"{orchestration_id}.json"
        if not idx_path.exists():
            raise OrchestratorStorageError(
                f"OrchestratorRecord {orchestration_id!r} not found.",
                context={"orchestration_id": orchestration_id},
            )
        raw = idx_path.read_text(encoding="utf-8")
        try:
            record = OrchestratorRecord.model_validate_json(raw)
        except Exception as exc:
            raise OrchestratorSchemaError(
                f"Schema mismatch loading orchestration {orchestration_id}: {exc}",
                context={"orchestration_id": orchestration_id, "cause": str(exc)},
            ) from exc
        if record.schema_version != ORCHESTRATOR_SCHEMA_VERSION:
            raise OrchestratorSchemaError(
                f"Schema version mismatch: got {record.schema_version!r}, "
                f"expected {ORCHESTRATOR_SCHEMA_VERSION!r}.",
                context={"orchestration_id": orchestration_id},
            )
        return record

    def load_for_date(self, date: datetime | None = None) -> list[OrchestratorRecord]:
        """Load all records from a date's JSONL partition."""
        target = date or datetime.now(UTC)
        jsonl_path = self._daily_jsonl_path(target)
        if not jsonl_path.exists():
            return []
        results: list[OrchestratorRecord] = []
        errors = 0
        with jsonl_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    results.append(OrchestratorRecord.model_validate_json(line))
                except Exception:
                    errors += 1
        logger.debug(
            "orchestrator_records_loaded",
            date=target.date().isoformat(),
            count=len(results),
            errors=errors,
        )
        return results

    def load_by_alert(self, alert_id: str) -> list[OrchestratorRecord]:
        """Scan today's JSONL and return records matching alert_id."""
        return [r for r in self.load_for_date() if r.alert_id == alert_id]

    def list_ids(self) -> list[str]:
        """Return all stored orchestration IDs, newest first."""
        return [f.stem for f in sorted(self._index_dir.glob("*.json"), reverse=True)]

    def list_dates(self) -> list[str]:
        files = sorted(self._dir.glob(f"{_JSONL_PREFIX}_*.jsonl"), reverse=True)
        return [f.stem.removeprefix(f"{_JSONL_PREFIX}_") for f in files]

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _daily_jsonl_path(self, ts: datetime) -> Path:
        return self._dir / f"{_JSONL_PREFIX}_{ts.strftime('%Y-%m-%d')}.jsonl"

    def _write_index(self, record: OrchestratorRecord) -> None:
        """Atomic overwrite of index entry (captures latest record state)."""
        path = self._index_dir / f"{record.orchestration_id}.json"
        tmp = path.with_suffix(".tmp")
        try:
            tmp.write_text(record.model_dump_json(indent=2), encoding="utf-8")
            tmp.replace(path)
        except Exception as exc:
            tmp.unlink(missing_ok=True)
            raise OrchestratorStorageError(
                f"Index write failed for {record.orchestration_id}: {exc}",
                context={"orchestration_id": record.orchestration_id, "cause": str(exc)},
            ) from exc

    def _get_lock(self, path_str: str) -> threading.Lock:
        with self._lock_map_lock:
            if path_str not in self._lock_map:
                self._lock_map[path_str] = threading.Lock()
            return self._lock_map[path_str]
