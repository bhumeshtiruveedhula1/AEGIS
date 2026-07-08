"""
backend.context.storage — Attack Context Persistence
=====================================================
Module 4.1 — Attack Context Generation

Persists AttackContext (JSONL, date-partitioned) and index JSON (atomic).
Identical conventions to BaselineStore, MetricStore, GraphStore, ChainStore.

File layout
-----------
context/
├── contexts_<YYYY-MM-DD>.jsonl    ← one AttackContext per line, append-only
└── index/
    └── <context_id>.json           ← lightweight index entry (atomic write)
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime
from pathlib import Path

import structlog

from backend.context.exceptions import ContextSchemaError, ContextStorageError
from backend.context.models import CONTEXT_SCHEMA_VERSION, AttackContext

logger = structlog.get_logger(__name__)

_JSONL_PREFIX = "contexts"
_INDEX_SUBDIR = "index"


class ContextStore:
    """
    Thread-safe, append-only storage for AttackContext objects.

    Parameters
    ----------
    store_dir : Root storage directory.
    """

    def __init__(self, store_dir: Path) -> None:
        self._dir = store_dir
        self._index_dir = store_dir / _INDEX_SUBDIR
        self._dir.mkdir(parents=True, exist_ok=True)
        self._index_dir.mkdir(parents=True, exist_ok=True)
        self._lock_map: dict[str, threading.Lock] = {}
        self._lock_map_lock = threading.Lock()
        logger.debug("context_store_initialized", store_dir=str(store_dir))

    # ── Write ─────────────────────────────────────────────────────────────────

    def save(self, ctx: AttackContext) -> Path:
        """Append context to today's JSONL + write atomic index entry."""
        jsonl_path = self._daily_jsonl_path(ctx.assembled_at)
        lock = self._get_file_lock(str(jsonl_path))
        try:
            line = ctx.model_dump_json() + "\n"
            with lock:
                with jsonl_path.open("a", encoding="utf-8") as fh:
                    fh.write(line)
        except OSError as exc:
            raise ContextStorageError(
                f"Failed to save context {ctx.context_id}: {exc}",
                context={"context_id": ctx.context_id, "cause": str(exc)},
            ) from exc

        self._write_index(ctx)
        return jsonl_path

    def save_batch(self, contexts: list[AttackContext]) -> list[Path]:
        """Batch append, grouped by date partition."""
        from collections import defaultdict
        groups: dict[str, list[AttackContext]] = defaultdict(list)
        for c in contexts:
            groups[self._daily_jsonl_path(c.assembled_at).name].append(c)

        written: list[Path] = []
        for fname, group in groups.items():
            jsonl_path = self._dir / fname
            lock = self._get_file_lock(str(jsonl_path))
            lines = "".join(c.model_dump_json() + "\n" for c in group)
            try:
                with lock:
                    with jsonl_path.open("a", encoding="utf-8") as fh:
                        fh.write(lines)
                written.append(jsonl_path)
            except OSError as exc:
                raise ContextStorageError(
                    f"Batch write failed for {jsonl_path}: {exc}",
                    context={"file": str(jsonl_path), "cause": str(exc)},
                ) from exc
            for c in group:
                self._write_index(c)
        return list(set(written))

    # ── Read ──────────────────────────────────────────────────────────────────

    def load(self, context_id: str) -> AttackContext:
        """Load a single AttackContext by ID via the index."""
        idx_path = self._index_dir / f"{context_id}.json"
        if not idx_path.exists():
            raise ContextStorageError(
                f"AttackContext {context_id!r} not found.",
                context={"context_id": context_id},
            )
        raw = idx_path.read_text(encoding="utf-8")
        try:
            ctx = AttackContext.model_validate_json(raw)
        except Exception as exc:
            raise ContextSchemaError(
                f"Schema mismatch loading context {context_id}: {exc}",
                context={"context_id": context_id, "cause": str(exc)},
            ) from exc
        if ctx.schema_version != CONTEXT_SCHEMA_VERSION:
            raise ContextSchemaError(
                f"Schema version mismatch: got {ctx.schema_version!r}, "
                f"expected {CONTEXT_SCHEMA_VERSION!r}.",
                context={"context_id": context_id},
            )
        return ctx

    def load_for_date(self, date: datetime | None = None) -> list[AttackContext]:
        """Load all AttackContext records from a date's JSONL partition."""
        target = date or datetime.now(UTC)
        jsonl_path = self._daily_jsonl_path(target)
        if not jsonl_path.exists():
            return []
        results: list[AttackContext] = []
        errors = 0
        with jsonl_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    results.append(AttackContext.model_validate_json(line))
                except Exception:  # noqa: BLE001
                    errors += 1
        logger.debug(
            "contexts_loaded",
            date=target.date().isoformat(),
            count=len(results),
            errors=errors,
        )
        return results

    def load_by_alert(self, alert_id: str) -> list[AttackContext]:
        """Scan today's JSONL and return contexts matching alert_id."""
        return [c for c in self.load_for_date() if c.identity.alert_id == alert_id]

    def list_context_ids(self) -> list[str]:
        """Return all stored context IDs, newest first."""
        return [f.stem for f in sorted(
            self._index_dir.glob("*.json"), reverse=True
        )]

    def list_dates(self) -> list[str]:
        files = sorted(self._dir.glob(f"{_JSONL_PREFIX}_*.jsonl"), reverse=True)
        return [f.stem.removeprefix(f"{_JSONL_PREFIX}_") for f in files]

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _daily_jsonl_path(self, ts: datetime) -> Path:
        return self._dir / f"{_JSONL_PREFIX}_{ts.strftime('%Y-%m-%d')}.jsonl"

    def _write_index(self, ctx: AttackContext) -> None:
        """Atomic write of full context to index file."""
        path = self._index_dir / f"{ctx.context_id}.json"
        tmp = path.with_suffix(".tmp")
        try:
            tmp.write_text(ctx.model_dump_json(indent=2), encoding="utf-8")
            tmp.replace(path)
        except Exception as exc:
            tmp.unlink(missing_ok=True)
            raise ContextStorageError(
                f"Index write failed for {ctx.context_id}: {exc}",
                context={"context_id": ctx.context_id, "cause": str(exc)},
            ) from exc

    def _get_file_lock(self, path_str: str) -> threading.Lock:
        with self._lock_map_lock:
            if path_str not in self._lock_map:
                self._lock_map[path_str] = threading.Lock()
            return self._lock_map[path_str]
