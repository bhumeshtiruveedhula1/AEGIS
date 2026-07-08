"""
backend.synthetic_attack.storage — Synthetic Attack Persistence
===============================================================
Module 3.X — Synthetic Attack Generation

Persists AttackExecution (JSONL, date-partitioned) and GenerationReport (JSON, atomic).
Follows the same storage conventions as existing modules.

File layout
-----------
synthetic_attack/
├── executions_<YYYY-MM-DD>.jsonl    ← one AttackExecution per line
└── reports/
    └── report_<report_id>.json      ← GenerationReport (atomic write)
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime
from pathlib import Path

import structlog

from backend.synthetic_attack.exceptions import StorageError
from backend.synthetic_attack.models import (
    SYNTHETIC_SCHEMA_VERSION,
    AttackExecution,
    GenerationReport,
)

logger = structlog.get_logger(__name__)

_EXEC_PREFIX = "executions"
_REPORT_SUBDIR = "reports"


class SyntheticAttackStore:
    """
    Append-only, thread-safe persistence for synthetic attack artifacts.

    Parameters
    ----------
    store_dir : Root directory for storage files.
    """

    def __init__(self, store_dir: Path) -> None:
        self._dir: Path = store_dir
        self._reports_dir: Path = store_dir / _REPORT_SUBDIR
        self._dir.mkdir(parents=True, exist_ok=True)
        self._reports_dir.mkdir(parents=True, exist_ok=True)
        self._lock_map: dict[str, threading.Lock] = {}
        self._lock_map_lock = threading.Lock()
        logger.debug("synthetic_attack_store_initialized", store_dir=str(store_dir))

    # ── Write ─────────────────────────────────────────────────────────────────

    def save_execution(self, execution: AttackExecution) -> Path:
        """Append one AttackExecution to today's JSONL partition. Thread-safe."""
        jsonl_path = self._daily_jsonl_path(execution.executed_at)
        lock = self._get_file_lock(str(jsonl_path))
        try:
            line = execution.model_dump_json() + "\n"
            with lock:
                with jsonl_path.open("a", encoding="utf-8") as fh:
                    fh.write(line)
        except OSError as exc:
            raise StorageError(
                f"Failed to save AttackExecution {execution.execution_id}: {exc}",
                context={"execution_id": execution.execution_id, "cause": str(exc)},
            ) from exc
        return jsonl_path

    def save_executions_batch(self, executions: list[AttackExecution]) -> list[Path]:
        """Batch append — groups by date partition for efficiency."""
        from collections import defaultdict

        groups: dict[str, list[AttackExecution]] = defaultdict(list)
        for ex in executions:
            groups[self._daily_jsonl_path(ex.executed_at).name].append(ex)

        written: list[Path] = []
        for fname, group in groups.items():
            jsonl_path = self._dir / fname
            lock = self._get_file_lock(str(jsonl_path))
            lines = "".join(ex.model_dump_json() + "\n" for ex in group)
            try:
                with lock:
                    with jsonl_path.open("a", encoding="utf-8") as fh:
                        fh.write(lines)
                written.append(jsonl_path)
            except OSError as exc:
                raise StorageError(
                    f"Failed batch write to {jsonl_path}: {exc}",
                    context={"file": str(jsonl_path), "cause": str(exc)},
                ) from exc
        return list(set(written))

    def save_report(self, report: GenerationReport) -> Path:
        """Atomic write via .tmp → rename."""
        path = self._reports_dir / f"report_{report.report_id}.json"
        tmp = path.with_suffix(".tmp")
        try:
            tmp.write_text(report.model_dump_json(indent=2), encoding="utf-8")
            tmp.replace(path)
        except Exception as exc:
            tmp.unlink(missing_ok=True)
            raise StorageError(
                f"Failed to save GenerationReport {report.report_id}: {exc}",
                context={"report_id": report.report_id, "cause": str(exc)},
            ) from exc
        logger.info(
            "generation_report_saved",
            report_id=report.report_id,
            total_events=report.total_events,
        )
        return path

    # ── Read ──────────────────────────────────────────────────────────────────

    def load_executions_for_date(
        self, date: datetime | None = None
    ) -> list[AttackExecution]:
        """Load all AttackExecution records from a specific date's JSONL."""
        target = date or datetime.now(UTC)
        jsonl_path = self._daily_jsonl_path(target)
        if not jsonl_path.exists():
            return []

        results: list[AttackExecution] = []
        errors = 0
        with jsonl_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    ex = AttackExecution.model_validate_json(line)
                    results.append(ex)
                except Exception:  # noqa: BLE001
                    errors += 1
        logger.debug(
            "executions_loaded",
            date=target.date().isoformat(),
            count=len(results),
            errors=errors,
        )
        return results

    def load_report(self, report_id: str) -> GenerationReport:
        """Load a GenerationReport by ID."""
        path = self._reports_dir / f"report_{report_id}.json"
        if not path.exists():
            raise StorageError(
                f"GenerationReport {report_id!r} not found.",
                context={"report_id": report_id},
            )
        try:
            return GenerationReport.model_validate_json(path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise StorageError(
                f"Failed to parse GenerationReport {report_id}: {exc}",
                context={"report_id": report_id, "cause": str(exc)},
            ) from exc

    def list_reports(self) -> list[str]:
        """Return report IDs, newest first."""
        files = sorted(self._reports_dir.glob("report_*.json"), reverse=True)
        return [f.stem.removeprefix("report_") for f in files]

    def list_execution_dates(self) -> list[str]:
        files = sorted(self._dir.glob(f"{_EXEC_PREFIX}_*.jsonl"), reverse=True)
        return [f.stem.removeprefix(f"{_EXEC_PREFIX}_") for f in files]

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _daily_jsonl_path(self, ts: datetime) -> Path:
        return self._dir / f"{_EXEC_PREFIX}_{ts.strftime('%Y-%m-%d')}.jsonl"

    def _get_file_lock(self, path_str: str) -> threading.Lock:
        with self._lock_map_lock:
            if path_str not in self._lock_map:
                self._lock_map[path_str] = threading.Lock()
            return self._lock_map[path_str]
