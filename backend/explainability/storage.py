"""
backend.explainability.storage — Explanation Store
====================================================
Module 3.2 — SHAP Explainability Layer

Persists ExplanationResult and ExplainabilityReport objects as JSONL files.
Atomic writes (write .tmp → rename) — never partial files visible to readers.

File Layout
-----------
explanations/
├── explanations_<date>.jsonl        ← one ExplanationResult per line
└── reports/
    └── report_<report_id>.json      ← one ExplainabilityReport per file

The date-partitioned JSONL approach matches the FeatureRecord output pattern
and simplifies time-range queries without a database.

Thread Safety
-------------
Each write uses os-level atomic rename.  Concurrent writers to the same
daily JSONL file use a threading.Lock on the file path.
"""

from __future__ import annotations

import json
import threading
from datetime import UTC, datetime
from pathlib import Path

import structlog

from backend.explainability.exceptions import ExplanationStorageError
from backend.explainability.models import ExplanationResult, ExplainabilityReport

logger = structlog.get_logger(__name__)

# File naming
_EXPL_PREFIX = "explanations"
_REPORT_SUBDIR = "reports"


class ExplanationStore:
    """
    Versioned, append-only persistence for explanation artifacts.

    Parameters
    ----------
    store_dir : Root directory for explanation files.
                Defaults to settings.data_dir / "explanations" if not provided.
    """

    def __init__(self, store_dir: Path) -> None:
        self._dir: Path = store_dir
        self._reports_dir: Path = store_dir / _REPORT_SUBDIR
        self._dir.mkdir(parents=True, exist_ok=True)
        self._reports_dir.mkdir(parents=True, exist_ok=True)
        # Per-file locks to prevent concurrent partial-line writes to JSONL
        self._file_locks: dict[str, threading.Lock] = {}
        self._lock_map_lock = threading.Lock()
        logger.debug("explanation_store_initialized", store_dir=str(store_dir))

    # ── Write API ─────────────────────────────────────────────────────────────

    def save_explanation(self, result: ExplanationResult) -> Path:
        """
        Append one ExplanationResult to today's JSONL partition.

        Uses a threading.Lock per file to prevent interleaved lines.
        Each line is one complete JSON object (JSONL format).

        Returns
        -------
        Path to the JSONL file the result was appended to.

        Raises
        ------
        ExplanationStorageError on I/O failure.
        """
        jsonl_path = self._daily_jsonl_path(result.explained_at)
        lock = self._get_file_lock(str(jsonl_path))

        try:
            line = result.model_dump_json() + "\n"
            with lock:
                with jsonl_path.open("a", encoding="utf-8") as fh:
                    fh.write(line)
        except OSError as exc:
            raise ExplanationStorageError(
                f"Failed to write ExplanationResult to {jsonl_path}: {exc}",
                context={"explanation_id": result.explanation_id, "cause": str(exc)},
            ) from exc

        logger.debug(
            "explanation_saved",
            explanation_id=result.explanation_id,
            alert_id=result.alert_id,
            file=jsonl_path.name,
        )
        return jsonl_path

    def save_report(self, report: ExplainabilityReport) -> Path:
        """
        Persist an ExplainabilityReport as a standalone JSON file.
        Atomic write: write .tmp → rename.

        Returns
        -------
        Path to the saved report file.

        Raises
        ------
        ExplanationStorageError on I/O failure.
        """
        report_path = self._reports_dir / f"report_{report.report_id}.json"
        tmp_path = report_path.with_suffix(".tmp")

        try:
            tmp_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
            tmp_path.replace(report_path)
        except Exception as exc:
            tmp_path.unlink(missing_ok=True)
            raise ExplanationStorageError(
                f"Failed to save ExplainabilityReport {report.report_id}: {exc}",
                context={"report_id": report.report_id, "cause": str(exc)},
            ) from exc

        logger.info(
            "report_saved",
            report_id=report.report_id,
            alerts_explained=report.alerts_explained,
            path=str(report_path),
        )
        return report_path

    def save_batch(self, results: list[ExplanationResult]) -> list[Path]:
        """
        Save multiple ExplanationResult objects efficiently.
        Groups by date partition to minimize file open/close operations.

        Returns
        -------
        List of distinct JSONL paths written to.
        """
        # Group by date partition
        from collections import defaultdict
        groups: dict[str, list[ExplanationResult]] = defaultdict(list)
        for r in results:
            key = self._daily_jsonl_path(r.explained_at).name
            groups[key].append(r)

        written_paths: list[Path] = []
        for filename, group_results in groups.items():
            jsonl_path = self._dir / filename
            lock = self._get_file_lock(str(jsonl_path))
            lines = "".join(r.model_dump_json() + "\n" for r in group_results)
            try:
                with lock:
                    with jsonl_path.open("a", encoding="utf-8") as fh:
                        fh.write(lines)
                written_paths.append(jsonl_path)
            except OSError as exc:
                raise ExplanationStorageError(
                    f"Failed batch write to {jsonl_path}: {exc}",
                    context={"file": str(jsonl_path), "cause": str(exc)},
                ) from exc

        logger.info("batch_explanations_saved", count=len(results))
        return list(set(written_paths))

    # ── Read API ─────────────────────────────────────────────────────────────

    def load_explanations_for_date(
        self,
        date: datetime | None = None,
    ) -> list[ExplanationResult]:
        """
        Load all ExplanationResult objects from a specific date's JSONL file.

        Parameters
        ----------
        date : UTC datetime. Defaults to today.

        Returns
        -------
        list[ExplanationResult] — empty if no file exists for that date.
        """
        target = date or datetime.now(UTC)
        jsonl_path = self._daily_jsonl_path(target)

        if not jsonl_path.exists():
            return []

        results: list[ExplanationResult] = []
        errors = 0
        with jsonl_path.open("r", encoding="utf-8") as fh:
            for line_no, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    results.append(ExplanationResult.model_validate_json(line))
                except Exception as exc:  # noqa: BLE001
                    errors += 1
                    logger.debug(
                        "explanation_parse_error",
                        file=jsonl_path.name,
                        line=line_no,
                        error=str(exc),
                    )
        logger.debug(
            "explanations_loaded",
            date=target.date().isoformat(),
            count=len(results),
            errors=errors,
        )
        return results

    def load_report(self, report_id: str) -> ExplainabilityReport:
        """
        Load a specific ExplainabilityReport by its report_id.

        Raises
        ------
        ExplanationStorageError if the file does not exist or is corrupt.
        """
        report_path = self._reports_dir / f"report_{report_id}.json"
        if not report_path.exists():
            raise ExplanationStorageError(
                f"Report {report_id!r} not found.",
                context={"report_id": report_id, "expected_path": str(report_path)},
            )
        try:
            raw = report_path.read_text(encoding="utf-8")
            return ExplainabilityReport.model_validate_json(raw)
        except Exception as exc:
            raise ExplanationStorageError(
                f"Failed to parse report {report_id}: {exc}",
                context={"report_id": report_id, "cause": str(exc)},
            ) from exc

    def list_reports(self) -> list[str]:
        """Return all available report_ids (newest first by filename sort)."""
        files = sorted(self._reports_dir.glob("report_*.json"), reverse=True)
        return [f.stem.removeprefix("report_") for f in files]

    def list_explanation_dates(self) -> list[str]:
        """Return all dates for which explanation JSONL files exist."""
        files = sorted(self._dir.glob(f"{_EXPL_PREFIX}_*.jsonl"), reverse=True)
        return [f.stem.removeprefix(f"{_EXPL_PREFIX}_") for f in files]

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _daily_jsonl_path(self, ts: datetime) -> Path:
        """Build the path for the date-partitioned JSONL file."""
        date_str = ts.strftime("%Y-%m-%d")
        return self._dir / f"{_EXPL_PREFIX}_{date_str}.jsonl"

    def _get_file_lock(self, path_str: str) -> threading.Lock:
        """Return (or create) the threading.Lock for a given file path."""
        with self._lock_map_lock:
            if path_str not in self._file_locks:
                self._file_locks[path_str] = threading.Lock()
            return self._file_locks[path_str]
