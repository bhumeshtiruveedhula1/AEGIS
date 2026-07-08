"""
backend.mitre.storage — MITRE Mapping Store
============================================
Module 3.3 — MITRE ATT&CK Mapper

Persists MappedAttack (JSONL) and MappingReport (JSON).
Follows the same atomic write / date-partitioned pattern as ExplanationStore.

File layout
-----------
mappings/
├── mappings_<YYYY-MM-DD>.jsonl    ← one MappedAttack per line
└── reports/
    └── report_<report_id>.json    ← one MappingReport per file
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime
from pathlib import Path

import structlog

from backend.mitre.exceptions import MappingStorageError, SchemaCompatibilityError
from backend.mitre.models import MITRE_SCHEMA_VERSION, MappedAttack, MappingReport

logger = structlog.get_logger(__name__)

_MAPPING_PREFIX = "mappings"
_REPORT_SUBDIR = "reports"


class MappingStore:
    """
    Versioned, append-only persistence for MITRE mapping artifacts.

    Parameters
    ----------
    store_dir : Root directory for mapping files.
    """

    def __init__(self, store_dir: Path) -> None:
        self._dir: Path = store_dir
        self._reports_dir: Path = store_dir / _REPORT_SUBDIR
        self._dir.mkdir(parents=True, exist_ok=True)
        self._reports_dir.mkdir(parents=True, exist_ok=True)
        self._file_locks: dict[str, threading.Lock] = {}
        self._lock_map_lock = threading.Lock()
        logger.debug("mapping_store_initialized", store_dir=str(store_dir))

    # ── Write ─────────────────────────────────────────────────────────────────

    def save_mapping(self, mapping: MappedAttack) -> Path:
        """Append one MappedAttack to today's JSONL partition. Thread-safe."""
        jsonl_path = self._daily_jsonl_path(mapping.mapped_at)
        lock = self._get_file_lock(str(jsonl_path))
        try:
            line = mapping.model_dump_json() + "\n"
            with lock:
                with jsonl_path.open("a", encoding="utf-8") as fh:
                    fh.write(line)
        except OSError as exc:
            raise MappingStorageError(
                f"Failed to save MappedAttack {mapping.mapping_id}: {exc}",
                context={"mapping_id": mapping.mapping_id, "cause": str(exc)},
            ) from exc
        logger.debug("mapping_saved", mapping_id=mapping.mapping_id)
        return jsonl_path

    def save_batch(self, mappings: list[MappedAttack]) -> list[Path]:
        """Batch append — groups by date partition for efficiency."""
        from collections import defaultdict
        groups: dict[str, list[MappedAttack]] = defaultdict(list)
        for m in mappings:
            groups[self._daily_jsonl_path(m.mapped_at).name].append(m)

        written: list[Path] = []
        for fname, group in groups.items():
            jsonl_path = self._dir / fname
            lock = self._get_file_lock(str(jsonl_path))
            lines = "".join(m.model_dump_json() + "\n" for m in group)
            try:
                with lock:
                    with jsonl_path.open("a", encoding="utf-8") as fh:
                        fh.write(lines)
                written.append(jsonl_path)
            except OSError as exc:
                raise MappingStorageError(
                    f"Failed batch write to {jsonl_path}: {exc}",
                    context={"file": str(jsonl_path), "cause": str(exc)},
                ) from exc
        logger.info("batch_mappings_saved", count=len(mappings))
        return list(set(written))

    def save_report(self, report: MappingReport) -> Path:
        """Atomic write: .tmp → rename. Returns the report file path."""
        report_path = self._reports_dir / f"report_{report.report_id}.json"
        tmp_path = report_path.with_suffix(".tmp")
        try:
            tmp_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
            tmp_path.replace(report_path)
        except Exception as exc:
            tmp_path.unlink(missing_ok=True)
            raise MappingStorageError(
                f"Failed to save MappingReport {report.report_id}: {exc}",
                context={"report_id": report.report_id, "cause": str(exc)},
            ) from exc
        logger.info(
            "mapping_report_saved",
            report_id=report.report_id,
            path=str(report_path),
        )
        return report_path

    # ── Read ──────────────────────────────────────────────────────────────────

    def load_mappings_for_date(
        self, date: datetime | None = None
    ) -> list[MappedAttack]:
        """Load all MappedAttack objects from a specific date's JSONL file."""
        target = date or datetime.now(UTC)
        jsonl_path = self._daily_jsonl_path(target)
        if not jsonl_path.exists():
            return []

        results: list[MappedAttack] = []
        errors = 0
        with jsonl_path.open("r", encoding="utf-8") as fh:
            for line_no, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    m = MappedAttack.model_validate_json(line)
                    self._check_schema(m.schema_version, line_no, jsonl_path)
                    results.append(m)
                except SchemaCompatibilityError:
                    raise
                except Exception as exc:  # noqa: BLE001
                    errors += 1
                    logger.debug(
                        "mapping_parse_error",
                        file=jsonl_path.name,
                        line=line_no,
                        error=str(exc),
                    )
        logger.debug(
            "mappings_loaded",
            date=target.date().isoformat(),
            count=len(results),
            errors=errors,
        )
        return results

    def load_report(self, report_id: str) -> MappingReport:
        """Load a specific MappingReport by ID."""
        path = self._reports_dir / f"report_{report_id}.json"
        if not path.exists():
            raise MappingStorageError(
                f"MappingReport {report_id!r} not found.",
                context={"report_id": report_id},
            )
        try:
            raw = path.read_text(encoding="utf-8")
            return MappingReport.model_validate_json(raw)
        except Exception as exc:
            raise MappingStorageError(
                f"Failed to parse MappingReport {report_id}: {exc}",
                context={"report_id": report_id, "cause": str(exc)},
            ) from exc

    def list_reports(self) -> list[str]:
        """Return all report IDs, newest first."""
        files = sorted(self._reports_dir.glob("report_*.json"), reverse=True)
        return [f.stem.removeprefix("report_") for f in files]

    def list_mapping_dates(self) -> list[str]:
        files = sorted(self._dir.glob(f"{_MAPPING_PREFIX}_*.jsonl"), reverse=True)
        return [f.stem.removeprefix(f"{_MAPPING_PREFIX}_") for f in files]

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _daily_jsonl_path(self, ts: datetime) -> Path:
        return self._dir / f"{_MAPPING_PREFIX}_{ts.strftime('%Y-%m-%d')}.jsonl"

    def _get_file_lock(self, path_str: str) -> threading.Lock:
        with self._lock_map_lock:
            if path_str not in self._file_locks:
                self._file_locks[path_str] = threading.Lock()
            return self._file_locks[path_str]

    @staticmethod
    def _check_schema(stored_version: str, line_no: int, path: Path) -> None:
        if stored_version != MITRE_SCHEMA_VERSION:
            raise SchemaCompatibilityError(
                f"Schema mismatch at line {line_no} of {path.name}: "
                f"stored={stored_version!r} current={MITRE_SCHEMA_VERSION!r}",
                context={"stored": stored_version, "current": MITRE_SCHEMA_VERSION},
            )
