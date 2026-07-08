"""
backend.chain_detection.storage — Chain Store
=============================================
Module 3.5 — Attack Chain Detection Engine

Persists AttackChain (JSONL, date-partitioned) and ChainReport (JSON, atomic).
Same philosophy as MappingStore and GraphStore.

File layout
-----------
chain_detection/
├── chains_<YYYY-MM-DD>.jsonl     ← one AttackChain per line
└── reports/
    └── report_<report_id>.json   ← ChainReport (atomic)
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime
from pathlib import Path

import structlog

from backend.chain_detection.exceptions import ChainSchemaError, ChainStorageError
from backend.chain_detection.models import CHAIN_SCHEMA_VERSION, AttackChain, ChainReport

logger = structlog.get_logger(__name__)

_CHAIN_PREFIX = "chains"
_REPORT_SUBDIR = "reports"


class ChainStore:
    """
    Versioned, append-only persistence for attack chain artifacts.

    Parameters
    ----------
    store_dir : Root directory for chain files.
    """

    def __init__(self, store_dir: Path) -> None:
        self._dir: Path = store_dir
        self._reports_dir: Path = store_dir / _REPORT_SUBDIR
        self._dir.mkdir(parents=True, exist_ok=True)
        self._reports_dir.mkdir(parents=True, exist_ok=True)
        self._file_locks: dict[str, threading.Lock] = {}
        self._lock_map_lock = threading.Lock()
        logger.debug("chain_store_initialized", store_dir=str(store_dir))

    # ── Write ─────────────────────────────────────────────────────────────────

    def save_chain(self, chain: AttackChain) -> Path:
        """Append one AttackChain to today's JSONL partition. Thread-safe."""
        jsonl_path = self._daily_jsonl_path(chain.discovered_at)
        lock = self._get_file_lock(str(jsonl_path))
        try:
            line = chain.model_dump_json() + "\n"
            with lock:
                with jsonl_path.open("a", encoding="utf-8") as fh:
                    fh.write(line)
        except OSError as exc:
            raise ChainStorageError(
                f"Failed to save AttackChain {chain.chain_id}: {exc}",
                context={"chain_id": chain.chain_id, "cause": str(exc)},
            ) from exc
        return jsonl_path

    def save_batch(self, chains: list[AttackChain]) -> list[Path]:
        """Batch append — groups by date partition."""
        from collections import defaultdict
        groups: dict[str, list[AttackChain]] = defaultdict(list)
        for c in chains:
            groups[self._daily_jsonl_path(c.discovered_at).name].append(c)

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
                raise ChainStorageError(
                    f"Failed batch write to {jsonl_path}: {exc}",
                    context={"file": str(jsonl_path), "cause": str(exc)},
                ) from exc
        logger.info("batch_chains_saved", count=len(chains))
        return list(set(written))

    def save_report(self, report: ChainReport) -> Path:
        """Atomic write: .tmp → rename. Returns path."""
        path = self._reports_dir / f"report_{report.report_id}.json"
        tmp = path.with_suffix(".tmp")
        try:
            tmp.write_text(report.model_dump_json(indent=2), encoding="utf-8")
            tmp.replace(path)
        except Exception as exc:
            tmp.unlink(missing_ok=True)
            raise ChainStorageError(
                f"Failed to save ChainReport {report.report_id}: {exc}",
                context={"report_id": report.report_id, "cause": str(exc)},
            ) from exc
        logger.info(
            "chain_report_saved",
            report_id=report.report_id,
            chains=len(report.chains),
        )
        return path

    # ── Read ──────────────────────────────────────────────────────────────────

    def load_chains_for_date(
        self, date: datetime | None = None
    ) -> list[AttackChain]:
        """Load all AttackChain objects from a specific date's JSONL file."""
        target = date or datetime.now(UTC)
        jsonl_path = self._daily_jsonl_path(target)
        if not jsonl_path.exists():
            return []

        results: list[AttackChain] = []
        errors = 0
        with jsonl_path.open("r", encoding="utf-8") as fh:
            for line_no, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    c = AttackChain.model_validate_json(line)
                    self._check_schema(c.schema_version, line_no, jsonl_path)
                    results.append(c)
                except ChainSchemaError:
                    raise
                except Exception:  # noqa: BLE001
                    errors += 1
        logger.debug(
            "chains_loaded",
            date=target.date().isoformat(),
            count=len(results),
            errors=errors,
        )
        return results

    def load_report(self, report_id: str) -> ChainReport:
        """Load a ChainReport by ID."""
        path = self._reports_dir / f"report_{report_id}.json"
        if not path.exists():
            raise ChainStorageError(
                f"ChainReport {report_id!r} not found.",
                context={"report_id": report_id},
            )
        try:
            return ChainReport.model_validate_json(path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise ChainStorageError(
                f"Failed to parse ChainReport {report_id}: {exc}",
                context={"report_id": report_id, "cause": str(exc)},
            ) from exc

    def list_reports(self) -> list[str]:
        """Return report IDs, newest first."""
        files = sorted(self._reports_dir.glob("report_*.json"), reverse=True)
        return [f.stem.removeprefix("report_") for f in files]

    def list_chain_dates(self) -> list[str]:
        files = sorted(self._dir.glob(f"{_CHAIN_PREFIX}_*.jsonl"), reverse=True)
        return [f.stem.removeprefix(f"{_CHAIN_PREFIX}_") for f in files]

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _daily_jsonl_path(self, ts: datetime) -> Path:
        return self._dir / f"{_CHAIN_PREFIX}_{ts.strftime('%Y-%m-%d')}.jsonl"

    def _get_file_lock(self, path_str: str) -> threading.Lock:
        with self._lock_map_lock:
            if path_str not in self._file_locks:
                self._file_locks[path_str] = threading.Lock()
            return self._file_locks[path_str]

    @staticmethod
    def _check_schema(stored: str, line_no: int, path: Path) -> None:
        if stored != CHAIN_SCHEMA_VERSION:
            raise ChainSchemaError(
                f"Schema mismatch at line {line_no} of {path.name}: "
                f"stored={stored!r} current={CHAIN_SCHEMA_VERSION!r}",
                context={"stored": stored, "current": CHAIN_SCHEMA_VERSION},
            )
