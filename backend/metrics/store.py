"""
backend.metrics.store — Metric Store
=====================================
Module 2.3 — Metrics Collection & Evaluation Engine

Persists MetricRecord objects to JSONL history and maintains a
MetricHistoryManifest for fast snapshot discovery.

Storage Layout
--------------
  data/metrics/
    history.jsonl        — All MetricRecord objects, one per line (append-only)
    manifest.json        — MetricHistoryManifest (lightweight index)
    snapshots/           — Per-snapshot JSON files (for random access)
      <snapshot_id>.json

Design
------
- history.jsonl is append-only — no mutation, no lock contention.
- manifest.json is rewritten atomically on every write.
- snapshots/ enables O(1) lookup without scanning history.jsonl.
- MetricStore is NOT a context manager — lifecycle managed by MetricService.
- All writes are UTF-8, all reads are defensive against corrupt lines.

Atomic Writes
-------------
All file writes use a write-then-rename pattern to prevent partial writes.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterator

import structlog

from backend.core.config import get_settings
from backend.metrics.exceptions import MetricStorageError, MetricVersionError
from backend.metrics.models import (
    METRICS_SCHEMA_VERSION,
    MetricHistoryManifest,
    MetricRecord,
    MetricSnapshot,
)

logger = structlog.get_logger(__name__)

_DEFAULT_METRICS_SUBDIR = "metrics"
_HISTORY_FILE = "history.jsonl"
_MANIFEST_FILE = "manifest.json"
_SNAPSHOTS_DIR = "snapshots"


class MetricStore:
    """
    Append-only metric history storage with manifest indexing.

    Parameters
    ----------
    store_dir : Base directory for metric storage.
                Defaults to settings.data_dir / "metrics".
    """

    def __init__(self, store_dir: Path | None = None) -> None:
        settings = get_settings()
        self._store_dir = store_dir or (settings.data_dir / _DEFAULT_METRICS_SUBDIR)
        self._history_file = self._store_dir / _HISTORY_FILE
        self._manifest_file = self._store_dir / _MANIFEST_FILE
        self._snapshots_dir = self._store_dir / _SNAPSHOTS_DIR
        self._manifest: MetricHistoryManifest | None = None  # lazy-loaded

    # ── Public API ───────────────────────────────────────────────────────

    def save(self, snapshot: MetricSnapshot, *, tags: dict | None = None) -> MetricRecord:
        """
        Persist a MetricSnapshot to history.

        Creates a MetricRecord wrapping the snapshot, appends it to
        history.jsonl, writes an individual snapshot JSON file, and
        updates the manifest.

        Parameters
        ----------
        snapshot : The completed MetricSnapshot to persist.
        tags     : Optional key-value tags for filtering.

        Returns
        -------
        MetricRecord — the persisted record.
        """
        if tags:
            # Merge tags into snapshot (immutable — use model_copy)
            snapshot = snapshot.model_copy(update={"tags": {**snapshot.tags, **tags}})

        record = MetricRecord(snapshot=snapshot)
        self._ensure_directories()

        try:
            self._append_to_history(record)
            self._write_snapshot_file(record)
            self._update_manifest(record)
        except Exception as exc:
            msg = f"Failed to save MetricRecord: {exc}"
            raise MetricStorageError(msg, context={"snapshot_id": snapshot.snapshot_id}) from exc

        logger.info(
            "metric_snapshot_saved",
            snapshot_id=snapshot.snapshot_id,
            computed=snapshot.computed_metric_count(),
            unavailable=snapshot.unavailable_metric_count(),
            tags=snapshot.tags,
        )

        return record

    def load_latest(self) -> MetricRecord | None:
        """
        Return the most recently saved MetricRecord.

        Returns None if no metrics have been stored.
        """
        manifest = self._load_manifest()
        if not manifest.entries:
            return None
        latest_entry = manifest.latest_entry()
        if latest_entry is None:
            return None
        return self.load_snapshot(latest_entry.snapshot_id)

    def load_snapshot(self, snapshot_id: str) -> MetricRecord | None:
        """
        Load a specific MetricRecord by snapshot ID.

        Uses the snapshots/ directory for O(1) lookup.
        Falls back to scanning history.jsonl if snapshot file is missing.

        Returns None if the snapshot_id is not found.
        """
        # Fast path: snapshot file
        snapshot_file = self._snapshots_dir / f"{snapshot_id}.json"
        if snapshot_file.exists():
            try:
                return MetricRecord.model_validate_json(snapshot_file.read_text(encoding="utf-8"))
            except Exception as exc:
                logger.warning(
                    "metric_snapshot_file_corrupt",
                    snapshot_id=snapshot_id,
                    error=str(exc),
                )

        # Fallback: scan history
        for record in self.iter_history():
            if record.snapshot.snapshot_id == snapshot_id:
                return record

        return None

    def iter_history(
        self,
        *,
        limit: int | None = None,
        reverse: bool = False,
    ) -> Iterator[MetricRecord]:
        """
        Iterate over all stored MetricRecord objects from history.jsonl.

        Parameters
        ----------
        limit   : Maximum number of records to yield. None = unlimited.
        reverse : If True, yield newest records first (scans all, then reverses).
        """
        if not self._history_file.exists():
            return

        records = []
        with self._history_file.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = MetricRecord.model_validate_json(line)
                    records.append(record)
                except Exception as exc:
                    logger.warning("metric_history_corrupt_line", error=str(exc))

        if reverse:
            records = list(reversed(records))

        for i, record in enumerate(records):
            if limit is not None and i >= limit:
                break
            yield record

    def load_history(
        self,
        *,
        limit: int | None = None,
        since: datetime | None = None,
    ) -> list[MetricRecord]:
        """
        Load metric history as a list, with optional filtering.

        Parameters
        ----------
        limit : Maximum records to return (newest first).
        since : Only return records collected after this UTC datetime.
        """
        records = list(self.iter_history(reverse=True))
        if since is not None:
            records = [r for r in records if r.snapshot.collected_at >= since]
        if limit is not None:
            records = records[:limit]
        return records

    def get_manifest(self) -> MetricHistoryManifest:
        """Return the current metrics manifest (loaded lazily)."""
        return self._load_manifest()

    def record_count(self) -> int:
        """Return the total number of snapshots in the manifest."""
        return self._load_manifest().total_snapshots

    def purge_before(self, cutoff: datetime) -> int:
        """
        Remove history entries older than `cutoff`.

        Rewrites history.jsonl keeping only records >= cutoff.
        Returns count of records purged.

        This is the ONLY mutating operation — use with care.
        """
        all_records = list(self.iter_history())
        keep = [r for r in all_records if r.snapshot.collected_at >= cutoff]
        purged = len(all_records) - len(keep)

        if purged == 0:
            return 0

        # Atomic rewrite
        tmp = self._history_file.with_suffix(".tmp")
        try:
            with tmp.open("w", encoding="utf-8", newline="\n") as f:
                for record in keep:
                    f.write(record.model_dump_json() + "\n")
            tmp.replace(self._history_file)
        except Exception as exc:
            tmp.unlink(missing_ok=True)
            msg = f"Failed to purge history: {exc}"
            raise MetricStorageError(msg) from exc

        # Rebuild manifest
        new_manifest = MetricHistoryManifest()
        for record in keep:
            new_manifest.add_entry(record)
        self._write_manifest(new_manifest)
        self._manifest = new_manifest

        logger.info("metric_history_purged", purged=purged, kept=len(keep), cutoff=cutoff.isoformat())
        return purged

    # ── Private helpers ──────────────────────────────────────────────────

    def _ensure_directories(self) -> None:
        try:
            self._store_dir.mkdir(parents=True, exist_ok=True)
            self._snapshots_dir.mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            msg = f"Cannot create metric store directories at {self._store_dir}: {exc}"
            raise MetricStorageError(msg) from exc

    def _append_to_history(self, record: MetricRecord) -> None:
        """Append one MetricRecord as a JSONL line to history.jsonl."""
        line = record.model_dump_json() + "\n"
        with self._history_file.open("a", encoding="utf-8", newline="\n") as f:
            f.write(line)

    def _write_snapshot_file(self, record: MetricRecord) -> None:
        """Write individual snapshot JSON for O(1) lookup."""
        snapshot_file = self._snapshots_dir / f"{record.snapshot.snapshot_id}.json"
        content = json.dumps(
            json.loads(record.model_dump_json()),
            indent=2,
            ensure_ascii=False,
        )
        # Atomic write via tmp file
        tmp = snapshot_file.with_suffix(".tmp")
        try:
            tmp.write_text(content, encoding="utf-8")
            tmp.replace(snapshot_file)
        except Exception:
            tmp.unlink(missing_ok=True)
            raise

    def _update_manifest(self, record: MetricRecord) -> None:
        """Load manifest, add entry, rewrite atomically."""
        manifest = self._load_manifest()
        manifest.add_entry(record)
        self._write_manifest(manifest)
        self._manifest = manifest

    def _write_manifest(self, manifest: MetricHistoryManifest) -> None:
        """Atomically write the manifest to disk."""
        content = json.dumps(
            json.loads(manifest.model_dump_json()),
            indent=2,
            ensure_ascii=False,
        )
        tmp = self._manifest_file.with_suffix(".tmp")
        try:
            tmp.write_text(content, encoding="utf-8")
            tmp.replace(self._manifest_file)
        except Exception:
            tmp.unlink(missing_ok=True)
            raise

    def _load_manifest(self) -> MetricHistoryManifest:
        """Load the manifest from disk, returning a fresh one if missing."""
        if self._manifest is not None:
            return self._manifest
        if not self._manifest_file.exists():
            self._manifest = MetricHistoryManifest()
            return self._manifest
        try:
            self._manifest = MetricHistoryManifest.model_validate_json(
                self._manifest_file.read_text(encoding="utf-8")
            )
        except Exception as exc:
            logger.warning("metric_manifest_corrupt", error=str(exc))
            self._manifest = MetricHistoryManifest()
        return self._manifest
