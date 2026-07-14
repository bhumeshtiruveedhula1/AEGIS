"""
backend.features.pipeline — Feature Extraction Pipeline
========================================================
Module 2.2 — Behavioral Feature Engine

Orchestrates the full feature extraction workflow:
  1. Load normalized CanonicalEvents (from Module 1.3 output)
  2. Resolve entity keys (user, host, source, user_host)
  3. Query BaselineReader for each entity dimension
  4. Run all extractors in group order
  5. Assemble FeatureVector and FeatureRecord for each entity × event pair
  6. Report statistics via FeaturePipelineReport

Design
------
- Pipeline is stateless across runs — all state lives in BaselineReader.
- Each event produces up to 4 FeatureRecords (one per entity dimension).
- Extractors are isolated via safe_extract() — one failure ≠ abort.
- BaselinePresenceExtractor is special: receives context dict per event.
- Primary entity dimension for feature extraction: most-specific-first.
  (user_host > user > host > source)

Primary Entity Selection
------------------------
The pipeline selects ONE primary entity baseline for feature computation
per event. The most specific available dimension is used:
  1. user_host (user on specific host)
  2. user
  3. host
  4. source
  5. None (cold-start — no baseline for any dimension)

This ensures features like process novelty are computed against the
most refined behavioral model available for the actor.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import structlog

from backend.baseline.models import EntityKey
from backend.baseline.reader_api import BaselineReader
from backend.features.extractors import get_all_extractors
from backend.features.extractors.baseline import BaselinePresenceExtractor
from backend.features.models import (
    FEATURE_SCHEMA_VERSION,
    FeaturePipelineReport,
    FeatureRecord,
    FeatureVector,
)
from backend.normalization.models import CanonicalEvent

if TYPE_CHECKING:
    from backend.baseline.models import EntityBaseline
    from backend.features.extractors import BaseExtractor

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Entity key resolution helpers
# ---------------------------------------------------------------------------


def _make_user_key(event: CanonicalEvent) -> EntityKey | None:
    try:
        return EntityKey(entity_type="user", entity_id=event.user)
    except Exception:
        return None


def _make_host_key(event: CanonicalEvent) -> EntityKey | None:
    try:
        return EntityKey(entity_type="host", entity_id=event.host)
    except Exception:
        return None


def _make_source_key(event: CanonicalEvent) -> EntityKey | None:
    try:
        return EntityKey(entity_type="source", entity_id=event.source)
    except Exception:
        return None


def _make_user_host_key(event: CanonicalEvent) -> EntityKey | None:
    try:
        composite_id = f"{event.user}::{event.host}"
        return EntityKey(entity_type="user_host", entity_id=composite_id)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# FeaturePipeline
# ---------------------------------------------------------------------------


class FeaturePipeline:
    """
    Behavioral feature extraction pipeline.

    Processes a stream of CanonicalEvents and produces FeatureRecords
    for every entity dimension where a baseline is available (or all
    dimensions regardless, depending on configuration).

    Parameters
    ----------
    baseline_reader : BaselineReader instance. Defaults to a new instance
                      loaded from the default baseline directory.
    emit_all_dimensions : If True, produce one FeatureRecord per entity
                          dimension per event (up to 4). Default: True.
    primary_only : If True, produce only one FeatureRecord per event
                   (most-specific entity dimension). Default: False.
    """

    def __init__(
        self,
        baseline_reader: BaselineReader | None = None,
        *,
        emit_all_dimensions: bool = True,
        primary_only: bool = False,
    ) -> None:
        self._reader: BaselineReader = baseline_reader or BaselineReader()
        self._extractors: list[BaseExtractor] = get_all_extractors()
        self._emit_all = emit_all_dimensions
        self._primary_only = primary_only

        # Locate the special BaselinePresenceExtractor
        self._presence_extractor: BaselinePresenceExtractor | None = None
        for ext in self._extractors:
            if isinstance(ext, BaselinePresenceExtractor):
                self._presence_extractor = ext
                break

        logger.info(
            "feature_pipeline_initialised",
            extractors=[e.group_name for e in self._extractors],
            baseline_ready=self._reader.is_ready,
        )

    @property
    def baseline_ready(self) -> bool:
        """True if a baseline is loaded and available for feature computation."""
        return self._reader.is_ready

    def process_event(self, event: CanonicalEvent) -> list[FeatureRecord]:
        """
        Extract feature vectors for all entity dimensions of one event.

        Returns
        -------
        list[FeatureRecord] — one record per entity dimension extracted.
        Empty if the event is invalid.
        """
        # Resolve entity keys
        keys: dict[str, EntityKey | None] = {
            "user": _make_user_key(event),
            "host": _make_host_key(event),
            "source": _make_source_key(event),
            "user_host": _make_user_host_key(event),
        }

        # Query baselines
        baselines: dict[str, EntityBaseline | None] = {
            dim: (self._reader.get_entity(key) if key is not None else None)
            for dim, key in keys.items()
        }

        # Baseline presence context for BaselinePresenceExtractor
        presence_ctx = {
            f"has_{dim}_baseline": baselines[dim] is not None
            for dim in ("user", "host", "source", "user_host")
        }
        if self._presence_extractor is not None:
            self._presence_extractor.set_context(presence_ctx)

        # Select primary entity (most-specific available)
        primary_key, primary_baseline = self._select_primary(keys, baselines)

        if self._primary_only:
            if primary_key is None:
                logger.debug(
                    "feature_pipeline_cold_start_skip",
                    event_id=getattr(event, "event_id", "unknown"),
                    detail="No baseline for any dimension (cold-start); primary_only=True skips record.",
                )
                return []
            return [self._extract_record(event, primary_key, primary_baseline)]

        # Emit one record per dimension, using that dimension's own baseline.
        # Each entity dimension (user, host, source, user_host) must be
        # assessed against ITS OWN behavioral baseline — not the primary's.
        # Using the wrong baseline would corrupt novelty and deviation features
        # for non-primary dimensions fed into downstream detection.
        records: list[FeatureRecord] = []
        for dim in ("user_host", "user", "host", "source"):
            key = keys[dim]
            if key is None:
                continue
            dim_baseline = baselines[dim]  # dimension-specific baseline (may be None)
            record = self._extract_record(event, key, dim_baseline)
            records.append(record)

        return records

    def process_batch(
        self, events: list[CanonicalEvent]
    ) -> tuple[list[FeatureRecord], FeaturePipelineReport]:
        """
        Process a batch of events and return all feature records + a report.

        Parameters
        ----------
        events : list of CanonicalEvent

        Returns
        -------
        (records, report) tuple
        """
        started = datetime.now(UTC)
        records: list[FeatureRecord] = []
        skipped = 0
        errors = 0
        warnings = 0

        for event in events:
            try:
                event_records = self.process_event(event)
                records.extend(event_records)
                if not event_records:
                    skipped += 1
            except Exception as exc:
                logger.warning(
                    "feature_pipeline_event_error",
                    event_id=getattr(event, "event_id", "unknown"),
                    error=str(exc),
                )
                errors += 1

        for r in records:
            warnings += len(r.feature_vector.extraction_warnings)

        report = FeaturePipelineReport(
            started_at=started,
            completed_at=datetime.now(UTC),
            events_read=len(events),
            events_skipped=skipped,
            feature_records_written=len(records),
            entities_extracted=len({r.entity_key for r in records}),
            baseline_available=self._reader.is_ready,
            baseline_profile_id=self._reader.profile_id,
            extraction_errors=errors,
            extraction_warnings=warnings,
            feature_schema_version=FEATURE_SCHEMA_VERSION,
        )

        logger.info(
            "feature_pipeline_batch_complete",
            events=len(events),
            records=len(records),
            errors=errors,
            duration_s=report.duration_seconds,
        )

        return records, report

    def stream_events(self, event_iter: Iterator[CanonicalEvent]) -> Iterator[FeatureRecord]:
        """
        Generator that processes events one-at-a-time from an iterator.

        Memory-efficient: suitable for large JSONL files.
        Yields FeatureRecords as they are produced.
        """
        for event in event_iter:
            try:
                yield from self.process_event(event)
            except Exception as exc:
                logger.warning(
                    "feature_pipeline_stream_error",
                    event_id=getattr(event, "event_id", "unknown"),
                    error=str(exc),
                )

    # ── Private ─────────────────────────────────────────────────────────────

    def _select_primary(
        self,
        keys: dict[str, EntityKey | None],
        baselines: dict[str, EntityBaseline | None],
    ) -> tuple[EntityKey | None, EntityBaseline | None]:
        """
        Select the most-specific entity dimension that has a baseline.
        Priority: user_host > user > host > source
        """
        for dim in ("user_host", "user", "host", "source"):
            key = keys[dim]
            bl = baselines[dim]
            if key is not None and bl is not None:
                return key, bl
        # No baseline found — use user dimension as primary (cold-start)
        return keys.get("user"), None

    def _extract_record(
        self,
        event: CanonicalEvent,
        entity_key: EntityKey,
        baseline: EntityBaseline | None,
    ) -> FeatureRecord:
        """Run all extractors and assemble a FeatureRecord."""
        all_features: dict[str, float] = {}
        all_warnings: list[str] = []

        for extractor in self._extractors:
            features, warnings = extractor.safe_extract(event, baseline)
            all_features.update(features)
            all_warnings.extend(warnings)

        vector = FeatureVector(
            entity_key=entity_key,
            values=all_features,
            extraction_warnings=all_warnings,
        )

        # F01 — Partial cold-start warning.
        # The NEG-05 scorer guard only rejects records that are BOTH
        # baseline_available=False AND entirely zero. Records with non-zero
        # event-level features (hour_of_day, result_is_failure, etc.) but no
        # baseline will reach the Isolation Forest scored against a model that
        # may have been trained with different feature distributions.
        # This log makes those records visible so operators know scoring is
        # occurring without baseline context.
        if baseline is None:
            arr = vector.to_array()
            if any(v != 0.0 for v in arr):
                non_zero_names = [name for name, val in all_features.items() if val != 0.0]
                logger.warning(
                    "feature_pipeline_cold_start_partial_vector",
                    event_id=event.event_id,
                    entity_key=repr(entity_key),
                    non_zero_feature_count=len(non_zero_names),
                    non_zero_features=non_zero_names[:10],  # cap for log sanity
                    detail=(
                        "baseline_available=False but feature vector is not all-zero. "
                        "Event-level features are populated; baseline features are 0.0. "
                        "This record will reach the scorer without baseline context."
                    ),
                )

        return FeatureRecord(
            event_id=event.event_id,
            event_type=event.event_type,
            event_source=event.source,
            event_timestamp=event.timestamp,
            event_host=str(event.host),
            event_user=str(event.user),
            entity_key=entity_key,
            baseline_available=baseline is not None,
            feature_vector=vector,
        )
