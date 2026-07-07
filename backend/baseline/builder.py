"""
backend.baseline.builder — Baseline Builder
==========================================
Module 2.1 — Baseline Generator

BaselineBuilder orchestrates the full baseline computation pipeline:
  1. Read normalized events (NormalizedEventReader)
  2. Group by entity dimension (EventAggregator)
  3. Compute per-entity statistics (compute_entity_baseline)
  4. Assemble BaselineProfile

The builder DOES NOT persist results — that is the BaselineStore's job.
This separation ensures the builder can be used in tests and in-process
pipelines without file I/O.

Usage
-----
    # From normalized JSONL file (production)
    builder = BaselineBuilder()
    profile = builder.build_from_file()

    # From an in-memory list (tests, scheduled re-build)
    builder = BaselineBuilder()
    profile = builder.build_from_events(events)

    # Inspect the build report
    report = builder.last_report
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

import structlog

from backend.baseline.aggregator import EventAggregator
from backend.baseline.exceptions import BaselineComputeError
from backend.baseline.models import (
    BaselineBuildReport,
    BaselineProfile,
    EntityKey,
)
from backend.baseline.reader import NormalizedEventReader
from backend.baseline.statistics import compute_entity_baseline

if TYPE_CHECKING:
    from backend.normalization.models import CanonicalEvent

logger = structlog.get_logger(__name__)


class BaselineBuilder:
    """
    Orchestrates the full baseline computation pipeline.

    Parameters
    ----------
    input_file:              Path to normalized_events.jsonl.
                             Defaults to data/normalized/normalized_events.jsonl.
    dimensions:              Entity dimension set to compute.
                             Defaults to all four dimensions.
    max_categorical_values:  Max unique values in frequency distributions.
    """

    def __init__(
        self,
        input_file: Path | None = None,
        *,
        dimensions: set[str] | None = None,
        max_categorical_values: int = 100,
    ) -> None:
        self._input_file = input_file
        self._dimensions = dimensions
        self._max_cat = max_categorical_values
        self._last_report: BaselineBuildReport | None = None

    @property
    def last_report(self) -> BaselineBuildReport | None:
        """BuildReport from the most recent build() call."""
        return self._last_report

    # ── Public API ──────────────────────────────────────────────────────────

    def build_from_file(self) -> BaselineProfile:
        """
        Execute the full baseline pipeline from the normalized JSONL file.

        Reads from data/normalized/normalized_events.jsonl (or the configured
        input_file), groups, computes statistics, and returns a BaselineProfile.

        Returns
        -------
        BaselineProfile with all entity baselines.

        Raises
        ------
        BaselineInputError if the normalized events file is missing or empty.
        """
        reader = NormalizedEventReader(input_file=self._input_file)
        logger.info(
            "baseline_builder_reading_file",
            file=str(reader.input_file),
        )
        events = reader.load_all()
        logger.info(
            "baseline_builder_events_loaded",
            count=len(events),
        )
        profile = self._build_profile(events, source_file=str(reader.input_file))
        if self._last_report is not None:
            object.__setattr__(self._last_report, "input_file", str(reader.input_file))
        return profile

    def build_from_events(
        self,
        events: list["CanonicalEvent"],
    ) -> BaselineProfile:
        """
        Execute the baseline pipeline from an in-memory event list.

        Used in tests, scheduled re-builds, and the BaselineUpdater.
        No file I/O — pure computation.

        Parameters
        ----------
        events:  List of CanonicalEvent objects.

        Returns
        -------
        BaselineProfile.
        """
        return self._build_profile(events, source_file=None)

    # ── Private implementation ──────────────────────────────────────────────

    def _build_profile(
        self,
        events: list["CanonicalEvent"],
        source_file: str | None,
    ) -> BaselineProfile:
        """
        Core pipeline: aggregate → compute per entity → assemble profile.

        Error isolation: a computation failure on one entity is logged and
        skipped; other entities continue.  The profile will have a lower
        entity count than expected, which is surfaced in the build report.
        """
        profile_id = str(uuid.uuid4())
        started_at = datetime.now(UTC)

        report = BaselineBuildReport(
            profile_id=profile_id,
            started_at=started_at,
            input_file=source_file,
            total_events_read=len(events),
        )

        logger.info(
            "baseline_builder_start",
            profile_id=profile_id,
            event_count=len(events),
        )

        # ── Step 1: Aggregate events by entity dimension ──────────────────
        aggregator = EventAggregator(dimensions=self._dimensions)
        groups = aggregator.aggregate(events)

        # ── Step 2: Compute per-entity baselines ──────────────────────────
        entity_baselines: dict[str, object] = {}
        compute_errors = 0

        for entity_key, entity_events in groups.items():
            try:
                baseline = compute_entity_baseline(
                    entity_key,
                    entity_events,
                    max_categorical_values=self._max_cat,
                )
                entity_baselines[entity_key.storage_key] = baseline

            except Exception as exc:  # noqa: BLE001
                compute_errors += 1
                logger.error(
                    "baseline_builder_entity_compute_error",
                    entity=repr(entity_key),
                    error=str(exc),
                    exc_info=True,
                )

        # ── Step 3: Count entities by type ────────────────────────────────
        entity_type_counts: dict[str, int] = {}
        for storage_key in entity_baselines:
            parts = storage_key.split("__", 1)
            if parts:
                etype = parts[0]
                entity_type_counts[etype] = entity_type_counts.get(etype, 0) + 1

        # ── Step 4: Assemble profile ──────────────────────────────────────
        profile = BaselineProfile(
            profile_id=profile_id,
            source_file=source_file,
            total_events_processed=len(events),
            entities=entity_baselines,  # type: ignore[arg-type]
            entity_type_counts=entity_type_counts,
        )

        completed_at = datetime.now(UTC)

        # Finalise report
        object.__setattr__(report, "completed_at", completed_at)
        object.__setattr__(report, "total_entities_computed", len(entity_baselines))
        object.__setattr__(report, "entities_by_type", entity_type_counts)
        object.__setattr__(report, "compute_errors", compute_errors)
        self._last_report = report

        logger.info(
            "baseline_builder_complete",
            profile_id=profile_id,
            total_entities=len(entity_baselines),
            compute_errors=compute_errors,
            duration_s=(completed_at - started_at).total_seconds(),
        )

        return profile
