"""
backend.baseline.service — Baseline Service
==========================================
Module 2.1 — Baseline Generator

BaselineService is the thin application-level orchestrator.
It wires together BaselineBuilder, BaselineStore, and BaselineUpdater
into callable actions for:
  - Scheduled full baseline builds
  - Incremental updates from new telemetry
  - Baseline status queries

This is the only entry point that application code (API handlers,
scheduled jobs, CLI scripts) should call.  Unit tests should use
BaselineBuilder and BaselineStore directly.

Usage
-----
    # Full build from normalized output
    service = BaselineService()
    report = service.build_from_normalized_output()

    # Incremental update with new events
    report = service.update_from_new_events(events, entity_key)

    # Query status
    status = service.get_status()
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog

from backend.baseline.builder import BaselineBuilder
from backend.baseline.exceptions import BaselineNotFoundError
from backend.baseline.models import (
    BaselineBuildReport,
    BaselineProfile,
    EntityKey,
)
from backend.baseline.storage import BaselineStore
from backend.baseline.updater import BaselineUpdater

if TYPE_CHECKING:
    from backend.normalization.models import CanonicalEvent

logger = structlog.get_logger(__name__)


class BaselineService:
    """
    Application-level orchestrator for baseline operations.

    Wires builder → store → updater.  Does NOT expose internal
    baseline models directly — callers receive reports and high-level
    status objects.

    Parameters
    ----------
    baseline_dir:    Root directory for baseline artefacts.
    input_file:      Path to normalized_events.jsonl.
    dimensions:      Entity dimensions to compute.
    """

    def __init__(
        self,
        baseline_dir: Path | None = None,
        input_file: Path | None = None,
        dimensions: set[str] | None = None,
        max_categorical_values: int = 100,
    ) -> None:
        self._store = BaselineStore(baseline_dir=baseline_dir)
        self._input_file = input_file
        self._dimensions = dimensions
        self._max_cat = max_categorical_values
        self._updater = BaselineUpdater(max_categorical_values=max_categorical_values)

    # ── Full build ──────────────────────────────────────────────────────────

    def build_from_normalized_output(self) -> BaselineBuildReport:
        """
        Execute a full baseline build from the Module 1.3 output.

        Reads from data/normalized/normalized_events.jsonl,
        computes all entity baselines, persists the profile and
        all entity files.

        Returns
        -------
        BaselineBuildReport with build statistics.

        Raises
        ------
        BaselineInputError if the normalized events file is missing.
        """
        logger.info("baseline_service_build_start")

        builder = BaselineBuilder(
            input_file=self._input_file,
            dimensions=self._dimensions,
            max_categorical_values=self._max_cat,
        )
        profile = builder.build_from_file()

        # Persist full profile + per-entity files
        saved_path = self._store.save(profile)
        entity_count = self._store.save_profile_entities(profile)

        report = builder.last_report
        if report is not None:
            object.__setattr__(
                report, "profile_saved_to", str(saved_path)
            )

        logger.info(
            "baseline_service_build_complete",
            profile_id=profile.profile_id,
            entities=entity_count,
            saved_to=str(saved_path),
        )

        return report or BaselineBuildReport(
            profile_id=profile.profile_id,
            total_events_read=profile.total_events_processed,
            total_entities_computed=profile.entity_count,
        )

    # ── Incremental update ──────────────────────────────────────────────────

    def update_from_new_events(
        self,
        new_events: list["CanonicalEvent"],
        entity_key: EntityKey,
    ) -> bool:
        """
        Incrementally update a specific entity's baseline with new events.

        Loads the existing EntityBaseline, merges new observations,
        and saves the updated entity file.

        Parameters
        ----------
        new_events:   New CanonicalEvent observations for this entity.
        entity_key:   The entity to update.

        Returns
        -------
        True if update succeeded. False if entity has no existing baseline
        (callers should run a full build first in that case).
        """
        if not new_events:
            return True

        if not self._store.entity_exists(entity_key):
            logger.warning(
                "baseline_service_entity_not_found_for_update",
                entity=repr(entity_key),
            )
            return False

        try:
            existing = self._store.load_entity(entity_key)
            updated = self._updater.update(existing, new_events)
            self._store.save_entity(entity_key, updated)
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "baseline_service_update_failed",
                entity=repr(entity_key),
                error=str(exc),
            )
            return False

        logger.info(
            "baseline_service_entity_updated",
            entity=repr(entity_key),
            new_events=len(new_events),
            total_observations=updated.observation_count,
        )
        return True

    # ── Status queries ──────────────────────────────────────────────────────

    def get_status(self) -> dict[str, Any]:
        """
        Return a status dict describing the current baseline state.

        Safe to call at any time — returns informative defaults when
        no baseline exists yet.

        Returns
        -------
        dict with keys:
          is_ready:           bool — True if a baseline profile exists.
          latest_profile_id:  str | None
          entity_count:       int
          built_at:           str | None (ISO 8601)
          baseline_version:   str | None
        """
        manifest = self._store.load_manifest()
        if manifest.latest_profile_id is None:
            return {
                "is_ready": False,
                "latest_profile_id": None,
                "entity_count": 0,
                "built_at": None,
                "baseline_version": None,
            }

        # Find the latest entry in the manifest
        if manifest.profiles:
            latest = manifest.profiles[0]
            return {
                "is_ready": True,
                "latest_profile_id": latest.profile_id,
                "entity_count": latest.entity_count,
                "built_at": latest.built_at.isoformat(),
                "baseline_version": latest.baseline_version,
            }

        return {
            "is_ready": True,
            "latest_profile_id": manifest.latest_profile_id,
            "entity_count": 0,
            "built_at": None,
            "baseline_version": None,
        }

    def entity_baseline_exists(self, entity_key: EntityKey) -> bool:
        """Return True if a persisted EntityBaseline exists for this entity."""
        return self._store.entity_exists(entity_key)
