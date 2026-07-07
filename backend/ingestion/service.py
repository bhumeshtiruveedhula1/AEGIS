"""
backend.ingestion.service — Ingestion Service
=============================================
Module 1.3 — Unified Log Collection & Normalization

The IngestionService is the top-level entry point for the telemetry
pipeline.  It wires together:
  - DigitalTwinRegistry  (from Module 1.2)
  - NormalizationPipeline (from Module 1.3)
  - Configuration        (backend.core.config)

This is the class that application startup code and API routes should
call.  It provides both sync run() and async run_async() interfaces.

Architecture Role
-----------------
The ingestion module owns the pipeline TRIGGER, not the pipeline LOGIC.
Normalization logic lives in backend.normalization.
The ingestion module is intentionally thin — it only orchestrates.

Usage
-----
    from backend.ingestion.service import IngestionService

    service = IngestionService()
    report = service.run()

    # In an async context (FastAPI background task):
    report = await service.run_async()

Configuration
-------------
Reads from backend.core.config.Settings:
  - data_dir:                     Root data directory
  - feature_normalization_enabled: Must be True to run
  - feature_ingestion_enabled:    Must be True to run
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import TYPE_CHECKING

import structlog

from backend.core.config import get_settings
from backend.digital_twin.registry import get_registry
from backend.normalization.pipeline import NormalizationPipeline
from backend.normalization.models import ParseReport

if TYPE_CHECKING:
    pass

logger = structlog.get_logger(__name__)


class IngestionService:
    """
    Top-level orchestrator for the telemetry ingestion pipeline.

    Responsibilities
    ----------------
    1. Load configuration.
    2. Obtain the DigitalTwinRegistry singleton.
    3. Build and run the NormalizationPipeline.
    4. Return the ParseReport.

    Parameters
    ----------
    output_dir:             Override for normalized output directory.
                            Defaults to settings.data_dir / "normalized".
    max_lines_per_source:   Passed to TelemetryCollector; 0 = unlimited.
    """

    def __init__(
        self,
        *,
        output_dir: Path | None = None,
        max_lines_per_source: int = 0,
    ) -> None:
        self._settings = get_settings()
        self._output_dir = output_dir or (
            self._settings.data_dir / "normalized"
        )
        self._max_lines = max_lines_per_source

    def run(self) -> ParseReport:
        """
        Execute a full ingestion + normalization run synchronously.

        Returns
        -------
        ParseReport summarizing the completed run.

        Raises
        ------
        RuntimeError if the feature flags are disabled.
        """
        self._check_feature_flags()

        registry = get_registry()
        pipeline = NormalizationPipeline(
            registry,
            output_dir=self._output_dir,
            max_lines_per_source=self._max_lines,
        )

        logger.info(
            "ingestion_service_run_started",
            output_dir=str(self._output_dir),
            max_lines=self._max_lines,
        )

        report = pipeline.run()

        logger.info(
            "ingestion_service_run_completed",
            total_normalized=report.total_events_normalized,
            total_errors=report.total_parse_errors,
            duration_s=report.duration_seconds,
        )

        return report

    async def run_async(self) -> ParseReport:
        """
        Execute the ingestion run in a thread pool (non-blocking).

        The pipeline is CPU+I/O bound with synchronous file I/O.
        This method runs it in asyncio's default thread executor so
        it does not block the event loop.

        Returns
        -------
        ParseReport
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.run)

    # ── Private ─────────────────────────────────────────────────────────────

    def _check_feature_flags(self) -> None:
        """Raise RuntimeError if required feature flags are not enabled."""
        if not self._settings.feature_ingestion_enabled:
            msg = (
                "IngestionService.run() called but FEATURE_INGESTION_ENABLED=false. "
                "Set FEATURE_INGESTION_ENABLED=true in your .env to activate."
            )
            raise RuntimeError(msg)
        if not self._settings.feature_normalization_enabled:
            msg = (
                "IngestionService.run() called but FEATURE_NORMALIZATION_ENABLED=false. "
                "Set FEATURE_NORMALIZATION_ENABLED=true in your .env to activate."
            )
            raise RuntimeError(msg)
