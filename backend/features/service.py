"""
backend.features.service — Feature Service
==========================================
Module 2.2 — Behavioral Feature Engine

FeatureService is the top-level application entry point for the feature
extraction pipeline. It wires together:
  - BaselineReader (from Module 2.1)
  - NormalizedEventReader (from Module 2.1)
  - FeaturePipeline
  - FeatureVectorWriter

Usage
-----
    from backend.features.service import FeatureService

    service = FeatureService()
    report = service.extract_from_normalized_output()
    # Features written to data/features/features_<run_id>.jsonl

Architecture
-----------
FeatureService owns the pipeline TRIGGER, not the pipeline LOGIC.
All extraction logic lives in the extractor classes and FeaturePipeline.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import structlog

from backend.baseline.reader import NormalizedEventReader
from backend.baseline.reader_api import BaselineReader
from backend.core.config import get_settings
from backend.features.exceptions import FeaturePipelineError
from backend.features.models import FeaturePipelineReport, FEATURE_SCHEMA_VERSION
from backend.features.pipeline import FeaturePipeline
from backend.features.writer import FeatureVectorWriter

logger = structlog.get_logger(__name__)


class FeatureService:
    """
    Application-level orchestrator for the behavioral feature extraction pipeline.

    Parameters
    ----------
    input_file       : Path to the normalized JSONL output from Module 1.3.
                       Defaults to settings.data_dir / "normalized" / "normalized_events.jsonl".
    output_dir       : Directory for feature output files.
                       Defaults to settings.data_dir / "features".
    baseline_dir     : Override baseline storage directory.
                       Defaults to the BaselineReader default.
    primary_only     : If True, emit only the primary entity dimension per event.
    """

    def __init__(
        self,
        *,
        input_file: Path | None = None,
        output_dir: Path | None = None,
        baseline_dir: Path | None = None,
        primary_only: bool = False,
    ) -> None:
        self._settings = get_settings()
        self._input_file = input_file or (
            self._settings.data_dir / "normalized" / "normalized_events.jsonl"
        )
        self._output_dir = output_dir or (self._settings.data_dir / "features")
        self._reader = BaselineReader(baseline_dir=baseline_dir)
        self._primary_only = primary_only

    def extract_from_normalized_output(self) -> FeaturePipelineReport:
        """
        Run the full feature extraction pipeline over the normalized event file.

        Returns
        -------
        FeaturePipelineReport — summary of the extraction run.

        Raises
        ------
        FeaturePipelineError if the input file is missing or extraction fails.
        """
        logger.info(
            "feature_service_start",
            input_file=str(self._input_file),
            baseline_ready=self._reader.is_ready,
        )

        # Load events
        event_reader = NormalizedEventReader(input_file=self._input_file)
        try:
            events = event_reader.load_all()
        except Exception as exc:
            msg = f"Failed to load normalized events: {exc}"
            raise FeaturePipelineError(
                msg, context={"input_file": str(self._input_file)}
            ) from exc

        if not events:
            msg = f"No events found in {self._input_file}"
            raise FeaturePipelineError(
                msg, context={"input_file": str(self._input_file)}
            )

        logger.info("feature_service_events_loaded", count=len(events))

        # Run pipeline
        pipeline = FeaturePipeline(
            baseline_reader=self._reader,
            emit_all_dimensions=not self._primary_only,
            primary_only=self._primary_only,
        )

        from backend.shared.utils.id_utils import generate_id
        run_id = generate_id()

        with FeatureVectorWriter(output_dir=self._output_dir, run_id=run_id) as writer:
            records, pipeline_report = pipeline.process_batch(events)
            writer.write_batch(records)

            # Enrich report with I/O paths
            final_report = FeaturePipelineReport(
                run_id=run_id,
                started_at=pipeline_report.started_at,
                completed_at=datetime.now(UTC),
                events_read=pipeline_report.events_read,
                events_skipped=pipeline_report.events_skipped,
                feature_records_written=pipeline_report.feature_records_written,
                entities_extracted=pipeline_report.entities_extracted,
                baseline_available=pipeline_report.baseline_available,
                baseline_profile_id=pipeline_report.baseline_profile_id,
                extraction_errors=pipeline_report.extraction_errors,
                extraction_warnings=pipeline_report.extraction_warnings,
                feature_schema_version=FEATURE_SCHEMA_VERSION,
                output_file=str(writer.output_path),
            )
            writer.write_report(final_report)

        logger.info(
            "feature_service_complete",
            records=final_report.feature_records_written,
            duration_s=final_report.duration_seconds,
            output=str(final_report.output_file),
        )

        return final_report

    def get_status(self) -> dict:
        """
        Return a dict describing the current Feature Engine status.
        Suitable for health endpoints and monitoring.
        """
        return {
            "baseline_ready": self._reader.is_ready,
            "baseline_profile_id": self._reader.profile_id,
            "input_file": str(self._input_file),
            "output_dir": str(self._output_dir),
            "feature_schema_version": FEATURE_SCHEMA_VERSION,
        }
