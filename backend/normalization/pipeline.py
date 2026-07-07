"""
backend.normalization.pipeline — Normalization Pipeline
=======================================================
Module 1.3 — Unified Log Collection & Normalization

The NormalizationPipeline is the central orchestrator.  It coordinates:
  1. TelemetryCollector  (source discovery + JSONL streaming)
  2. Parser dispatch     (source → parser → CanonicalEvent)
  3. NormalizedEventWriter (output + dead-letter writing)
  4. Statistics tracking  (ParseStats + ParseReport)

Data Flow
---------
  DigitalTwinRegistry
      │
      ▼ (TelemetryCollector)
  RawRecord stream
      │
      ▼ (parser dispatch via PARSER_REGISTRY)
  CanonicalEvent  ─── success ──▶  NormalizedEventWriter
                  └── failure ──▶  dead-letter writer + ParseStats.parse_errors++

Configuration
-------------
All tunable parameters come from NormalizationSettings (backend.core.config).
The pipeline is stateless between runs — create a new instance per run
or call run() repeatedly (stats reset on each call).

Thread Safety
-------------
The pipeline is NOT thread-safe.  Run one pipeline instance per process.
Future parallel ingestion: shard by source, one pipeline per source.

Usage
-----
    from backend.digital_twin.registry import get_registry
    from backend.normalization.pipeline import NormalizationPipeline

    registry = get_registry()
    pipeline = NormalizationPipeline(registry)
    report = pipeline.run()

    print(f"Normalized: {report.total_events_normalized}")
    print(f"Errors:     {report.total_parse_errors}")
"""

from __future__ import annotations

import uuid
from collections.abc import Generator, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog

from backend.normalization.collector import TelemetryCollector
from backend.normalization.exceptions import NormalizationError, ParseError, SourceError
from backend.normalization.models import (
    CanonicalEvent,
    ParseReport,
    ParseStats,
    RawRecord,
)
from backend.normalization.parsers import get_parser
from backend.normalization.writer import NormalizedEventWriter

if TYPE_CHECKING:
    from backend.digital_twin.registry import DigitalTwinRegistry

logger = structlog.get_logger(__name__)


class NormalizationPipeline:
    """
    Orchestrates the complete telemetry normalization pipeline.

    Parameters
    ----------
    registry:           DigitalTwinRegistry from Module 1.2.
    output_dir:         Directory to write normalized JSONL and error files.
                        Defaults to data/normalized/.
    max_lines_per_source: Passed to TelemetryCollector; 0 = unlimited.

    Attributes
    ----------
    After run() completes, these attributes are populated:
    _last_report:  ParseReport for the most recent run.
    """

    def __init__(
        self,
        registry: "DigitalTwinRegistry",
        *,
        output_dir: Path | None = None,
        max_lines_per_source: int = 0,
    ) -> None:
        self._registry = registry
        self._output_dir = output_dir or Path("./data/normalized")
        self._max_lines = max_lines_per_source
        self._last_report: ParseReport | None = None

        # Ensure output directory exists
        self._output_dir.mkdir(parents=True, exist_ok=True)

    # ── Public API ──────────────────────────────────────────────────────────

    def run(self) -> ParseReport:
        """
        Execute a full normalization run across all telemetry sources.

        Reads all available JSONL telemetry, normalizes each record,
        writes output to data/normalized/normalized_events.jsonl,
        and writes failed records to data/normalized/error_events.jsonl.

        Returns
        -------
        ParseReport summarizing the run.

        Raises
        ------
        Does NOT raise.  All errors are caught, logged, and counted.
        The report's per_source_stats will reflect all failures.
        """
        run_id = str(uuid.uuid4())
        started_at = datetime.now(UTC)

        output_file = self._output_dir / "normalized_events.jsonl"
        error_file = self._output_dir / "error_events.jsonl"

        logger.info(
            "normalization_pipeline_started",
            run_id=run_id,
            output_file=str(output_file),
            error_file=str(error_file),
        )

        report = ParseReport(
            run_id=run_id,
            started_at=started_at,
            output_file=str(output_file),
            error_file=str(error_file),
        )

        # Per-source stats tracker
        stats_by_source: dict[str, ParseStats] = {}

        # Build collector and writers
        collector = TelemetryCollector(
            self._registry,
            max_lines_per_source=self._max_lines,
        )
        event_writer = NormalizedEventWriter(output_file)
        error_writer = NormalizedEventWriter(error_file)

        with event_writer, error_writer:
            for raw_record in collector.stream_records():
                source = raw_record.source
                stats = stats_by_source.setdefault(
                    source,
                    ParseStats(source=source),
                )
                stats.total_lines_read += 1  # type: ignore[attr-defined]

                canonical = self._normalize_record(raw_record, stats, error_writer)
                if canonical is not None:
                    self._update_timestamp_range(stats, canonical.timestamp)
                    event_writer.write(canonical)
                    stats.events_normalized += 1  # type: ignore[attr-defined]

        # Finalise report
        report.sources_processed = sorted(stats_by_source.keys())
        report.per_source_stats = list(stats_by_source.values())
        report.total_events_normalized = sum(
            s.events_normalized for s in report.per_source_stats
        )
        report.total_parse_errors = sum(
            s.parse_errors + s.validation_errors for s in report.per_source_stats
        )
        object.__setattr__(report, "completed_at", datetime.now(UTC))

        self._last_report = report
        self._write_report(report)

        logger.info(
            "normalization_pipeline_completed",
            run_id=run_id,
            total_normalized=report.total_events_normalized,
            total_errors=report.total_parse_errors,
            duration_s=report.duration_seconds,
        )

        return report

    def stream_normalized(self) -> Generator[CanonicalEvent, None, None]:
        """
        Stream CanonicalEvent objects without writing to disk.

        Useful for in-process consumers (e.g., tests, real-time processing).

        Yields
        ------
        CanonicalEvent for each successfully normalized record.
        Errors are logged but not yielded.
        """
        collector = TelemetryCollector(
            self._registry,
            max_lines_per_source=self._max_lines,
        )
        dummy_stats = ParseStats(source="streaming")
        for raw_record in collector.stream_records():
            canonical = self._normalize_record(
                raw_record, dummy_stats, writer=None
            )
            if canonical is not None:
                yield canonical

    def normalize_record(self, raw_record: RawRecord) -> CanonicalEvent | None:
        """
        Normalize a single RawRecord.  Public interface for testing.

        Returns None if normalization fails.
        """
        dummy_stats = ParseStats(source=raw_record.source)
        return self._normalize_record(raw_record, dummy_stats, writer=None)

    @property
    def last_report(self) -> ParseReport | None:
        """ParseReport from the most recent run(), or None if never run."""
        return self._last_report

    # ── Private implementation ──────────────────────────────────────────────

    def _normalize_record(
        self,
        raw_record: RawRecord,
        stats: ParseStats,
        writer: NormalizedEventWriter | None,
    ) -> CanonicalEvent | None:
        """
        Dispatch a RawRecord to the correct parser and return CanonicalEvent.

        On success: returns CanonicalEvent.
        On failure: logs, increments error counter, optionally writes to dead-letter.
        Returns None on any failure.
        """
        try:
            parser = get_parser(raw_record.source)
        except SourceError as exc:
            logger.warning(
                "normalization_no_parser",
                source=raw_record.source,
                line_number=raw_record.line_number,
                file=raw_record.source_file,
                error=str(exc),
            )
            stats.parse_errors += 1  # type: ignore[attr-defined]
            self._write_error(writer, raw_record, str(exc))
            return None

        try:
            canonical = parser.parse(raw_record.raw_dict)
        except NormalizationError as exc:
            logger.warning(
                "normalization_parse_error",
                source=raw_record.source,
                line_number=raw_record.line_number,
                file=raw_record.source_file,
                error=str(exc),
                error_type=type(exc).__name__,
            )
            stats.parse_errors += 1  # type: ignore[attr-defined]
            self._write_error(writer, raw_record, str(exc))
            return None

        except Exception as exc:  # noqa: BLE001
            # Unexpected errors — log with full context, count as parse error
            logger.error(
                "normalization_unexpected_error",
                source=raw_record.source,
                line_number=raw_record.line_number,
                file=raw_record.source_file,
                error=str(exc),
                exc_info=True,
            )
            stats.parse_errors += 1  # type: ignore[attr-defined]
            self._write_error(writer, raw_record, f"Unexpected: {exc}")
            return None

        # Attach source file path to canonical event
        object.__setattr__(canonical, "source_file", raw_record.source_file)

        # Count warnings
        if canonical.parse_warnings:
            stats.warnings_emitted += len(canonical.parse_warnings)  # type: ignore[attr-defined]
            logger.debug(
                "normalization_warnings",
                source=raw_record.source,
                line_number=raw_record.line_number,
                warnings=canonical.parse_warnings,
            )

        return canonical

    @staticmethod
    def _update_timestamp_range(
        stats: ParseStats,
        timestamp: datetime,
    ) -> None:
        """Update first/last event timestamp in stats."""
        if stats.first_event_timestamp is None or timestamp < stats.first_event_timestamp:
            object.__setattr__(stats, "first_event_timestamp", timestamp)
        if stats.last_event_timestamp is None or timestamp > stats.last_event_timestamp:
            object.__setattr__(stats, "last_event_timestamp", timestamp)

    @staticmethod
    def _write_error(
        writer: NormalizedEventWriter | None,
        raw_record: RawRecord,
        reason: str,
    ) -> None:
        """Write a dead-letter record. No-op if writer is None."""
        if writer is None:
            return
        dead_letter = {
            "error_reason": reason,
            "source": raw_record.source,
            "source_file": raw_record.source_file,
            "line_number": raw_record.line_number,
            "raw_line": raw_record.raw_line,
            "received_at": raw_record.received_at.isoformat(),
        }
        writer.write_raw(dead_letter)

    def _write_report(self, report: ParseReport) -> None:
        """Persist the ParseReport as JSON to the output directory."""
        import json  # noqa: PLC0415
        report_path = self._output_dir / "pipeline_report.json"
        try:
            report_path.write_text(
                json.dumps(
                    report.model_dump(mode="json"),
                    indent=2,
                    default=str,
                ),
                encoding="utf-8",
            )
        except OSError as exc:
            logger.warning("normalization_report_write_failed", error=str(exc))
