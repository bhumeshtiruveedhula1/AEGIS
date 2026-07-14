"""
backend.normalization.collector — Telemetry Collector
=====================================================
Module 1.3 — Unified Log Collection & Normalization

The TelemetryCollector discovers telemetry sources via the
DigitalTwinRegistry and streams raw records from JSONL files.

Responsibilities
----------------
1. Ask the registry for all active telemetry sources.
2. For each source, open its JSONL log file.
3. Stream records line-by-line (generator — never loads full file).
4. Deserialise each line to a dict.
5. Attach source metadata (source name, file path, line number).
6. Yield RawRecord objects to the pipeline.
7. Handle I/O errors per-source (one broken source never stops others).

Design Principles
-----------------
- Generator-based: `stream_records()` yields one RawRecord at a time.
  Memory footprint is O(1) regardless of file size.
- Error isolation: SourceError → log and skip source; continue others.
- ParseError    → log and skip line; continue next line.
- Line ordering is preserved (file order = yield order).
- The collector performs NO interpretation of record content.

Configuration
-------------
NORM_MAX_LINES_PER_SOURCE controls maximum lines read per source
in a single pipeline run.  0 = unlimited.  Default: 0.

Integration
-----------
Used by NormalizationPipeline:

    collector = TelemetryCollector(registry)
    for raw_record in collector.stream_records():
        canonical = pipeline.process(raw_record)
"""

from __future__ import annotations

import json
from collections.abc import Generator
from pathlib import Path
from typing import TYPE_CHECKING

import structlog

from backend.normalization.exceptions import SourceError
from backend.normalization.models import RawRecord

if TYPE_CHECKING:
    from backend.digital_twin.registry import DigitalTwinRegistry

logger = structlog.get_logger(__name__)


class TelemetryCollector:
    """
    Discovers and streams raw telemetry records from Digital Twin log files.

    Parameters
    ----------
    registry:           DigitalTwinRegistry instance from Module 1.2.
    max_lines_per_source: Maximum lines to read per source (0 = unlimited).

    Usage
    -----
        registry = get_registry()
        collector = TelemetryCollector(registry)

        for raw_record in collector.stream_records():
            # process each record
            ...

    Error Handling
    --------------
    - Missing log file    → SourceError logged; source skipped.
    - Empty file          → source skipped silently.
    - Malformed JSON line → ParseError logged; line skipped.
    - Non-dict JSON line  → ParseError logged; line skipped.
    """

    def __init__(
        self,
        registry: DigitalTwinRegistry,
        *,
        max_lines_per_source: int = 0,
    ) -> None:
        self._registry = registry
        self._max_lines = max_lines_per_source

    def stream_records(self) -> Generator[RawRecord, None, None]:
        """
        Yield RawRecord objects from all active telemetry sources.

        Yields records in source-discovery order, preserving within-source
        file order.

        Generator protocol:
            - Each iteration yields exactly one RawRecord.
            - Caller may send() nothing and return() at any time.
            - All resources are released on generator exhaustion or close().
        """
        sources = self._registry.list_telemetry_sources()
        if not sources:
            logger.warning("telemetry_no_sources_found")
            return

        for source in sources:
            source_name = str(source.container_role)  # TelemetrySource field is container_role
            log_path = (
                Path(source.host_log_path)
                if isinstance(source.host_log_path, str)
                else source.host_log_path
            )

            logger.info(
                "telemetry_collector_reading_source",
                source=source_name,
                path=str(log_path),
            )

            yield from self._stream_source(source_name, log_path)

    def _stream_source(
        self,
        source_name: str,
        log_path: Path,
    ) -> Generator[RawRecord, None, None]:
        """
        Stream RawRecords from a single JSONL file.

        Parameters
        ----------
        source_name:  Canonical source identifier string.
        log_path:     Filesystem path to the JSONL log file.
        """
        path_str = str(log_path)

        # ── Validate file exists ──────────────────────────────────────────
        if not log_path.exists():
            error = SourceError(
                f"Log file not found for source '{source_name}': {path_str}",
                source=source_name,
                path=path_str,
            )
            logger.warning(
                "telemetry_source_file_missing",
                source=source_name,
                path=path_str,
            )
            # Yield nothing — caller continues to next source
            return

        if not log_path.is_file():
            logger.warning(
                "telemetry_source_path_not_file",
                source=source_name,
                path=path_str,
            )
            return

        # ── Stream line by line ───────────────────────────────────────────
        lines_read = 0
        try:
            with log_path.open(encoding="utf-8") as fh:
                for line_number, line in enumerate(fh, start=1):
                    if self._max_lines > 0 and lines_read >= self._max_lines:
                        logger.info(
                            "telemetry_source_max_lines_reached",
                            source=source_name,
                            max_lines=self._max_lines,
                        )
                        break

                    raw_line = line.rstrip("\n")
                    if not raw_line:
                        continue  # Skip blank lines silently

                    raw_dict = self._parse_line(raw_line, line_number, source_name, path_str)
                    if raw_dict is None:
                        continue  # Parse error already logged

                    lines_read += 1
                    yield RawRecord(
                        source=source_name,
                        source_file=path_str,
                        line_number=line_number,
                        raw_dict=raw_dict,
                        raw_line=raw_line,
                    )

        except OSError as exc:
            logger.error(
                "telemetry_source_read_error",
                source=source_name,
                path=path_str,
                error=str(exc),
            )

        logger.info(
            "telemetry_source_complete",
            source=source_name,
            lines_read=lines_read,
        )

    def _parse_line(
        self,
        line: str,
        line_number: int,
        source_name: str,
        path_str: str,
    ) -> dict | None:
        """
        Parse a raw JSON line into a dict.

        Returns None on any parsing failure (error already logged).
        Never raises — all exceptions are caught and logged.
        """
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError as exc:
            logger.warning(
                "telemetry_line_json_error",
                source=source_name,
                path=path_str,
                line_number=line_number,
                error=str(exc),
                raw_line=line[:200],  # Truncate for log safety
            )
            return None

        if not isinstance(parsed, dict):
            logger.warning(
                "telemetry_line_not_dict",
                source=source_name,
                path=path_str,
                line_number=line_number,
                actual_type=type(parsed).__name__,
            )
            return None

        return parsed

    def collect_from_file(
        self,
        source_name: str,
        file_path: Path,
    ) -> Generator[RawRecord, None, None]:
        """
        Stream RawRecords from an explicit file path.

        Used in tests and one-off ingestion scenarios where the registry
        is not involved.  Same error handling as stream_records().

        Parameters
        ----------
        source_name:  Source identifier to embed in each RawRecord.
        file_path:    Path to the JSONL file to read.
        """
        yield from self._stream_source(source_name, file_path)
