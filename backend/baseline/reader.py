"""
backend.baseline.reader — Normalized Event Reader
=================================================
Module 2.1 — Baseline Generator

Reads CanonicalEvent records from the normalized JSONL output produced
by Module 1.3.  Produces a stream of CanonicalEvent objects for the
baseline aggregator.

Design
------
- Generator-based: never loads the entire file into memory.
- Validates each JSON dict against the CanonicalEvent schema.
- Skips invalid lines with a structured warning (does not raise).
- Supports reading from an explicit file path OR from settings default.
- Exposes load_all() as a convenience for tests and small datasets.

Coupling Rule
-------------
This reader ONLY reads from files produced by Module 1.3.
It NEVER reads raw Digital Twin JSONL directly.
The normalized file is the single source of truth for baseline computation.

Usage
-----
    reader = NormalizedEventReader()
    for event in reader.stream():
        # event is a CanonicalEvent
        ...

    # Or with an explicit file path:
    reader = NormalizedEventReader(input_file=Path("data/normalized/normalized_events.jsonl"))
    events = reader.load_all()
"""

from __future__ import annotations

import json
from collections.abc import Generator
from pathlib import Path
from typing import Any

import structlog

from backend.baseline.exceptions import BaselineInputError
from backend.normalization.models import CanonicalEvent

logger = structlog.get_logger(__name__)

# Default path matches Module 1.3 NormalizationPipeline output
_DEFAULT_NORMALIZED_FILE = Path("./data/normalized/normalized_events.jsonl")


class NormalizedEventReader:
    """
    Reads CanonicalEvent records from the normalized JSONL output.

    Parameters
    ----------
    input_file:  Path to the normalized_events.jsonl file.
                 Defaults to data/normalized/normalized_events.jsonl.

    Attributes
    ----------
    lines_read:       Total lines read in the last stream() call.
    events_yielded:   Total valid events yielded.
    parse_errors:     Lines that could not be parsed.
    """

    def __init__(self, input_file: Path | None = None) -> None:
        self._file = input_file or _DEFAULT_NORMALIZED_FILE
        self.lines_read: int = 0
        self.events_yielded: int = 0
        self.parse_errors: int = 0

    def stream(self) -> Generator[CanonicalEvent, None, None]:
        """
        Stream CanonicalEvent objects from the normalized JSONL file.

        Yields one CanonicalEvent per valid line.
        Skips blank lines and invalid JSON silently (with log warning).
        Skips lines that fail CanonicalEvent schema validation.

        Raises
        ------
        BaselineInputError if the file does not exist or is not readable.
        """
        self._validate_file_accessible()

        self.lines_read = 0
        self.events_yielded = 0
        self.parse_errors = 0

        logger.info(
            "baseline_reader_start",
            file=str(self._file),
        )

        with self._file.open(encoding="utf-8") as fh:
            for line_no, raw_line in enumerate(fh, start=1):
                self.lines_read += 1
                stripped = raw_line.strip()
                if not stripped:
                    continue

                event = self._parse_line(stripped, line_no)
                if event is not None:
                    self.events_yielded += 1
                    yield event
                else:
                    self.parse_errors += 1

        logger.info(
            "baseline_reader_complete",
            file=str(self._file),
            lines_read=self.lines_read,
            events_yielded=self.events_yielded,
            parse_errors=self.parse_errors,
        )

    def load_all(self) -> list[CanonicalEvent]:
        """
        Load all events into memory.

        Convenience method for small datasets, tests, and builder passes.
        For large production files, prefer stream().

        Returns
        -------
        list of CanonicalEvent in file order.

        Raises
        ------
        BaselineInputError if the file does not exist.
        """
        return list(self.stream())

    @property
    def input_file(self) -> Path:
        """The file this reader is configured to read."""
        return self._file

    @property
    def file_size_bytes(self) -> int | None:
        """File size in bytes, or None if not accessible."""
        if not self._file.exists():
            return None
        return self._file.stat().st_size

    # ── Private ─────────────────────────────────────────────────────────────

    def _validate_file_accessible(self) -> None:
        """Raise BaselineInputError if the file cannot be read."""
        if not self._file.exists():
            raise BaselineInputError(
                f"Normalized event file not found: {self._file}. "
                "Run the normalization pipeline (Module 1.3) first.",
                context={"path": str(self._file)},
            )
        if not self._file.is_file():
            raise BaselineInputError(
                f"Path exists but is not a file: {self._file}",
                context={"path": str(self._file)},
            )
        if self._file.stat().st_size == 0:
            raise BaselineInputError(
                f"Normalized event file is empty: {self._file}. "
                "Run the normalization pipeline to produce events.",
                context={"path": str(self._file)},
            )

    def _parse_line(self, line: str, line_no: int) -> CanonicalEvent | None:
        """
        Parse one JSONL line into a CanonicalEvent.

        Returns None on any failure (logged as warning).
        """
        # Step 1: JSON parse
        try:
            raw: Any = json.loads(line)
        except json.JSONDecodeError as exc:
            logger.warning(
                "baseline_reader_json_error",
                line_number=line_no,
                error=str(exc),
                raw_line=line[:150],
            )
            return None

        if not isinstance(raw, dict):
            logger.warning(
                "baseline_reader_not_dict",
                line_number=line_no,
                actual_type=type(raw).__name__,
            )
            return None

        # Step 2: Schema validation
        try:
            return CanonicalEvent.model_validate(raw)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "baseline_reader_validation_error",
                line_number=line_no,
                error=str(exc),
                source=raw.get("source", "unknown"),
            )
            return None
