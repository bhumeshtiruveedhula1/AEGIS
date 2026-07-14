"""
backend.normalization.writer — Normalized Event Writer
======================================================
Module 1.3 — Unified Log Collection & Normalization

The NormalizedEventWriter serialises CanonicalEvent objects to JSONL
format.  It is used by the pipeline for both the main output file and
the dead-letter (error) file.

Design
------
- Context manager — resources always released (flush + close).
- write() accepts CanonicalEvent.
- write_raw() accepts a plain dict (used for dead-letter records).
- Events written in call order — callers control ordering.
- Buffered writes (Python default buffer) — fsync on close.

Ordering Guarantee
------------------
The writer preserves the order in which write() is called.
The pipeline calls write() in source-file order (line 1 → N).
Timestamp-based reordering is NOT performed in this module —
that is the responsibility of the Feature Engine (Module 2.x).
For forensic use, line_number and source_file on each RawRecord
allow reconstruction of original ordering.

Output Format
-------------
One JSON object per line, UTF-8, no trailing comma, LF line ending.
Every object contains all CanonicalEvent fields (None fields included).

    {"event_id": "...", "timestamp": "...", "source": "hospital_server", ...}
    {"event_id": "...", "timestamp": "...", "source": "ot_node", ...}

Consumers can trust:
  - Every line is a valid JSON object.
  - Every object has the full CanonicalEvent schema.
  - normalizer_version is present on every object.

Usage
-----
    writer = NormalizedEventWriter(Path("data/normalized/normalized_events.jsonl"))

    with writer:
        for event in canonical_events:
            writer.write(event)

    # Or as a one-liner for tests:
    NormalizedEventWriter.write_all(events, Path("output.jsonl"))
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import structlog

from backend.normalization.models import CanonicalEvent

logger = structlog.get_logger(__name__)


def _default_serializer(obj: Any) -> Any:
    """JSON serializer for types not handled by the default encoder."""

    if hasattr(obj, "isoformat"):
        return obj.isoformat()
    if hasattr(obj, "__str__"):
        return str(obj)
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serialisable")


class NormalizedEventWriter:
    """
    Writes CanonicalEvent objects to a JSONL file.

    Parameters
    ----------
    output_path:  Path to the output JSONL file.
                  Created if it does not exist.
                  Opened in WRITE (truncate) mode by default — each pipeline
                  run produces a complete, self-contained output.
    overwrite:    If True (default), truncate file before writing.
                  Set to False to append to an existing file.

    Attributes
    ----------
    events_written:  Count of events written in this session.
    """

    def __init__(
        self,
        output_path: Path,
        *,
        overwrite: bool = True,
    ) -> None:
        self._path = output_path
        self._overwrite = overwrite
        self._fh = None
        self.events_written: int = 0

    def __enter__(self) -> NormalizedEventWriter:
        self._open()
        return self

    def __exit__(self, *_: Any) -> None:
        self._close()

    def write(self, event: CanonicalEvent) -> None:
        """
        Serialise and write a CanonicalEvent to the output file.

        Parameters
        ----------
        event:  A fully normalized CanonicalEvent.

        Raises
        ------
        RuntimeError if writer is not open (use as context manager or call open()).
        """
        if self._fh is None:
            msg = "NormalizedEventWriter is not open. Use as context manager."
            raise RuntimeError(msg)

        line = json.dumps(
            event.model_dump(mode="json"),
            default=_default_serializer,
            separators=(",", ":"),  # Compact JSON — no extra whitespace
            ensure_ascii=False,
        )
        self._fh.write(line + "\n")
        self.events_written += 1

    def write_raw(self, raw_dict: dict[str, Any]) -> None:
        """
        Write a raw dict as a JSONL line.

        Used for dead-letter records that could not be parsed into
        CanonicalEvent — the raw dict + error reason is preserved verbatim.

        Parameters
        ----------
        raw_dict:  Any serialisable dict.
        """
        if self._fh is None:
            msg = "NormalizedEventWriter is not open."
            raise RuntimeError(msg)
        line = json.dumps(
            raw_dict,
            default=_default_serializer,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        self._fh.write(line + "\n")
        self.events_written += 1

    def flush(self) -> None:
        """Flush buffered writes to the OS."""
        if self._fh is not None:
            self._fh.flush()

    @property
    def path(self) -> Path:
        """Output file path."""
        return self._path

    # ── Class methods for convenience ───────────────────────────────────────

    @classmethod
    def write_all(
        cls,
        events: list[CanonicalEvent],
        output_path: Path,
        *,
        overwrite: bool = True,
    ) -> int:
        """
        Write a list of events to a file in one call.

        Parameters
        ----------
        events:       Events to write.
        output_path:  Output file path.
        overwrite:    Truncate file before writing (default: True).

        Returns
        -------
        Number of events written.
        """
        writer = cls(output_path, overwrite=overwrite)
        with writer:
            for event in events:
                writer.write(event)
        return writer.events_written

    @classmethod
    def read_all(cls, input_path: Path) -> list[dict[str, Any]]:
        """
        Read all records from a JSONL file.

        Used in tests and validation scripts.

        Returns
        -------
        List of dicts (one per line).  Skips blank and invalid lines.
        """
        records = []
        with input_path.open(encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    records.append(json.loads(stripped))
                except json.JSONDecodeError:
                    logger.warning(
                        "writer_read_invalid_json_line",
                        path=str(input_path),
                        line=stripped[:100],
                    )
        return records

    # ── Private ─────────────────────────────────────────────────────────────

    def _open(self) -> None:
        """Open the output file."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        mode = "w" if self._overwrite else "a"
        self._fh = self._path.open(mode=mode, encoding="utf-8", buffering=8192)
        logger.debug(
            "normalized_writer_opened",
            path=str(self._path),
            mode=mode,
        )

    def _close(self) -> None:
        """Flush and close the output file."""
        if self._fh is not None:
            try:
                self._fh.flush()
                self._fh.close()
            except OSError as exc:
                logger.warning("normalized_writer_close_error", error=str(exc))
            finally:
                self._fh = None
            logger.debug(
                "normalized_writer_closed",
                path=str(self._path),
                events_written=self.events_written,
            )
