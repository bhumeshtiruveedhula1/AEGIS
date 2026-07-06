"""
docker/digital_twin/shared/writer.py
=====================================
Thread-safe, buffered JSONL writer for telemetry generators.

All Digital Twin generators use this module for log output.
It handles:
  - Atomic line-by-line JSONL writes
  - Buffered I/O for performance (configurable flush interval)
  - Log rotation by size (configurable max_bytes)
  - Structured stderr logging (no external dependencies)
  - Event counter for health check reporting

Design
------
EventWriter is NOT async — generators run in a single-threaded synchronous
loop. Async I/O would add unnecessary complexity with no throughput benefit
at the expected event rates (<10K events/hour per container).

Usage
-----
    from shared.writer import EventWriter
    from shared.event_schema import make_event

    writer = EventWriter(
        log_path="/logs/hospital_server.jsonl",
        buffer_size=100,         # flush every 100 events
        max_bytes=100 * 1024**2, # rotate at 100 MB
    )

    event = make_event(source="hospital_server", ...)
    writer.write(event)
    writer.flush()               # called automatically on exit

    # Use as context manager:
    with EventWriter("/logs/hospital_server.jsonl") as writer:
        writer.write(event)
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TextIO

from shared.event_schema import TelemetryEvent


# ---------------------------------------------------------------------------
# Rotation strategy constants
# ---------------------------------------------------------------------------
DEFAULT_BUFFER_SIZE = 50          # events before auto-flush
DEFAULT_MAX_BYTES = 500 * 1024**2  # 500 MB per file before rotation
DEFAULT_BACKUP_COUNT = 5          # rotated files to keep


def _stderr(level: str, message: str, **kwargs: Any) -> None:
    """Minimal structured logger to stderr (no structlog dependency)."""
    record = {
        "ts": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z",
        "level": level,
        "msg": message,
        **kwargs,
    }
    print(json.dumps(record, separators=(",", ":")), file=sys.stderr, flush=True)


class EventWriter:
    """
    Thread-safe JSONL writer with buffering and log rotation.

    Parameters
    ----------
    log_path : str | Path
        Destination JSONL file path.
    buffer_size : int
        Number of events to buffer before flushing to disk.
    max_bytes : int
        Maximum file size in bytes before rotation.
    backup_count : int
        Number of rotated backup files to keep.
    """

    def __init__(
        self,
        log_path: str | Path,
        buffer_size: int = DEFAULT_BUFFER_SIZE,
        max_bytes: int = DEFAULT_MAX_BYTES,
        backup_count: int = DEFAULT_BACKUP_COUNT,
    ) -> None:
        self._path = Path(log_path)
        self._buffer_size = buffer_size
        self._max_bytes = max_bytes
        self._backup_count = backup_count

        self._lock = threading.Lock()
        self._buffer: list[str] = []
        self._total_written: int = 0
        self._error_count: int = 0
        self._file: TextIO | None = None

        # Ensure parent directories exist
        self._path.parent.mkdir(parents=True, exist_ok=True)

        # Open initial file handle
        self._open_file()

        _stderr("INFO", "event_writer_initialised", path=str(self._path))

    # -----------------------------------------------------------------------
    # Context Manager
    # -----------------------------------------------------------------------

    def __enter__(self) -> "EventWriter":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    # -----------------------------------------------------------------------
    # Write Interface
    # -----------------------------------------------------------------------

    def write(self, event: TelemetryEvent) -> None:
        """
        Write a single TelemetryEvent to the buffer.

        Flushes automatically when buffer reaches buffer_size.
        Thread-safe — safe to call from multiple threads.
        """
        line = event.to_jsonl_line()
        with self._lock:
            self._buffer.append(line)
            if len(self._buffer) >= self._buffer_size:
                self._flush_locked()

    def write_dict(self, data: dict[str, Any]) -> None:
        """Write a raw dict as a JSONL line (for error/metadata records)."""
        line = json.dumps(data, separators=(",", ":"))
        with self._lock:
            self._buffer.append(line)
            if len(self._buffer) >= self._buffer_size:
                self._flush_locked()

    def flush(self) -> None:
        """Force-flush the buffer to disk."""
        with self._lock:
            self._flush_locked()

    @property
    def total_written(self) -> int:
        """Total events successfully written to disk."""
        return self._total_written

    @property
    def error_count(self) -> int:
        """Total write errors encountered."""
        return self._error_count

    def close(self) -> None:
        """Flush remaining buffer and close the file handle."""
        with self._lock:
            self._flush_locked()
            if self._file is not None:
                try:
                    self._file.close()
                except OSError:
                    pass
                self._file = None
        _stderr(
            "INFO",
            "event_writer_closed",
            path=str(self._path),
            total_written=self._total_written,
        )

    # -----------------------------------------------------------------------
    # Internal
    # -----------------------------------------------------------------------

    def _open_file(self) -> None:
        """Open (or re-open after rotation) the log file in append mode."""
        if self._file is not None:
            try:
                self._file.close()
            except OSError:
                pass
        self._file = open(self._path, "a", encoding="utf-8", buffering=1)  # noqa: SIM115, WPS515

    def _flush_locked(self) -> None:
        """
        Flush the internal buffer to disk.
        MUST be called with self._lock held.
        """
        if not self._buffer:
            return
        if self._file is None:
            self._open_file()

        try:
            content = "\n".join(self._buffer) + "\n"
            self._file.write(content)  # type: ignore[union-attr]
            self._file.flush()  # type: ignore[union-attr]
            self._total_written += len(self._buffer)
            self._buffer.clear()

            # Check rotation
            if os.path.getsize(self._path) >= self._max_bytes:
                self._rotate_locked()

        except OSError as exc:
            self._error_count += 1
            _stderr("ERROR", "event_writer_flush_failed", error=str(exc))

    def _rotate_locked(self) -> None:
        """
        Rotate the current log file.
        Renames .jsonl → .jsonl.1, .jsonl.1 → .jsonl.2, etc.
        MUST be called with self._lock held.
        """
        try:
            if self._file is not None:
                self._file.close()
                self._file = None

            # Shift existing backups
            for i in range(self._backup_count - 1, 0, -1):
                old = self._path.with_suffix(f".jsonl.{i}")
                new = self._path.with_suffix(f".jsonl.{i + 1}")
                if old.exists():
                    old.rename(new)

            # Move current → .jsonl.1
            backup = self._path.with_suffix(".jsonl.1")
            if self._path.exists():
                self._path.rename(backup)

            # Open fresh file
            self._open_file()

            _stderr("INFO", "log_rotation_completed", path=str(self._path))

        except OSError as exc:
            _stderr("ERROR", "log_rotation_failed", error=str(exc))
            self._open_file()  # Re-open original as fallback
