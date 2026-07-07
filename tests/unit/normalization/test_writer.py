"""
tests/unit/normalization/test_writer.py
========================================
Unit tests for NormalizedEventWriter:
  - Context manager lifecycle
  - write() and write_raw()
  - read_all() round-trip
  - write_all() class method
  - Append vs overwrite mode
  - JSON serialisation correctness
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from backend.normalization.models import CanonicalEvent
from backend.normalization.writer import NormalizedEventWriter
from tests.unit.normalization.conftest import FIXED_DT


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_event(event_type: str = "ProcessCreate", **kwargs) -> CanonicalEvent:
    """Construct a minimal CanonicalEvent for tests."""
    defaults = dict(
        timestamp=FIXED_DT,
        source="hospital_server",
        event_type=event_type,
        host="hospital-server-01",
        user="svc-iis",
        resource="w3wp.exe",
        action="execute",
        result="success",
    )
    defaults.update(kwargs)
    return CanonicalEvent(**defaults)


# ===========================================================================
# Context manager lifecycle
# ===========================================================================

class TestWriterLifecycle:

    def test_context_manager_opens_and_closes(self, tmp_path: Path) -> None:
        out_file = tmp_path / "events.jsonl"
        with NormalizedEventWriter(out_file) as writer:
            assert writer._fh is not None
        # File is closed after context
        assert writer._fh is None

    def test_write_outside_context_raises(self, tmp_path: Path) -> None:
        writer = NormalizedEventWriter(tmp_path / "events.jsonl")
        event = _make_event()
        with pytest.raises(RuntimeError):
            writer.write(event)

    def test_file_created_when_not_exists(self, tmp_path: Path) -> None:
        out_file = tmp_path / "new" / "subdir" / "events.jsonl"
        with NormalizedEventWriter(out_file) as writer:
            writer.write(_make_event())
        assert out_file.exists()

    def test_events_written_counter(self, tmp_path: Path) -> None:
        out_file = tmp_path / "events.jsonl"
        with NormalizedEventWriter(out_file) as writer:
            for _ in range(5):
                writer.write(_make_event())
        assert writer.events_written == 5


# ===========================================================================
# write() correctness
# ===========================================================================

class TestWriteMethod:

    def test_one_line_per_event(self, tmp_path: Path) -> None:
        out_file = tmp_path / "events.jsonl"
        with NormalizedEventWriter(out_file) as writer:
            writer.write(_make_event())
            writer.write(_make_event(event_type="NetworkConnect"))

        lines = out_file.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 2

    def test_each_line_is_valid_json(self, tmp_path: Path) -> None:
        out_file = tmp_path / "events.jsonl"
        with NormalizedEventWriter(out_file) as writer:
            for _ in range(3):
                writer.write(_make_event())

        for line in out_file.read_text(encoding="utf-8").strip().splitlines():
            parsed = json.loads(line)
            assert isinstance(parsed, dict)

    def test_serialised_source_matches(self, tmp_path: Path) -> None:
        out_file = tmp_path / "events.jsonl"
        event = _make_event(source="ot_node")
        with NormalizedEventWriter(out_file) as writer:
            writer.write(event)

        parsed = json.loads(out_file.read_text(encoding="utf-8").strip())
        assert parsed["source"] == "ot_node"

    def test_normalizer_version_present(self, tmp_path: Path) -> None:
        out_file = tmp_path / "events.jsonl"
        with NormalizedEventWriter(out_file) as writer:
            writer.write(_make_event())

        parsed = json.loads(out_file.read_text(encoding="utf-8").strip())
        assert "normalizer_version" in parsed

    def test_none_fields_included_in_output(self, tmp_path: Path) -> None:
        out_file = tmp_path / "events.jsonl"
        with NormalizedEventWriter(out_file) as writer:
            writer.write(_make_event())  # process, pid, etc. are None

        parsed = json.loads(out_file.read_text(encoding="utf-8").strip())
        assert "process" in parsed
        assert parsed["process"] is None


# ===========================================================================
# write_raw() for dead-letter records
# ===========================================================================

class TestWriteRaw:

    def test_write_raw_dict(self, tmp_path: Path) -> None:
        out_file = tmp_path / "errors.jsonl"
        with NormalizedEventWriter(out_file) as writer:
            writer.write_raw({"error_reason": "ParseError", "raw_line": '{"bad":}'})

        parsed = json.loads(out_file.read_text(encoding="utf-8").strip())
        assert parsed["error_reason"] == "ParseError"

    def test_write_raw_increments_counter(self, tmp_path: Path) -> None:
        out_file = tmp_path / "errors.jsonl"
        with NormalizedEventWriter(out_file) as writer:
            writer.write_raw({"x": 1})
            writer.write_raw({"x": 2})
        assert writer.events_written == 2


# ===========================================================================
# read_all() round-trip
# ===========================================================================

class TestReadAll:

    def test_read_all_returns_written_events(self, tmp_path: Path) -> None:
        out_file = tmp_path / "events.jsonl"
        events = [_make_event(event_type=t) for t in ("ProcessCreate", "NetworkConnect")]
        NormalizedEventWriter.write_all(events, out_file)

        records = NormalizedEventWriter.read_all(out_file)
        assert len(records) == 2

    def test_read_all_event_types_match(self, tmp_path: Path) -> None:
        out_file = tmp_path / "events.jsonl"
        event_types = ["ProcessCreate", "FileAccess", "UserLogon"]
        events = [_make_event(event_type=t) for t in event_types]
        NormalizedEventWriter.write_all(events, out_file)

        records = NormalizedEventWriter.read_all(out_file)
        read_types = [r["event_type"] for r in records]
        assert read_types == event_types

    def test_read_all_skips_blank_lines(self, tmp_path: Path) -> None:
        out_file = tmp_path / "events.jsonl"
        out_file.write_text('{"a": 1}\n\n{"b": 2}\n', encoding="utf-8")
        records = NormalizedEventWriter.read_all(out_file)
        assert len(records) == 2

    def test_read_all_skips_invalid_json(self, tmp_path: Path) -> None:
        out_file = tmp_path / "events.jsonl"
        out_file.write_text('{"a": 1}\nNOT JSON\n{"b": 2}\n', encoding="utf-8")
        records = NormalizedEventWriter.read_all(out_file)
        assert len(records) == 2


# ===========================================================================
# write_all() class method
# ===========================================================================

class TestWriteAll:

    def test_write_all_writes_correct_count(self, tmp_path: Path) -> None:
        out_file = tmp_path / "events.jsonl"
        events = [_make_event() for _ in range(7)]
        count = NormalizedEventWriter.write_all(events, out_file)
        assert count == 7

    def test_write_all_overwrite_truncates_existing(self, tmp_path: Path) -> None:
        out_file = tmp_path / "events.jsonl"
        # Write 10 events first
        NormalizedEventWriter.write_all([_make_event()] * 10, out_file)
        # Overwrite with 3 events
        NormalizedEventWriter.write_all([_make_event()] * 3, out_file, overwrite=True)
        records = NormalizedEventWriter.read_all(out_file)
        assert len(records) == 3


# ===========================================================================
# Append vs overwrite mode
# ===========================================================================

class TestAppendVsOverwrite:

    def test_append_mode_accumulates(self, tmp_path: Path) -> None:
        out_file = tmp_path / "events.jsonl"
        # First write: 3 events
        with NormalizedEventWriter(out_file, overwrite=False) as w:
            for _ in range(3):
                w.write(_make_event())
        # Second write: 2 more events (append)
        with NormalizedEventWriter(out_file, overwrite=False) as w:
            for _ in range(2):
                w.write(_make_event())
        records = NormalizedEventWriter.read_all(out_file)
        assert len(records) == 5

    def test_overwrite_mode_replaces(self, tmp_path: Path) -> None:
        out_file = tmp_path / "events.jsonl"
        with NormalizedEventWriter(out_file, overwrite=False) as w:
            for _ in range(10):
                w.write(_make_event())
        with NormalizedEventWriter(out_file, overwrite=True) as w:
            w.write(_make_event())
        records = NormalizedEventWriter.read_all(out_file)
        assert len(records) == 1
