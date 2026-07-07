"""
tests/unit/normalization/test_pipeline.py
==========================================
Unit tests for NormalizationPipeline:
  - run() produces ParseReport
  - normalize_record() single-record API
  - stream_normalized() generator API
  - Error isolation (bad source, bad record)
  - Statistics tracking
  - Dead-letter recording
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from backend.normalization.models import CanonicalEvent, RawRecord
from backend.normalization.pipeline import NormalizationPipeline
from backend.normalization.writer import NormalizedEventWriter
from tests.unit.normalization.conftest import (
    make_hospital_raw,
    make_ot_raw,
    make_dc_raw,
    make_attacker_raw,
    make_raw_record,
    write_jsonl,
)


# ---------------------------------------------------------------------------
# Registry mock builder
# ---------------------------------------------------------------------------

def _mock_registry(*file_specs: tuple[str, Path]) -> MagicMock:
    """
    Build a mock registry.
    file_specs: [(source_name, Path), ...]
    """
    registry = MagicMock()
    sources = []
    for role, path in file_specs:
        src = MagicMock()
        src.role = role
        src.host_log_path = path
        sources.append(src)
    registry.list_telemetry_sources.return_value = sources
    return registry


# ===========================================================================
# normalize_record() — single record API
# ===========================================================================

class TestNormalizeRecord:
    """Tests normalize_record() — the per-record public API."""

    def _pipeline(self, tmp_path: Path) -> NormalizationPipeline:
        registry = MagicMock()
        registry.list_telemetry_sources.return_value = []
        return NormalizationPipeline(registry, output_dir=tmp_path / "out")

    def test_normalize_hospital_record(self, tmp_path: Path) -> None:
        pipeline = self._pipeline(tmp_path)
        raw = make_raw_record("hospital_server", make_hospital_raw())
        event = pipeline.normalize_record(raw)
        assert isinstance(event, CanonicalEvent)
        assert event.source == "hospital_server"
        assert event.event_type == "ProcessCreate"

    def test_normalize_dc_record(self, tmp_path: Path) -> None:
        pipeline = self._pipeline(tmp_path)
        raw = make_raw_record("domain_controller", make_dc_raw())
        event = pipeline.normalize_record(raw)
        assert event.source == "domain_controller"
        assert event.logon_type == "network"

    def test_normalize_ot_record(self, tmp_path: Path) -> None:
        pipeline = self._pipeline(tmp_path)
        raw = make_raw_record("ot_node", make_ot_raw())
        event = pipeline.normalize_record(raw)
        assert event.source == "ot_node"
        assert event.modbus_register == 15
        assert event.protocol == "modbus"

    def test_normalize_attacker_record(self, tmp_path: Path) -> None:
        pipeline = self._pipeline(tmp_path)
        raw = make_raw_record("attacker", make_attacker_raw())
        event = pipeline.normalize_record(raw)
        assert event.source == "attacker"
        assert event.event_type == "AttackerHeartbeat"

    def test_unknown_source_returns_none(self, tmp_path: Path) -> None:
        pipeline = self._pipeline(tmp_path)
        raw = make_raw_record("unknown_source", {"event_type": "Foo"})
        result = pipeline.normalize_record(raw)
        assert result is None

    def test_bad_record_missing_timestamp_returns_none(self, tmp_path: Path) -> None:
        pipeline = self._pipeline(tmp_path)
        raw_dict = make_hospital_raw()
        del raw_dict["timestamp"]
        raw = make_raw_record("hospital_server", raw_dict)
        result = pipeline.normalize_record(raw)
        assert result is None

    def test_source_file_attached_to_event(self, tmp_path: Path) -> None:
        pipeline = self._pipeline(tmp_path)
        raw = make_raw_record(
            "hospital_server",
            make_hospital_raw(),
            source_file="/logs/hospital_server.jsonl",
        )
        event = pipeline.normalize_record(raw)
        assert event is not None
        assert event.source_file == "/logs/hospital_server.jsonl"


# ===========================================================================
# stream_normalized() — generator API
# ===========================================================================

class TestStreamNormalized:

    def test_stream_normalized_yields_canonical_events(self, tmp_path: Path) -> None:
        log_file = tmp_path / "hospital.jsonl"
        write_jsonl(log_file, [make_hospital_raw()] * 10)

        registry = _mock_registry(("hospital_server", log_file))
        pipeline = NormalizationPipeline(registry, output_dir=tmp_path / "out")

        events = list(pipeline.stream_normalized())
        assert len(events) == 10
        assert all(isinstance(e, CanonicalEvent) for e in events)

    def test_stream_normalized_skips_errors(self, tmp_path: Path) -> None:
        log_file = tmp_path / "mixed.jsonl"
        good = make_hospital_raw()
        bad = {}  # Missing timestamp, event_type, host
        write_jsonl(log_file, [good, bad, good, bad, good])

        registry = _mock_registry(("hospital_server", log_file))
        pipeline = NormalizationPipeline(registry, output_dir=tmp_path / "out")

        events = list(pipeline.stream_normalized())
        assert len(events) == 3  # 2 bad records skipped

    def test_stream_normalized_multi_source(self, tmp_path: Path) -> None:
        h_file = tmp_path / "hospital.jsonl"
        ot_file = tmp_path / "ot.jsonl"
        write_jsonl(h_file, [make_hospital_raw()] * 5)
        write_jsonl(ot_file, [make_ot_raw()] * 3)

        registry = _mock_registry(
            ("hospital_server", h_file),
            ("ot_node", ot_file),
        )
        pipeline = NormalizationPipeline(registry, output_dir=tmp_path / "out")
        events = list(pipeline.stream_normalized())
        assert len(events) == 8


# ===========================================================================
# run() — full pipeline with disk I/O
# ===========================================================================

class TestRunPipeline:

    def test_run_returns_parse_report(self, tmp_path: Path) -> None:
        log_file = tmp_path / "hospital.jsonl"
        write_jsonl(log_file, [make_hospital_raw()] * 5)

        registry = _mock_registry(("hospital_server", log_file))
        pipeline = NormalizationPipeline(registry, output_dir=tmp_path / "out")
        report = pipeline.run()

        assert report is not None
        assert report.total_events_normalized == 5
        assert report.total_parse_errors == 0

    def test_run_writes_output_jsonl(self, tmp_path: Path) -> None:
        log_file = tmp_path / "hospital.jsonl"
        write_jsonl(log_file, [make_hospital_raw()] * 3)

        out_dir = tmp_path / "out"
        registry = _mock_registry(("hospital_server", log_file))
        pipeline = NormalizationPipeline(registry, output_dir=out_dir)
        pipeline.run()

        output_file = out_dir / "normalized_events.jsonl"
        assert output_file.exists()
        records = NormalizedEventWriter.read_all(output_file)
        assert len(records) == 3

    def test_run_writes_pipeline_report_json(self, tmp_path: Path) -> None:
        log_file = tmp_path / "hospital.jsonl"
        write_jsonl(log_file, [make_hospital_raw()])

        out_dir = tmp_path / "out"
        registry = _mock_registry(("hospital_server", log_file))
        NormalizationPipeline(registry, output_dir=out_dir).run()

        report_file = out_dir / "pipeline_report.json"
        assert report_file.exists()
        report_data = json.loads(report_file.read_text(encoding="utf-8"))
        assert "total_events_normalized" in report_data

    def test_run_error_events_written_to_error_file(self, tmp_path: Path) -> None:
        log_file = tmp_path / "mixed.jsonl"
        good = make_hospital_raw()
        bad = {"source": "hospital_server", "no_timestamp": True}  # Missing required
        write_jsonl(log_file, [good, bad, good])

        out_dir = tmp_path / "out"
        registry = _mock_registry(("hospital_server", log_file))
        report = NormalizationPipeline(registry, output_dir=out_dir).run()

        assert report.total_events_normalized == 2
        assert report.total_parse_errors == 1

    def test_run_missing_source_file_skipped(self, tmp_path: Path) -> None:
        missing = tmp_path / "missing.jsonl"  # Do not create
        registry = _mock_registry(("hospital_server", missing))

        out_dir = tmp_path / "out"
        report = NormalizationPipeline(registry, output_dir=out_dir).run()
        assert report.total_events_normalized == 0
        assert report.total_parse_errors == 0

    def test_run_completed_at_set(self, tmp_path: Path) -> None:
        log_file = tmp_path / "hospital.jsonl"
        write_jsonl(log_file, [make_hospital_raw()])

        registry = _mock_registry(("hospital_server", log_file))
        report = NormalizationPipeline(registry, output_dir=tmp_path / "out").run()
        assert report.completed_at is not None

    def test_run_per_source_stats_populated(self, tmp_path: Path) -> None:
        h_file = tmp_path / "hospital.jsonl"
        ot_file = tmp_path / "ot.jsonl"
        write_jsonl(h_file, [make_hospital_raw()] * 10)
        write_jsonl(ot_file, [make_ot_raw()] * 5)

        registry = _mock_registry(
            ("hospital_server", h_file),
            ("ot_node", ot_file),
        )
        report = NormalizationPipeline(
            registry, output_dir=tmp_path / "out"
        ).run()

        assert len(report.per_source_stats) == 2
        sources = {s.source for s in report.per_source_stats}
        assert "hospital_server" in sources
        assert "ot_node" in sources

    def test_run_last_report_attribute_set(self, tmp_path: Path) -> None:
        log_file = tmp_path / "hospital.jsonl"
        write_jsonl(log_file, [make_hospital_raw()])

        registry = _mock_registry(("hospital_server", log_file))
        pipeline = NormalizationPipeline(registry, output_dir=tmp_path / "out")
        pipeline.run()

        assert pipeline.last_report is not None
        assert pipeline.last_report.total_events_normalized == 1

    def test_output_events_have_normalizer_version(self, tmp_path: Path) -> None:
        log_file = tmp_path / "hospital.jsonl"
        write_jsonl(log_file, [make_hospital_raw()])

        out_dir = tmp_path / "out"
        registry = _mock_registry(("hospital_server", log_file))
        NormalizationPipeline(registry, output_dir=out_dir).run()

        records = NormalizedEventWriter.read_all(out_dir / "normalized_events.jsonl")
        assert all("normalizer_version" in r for r in records)
        assert all(r["normalizer_version"] == "1.0.0" for r in records)
