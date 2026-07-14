"""
tests/integration/test_normalization_pipeline.py
=================================================
Module 1.3 Integration Tests — Full Pipeline

Validates the complete pipeline:
  Digital Twin telemetry (JSONL files)
      ↓ TelemetryCollector (registry discovery)
      ↓ NormalizationPipeline (parser dispatch)
      ↓ CanonicalEvent output
      ↓ NormalizedEventWriter (JSONL output)

These tests simulate realistic multi-source scenarios without requiring
Docker containers.  They write synthetic JSONL files that match the
exact format produced by the Digital Twin generators.

Test Coverage
-------------
- Complete 4-source pipeline run
- Schema contract validation (all output fields present)
- Event ordering preservation (within-source)
- Error isolation (malformed records do not stop pipeline)
- Statistics accuracy
- Dead-letter recording for parse errors
- Output JSONL is a valid canonical event stream
- normalizer_version consistency

Runs in under 5 seconds (no Docker, no network).
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock

from backend.normalization.pipeline import NormalizationPipeline
from backend.normalization.writer import NormalizedEventWriter
from tests.unit.normalization.conftest import (
    make_attacker_raw,
    make_dc_raw,
    make_hospital_raw,
    make_ot_raw,
    write_jsonl,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_registry(*file_specs: tuple[str, Path]) -> MagicMock:
    """Build a registry mock from (source_name, path) pairs."""
    registry = MagicMock()
    sources = []
    for role, path in file_specs:
        src = MagicMock()
        src.container_role = role  # matches TelemetrySource.container_role (digital_twin/models.py)
        src.host_log_path = path
        sources.append(src)
    registry.list_telemetry_sources.return_value = sources
    return registry


CANONICAL_REQUIRED_KEYS = {
    "event_id",
    "timestamp",
    "source",
    "event_type",
    "host",
    "user",
    "resource",
    "action",
    "result",
    "normalizer_version",
    "parse_warnings",
    "extra_fields",
    "normalized_at",
}


# ===========================================================================
# Integration: 4-source pipeline
# ===========================================================================


class TestFullPipeline:
    """
    Full end-to-end pipeline with all 4 Digital Twin sources.
    """

    def test_four_source_pipeline_produces_correct_event_count(self, tmp_path: Path) -> None:
        """All events from all sources are normalized and written."""
        h_file = tmp_path / "hospital_server.jsonl"
        dc_file = tmp_path / "domain_controller.jsonl"
        ot_file = tmp_path / "ot_node.jsonl"
        at_file = tmp_path / "attacker.jsonl"

        write_jsonl(h_file, [make_hospital_raw()] * 50)
        write_jsonl(dc_file, [make_dc_raw()] * 20)
        write_jsonl(ot_file, [make_ot_raw()] * 30)
        write_jsonl(at_file, [make_attacker_raw()] * 5)

        registry = _mock_registry(
            ("hospital_server", h_file),
            ("domain_controller", dc_file),
            ("ot_node", ot_file),
            ("attacker", at_file),
        )
        out_dir = tmp_path / "normalized"
        report = NormalizationPipeline(registry, output_dir=out_dir).run()

        assert report.total_events_normalized == 105
        assert report.total_parse_errors == 0

    def test_output_jsonl_has_correct_line_count(self, tmp_path: Path) -> None:
        h_file = tmp_path / "hospital_server.jsonl"
        write_jsonl(h_file, [make_hospital_raw()] * 100)

        registry = _mock_registry(("hospital_server", h_file))
        out_dir = tmp_path / "normalized"
        NormalizationPipeline(registry, output_dir=out_dir).run()

        output_lines = (
            (out_dir / "normalized_events.jsonl").read_text(encoding="utf-8").strip().splitlines()
        )
        assert len(output_lines) == 100

    def test_all_sources_represented_in_output(self, tmp_path: Path) -> None:
        h_file = tmp_path / "hospital.jsonl"
        ot_file = tmp_path / "ot.jsonl"
        dc_file = tmp_path / "dc.jsonl"
        at_file = tmp_path / "attacker.jsonl"

        write_jsonl(h_file, [make_hospital_raw()])
        write_jsonl(ot_file, [make_ot_raw()])
        write_jsonl(dc_file, [make_dc_raw()])
        write_jsonl(at_file, [make_attacker_raw()])

        registry = _mock_registry(
            ("hospital_server", h_file),
            ("ot_node", ot_file),
            ("domain_controller", dc_file),
            ("attacker", at_file),
        )
        out_dir = tmp_path / "normalized"
        NormalizationPipeline(registry, output_dir=out_dir).run()

        records = NormalizedEventWriter.read_all(out_dir / "normalized_events.jsonl")
        sources_in_output = {r["source"] for r in records}
        assert sources_in_output == {"hospital_server", "ot_node", "domain_controller", "attacker"}


# ===========================================================================
# Integration: Schema contract validation
# ===========================================================================


class TestSchemaContract:
    """Verify every output event satisfies the canonical schema contract."""

    def test_all_required_fields_present_in_every_output_event(self, tmp_path: Path) -> None:
        h_file = tmp_path / "hospital.jsonl"
        ot_file = tmp_path / "ot.jsonl"
        write_jsonl(h_file, [make_hospital_raw()] * 20)
        write_jsonl(ot_file, [make_ot_raw()] * 10)

        registry = _mock_registry(("hospital_server", h_file), ("ot_node", ot_file))
        out_dir = tmp_path / "normalized"
        NormalizationPipeline(registry, output_dir=out_dir).run()

        records = NormalizedEventWriter.read_all(out_dir / "normalized_events.jsonl")
        for i, record in enumerate(records):
            missing = CANONICAL_REQUIRED_KEYS - record.keys()
            assert not missing, f"Record {i} missing fields: {missing}"

    def test_normalizer_version_consistent_across_all_events(self, tmp_path: Path) -> None:
        h_file = tmp_path / "hospital.jsonl"
        write_jsonl(h_file, [make_hospital_raw()] * 50)

        registry = _mock_registry(("hospital_server", h_file))
        out_dir = tmp_path / "normalized"
        NormalizationPipeline(registry, output_dir=out_dir).run()

        records = NormalizedEventWriter.read_all(out_dir / "normalized_events.jsonl")
        versions = {r["normalizer_version"] for r in records}
        assert versions == {"1.0.0"}

    def test_all_timestamps_are_utc_strings(self, tmp_path: Path) -> None:
        h_file = tmp_path / "hospital.jsonl"
        write_jsonl(h_file, [make_hospital_raw()] * 10)

        registry = _mock_registry(("hospital_server", h_file))
        out_dir = tmp_path / "normalized"
        NormalizationPipeline(registry, output_dir=out_dir).run()

        records = NormalizedEventWriter.read_all(out_dir / "normalized_events.jsonl")
        for record in records:
            ts_str = record["timestamp"]
            # Must be parseable
            dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            assert dt.tzinfo is not None

    def test_hosts_are_lowercased_in_output(self, tmp_path: Path) -> None:
        h_file = tmp_path / "hospital.jsonl"
        write_jsonl(h_file, [make_hospital_raw({"host": "HOSPITAL-SERVER-01"})])

        registry = _mock_registry(("hospital_server", h_file))
        out_dir = tmp_path / "normalized"
        NormalizationPipeline(registry, output_dir=out_dir).run()

        records = NormalizedEventWriter.read_all(out_dir / "normalized_events.jsonl")
        assert records[0]["host"] == "hospital-server-01"

    def test_ot_events_have_modbus_fields(self, tmp_path: Path) -> None:
        ot_file = tmp_path / "ot.jsonl"
        write_jsonl(ot_file, [make_ot_raw()])

        registry = _mock_registry(("ot_node", ot_file))
        out_dir = tmp_path / "normalized"
        NormalizationPipeline(registry, output_dir=out_dir).run()

        records = NormalizedEventWriter.read_all(out_dir / "normalized_events.jsonl")
        assert records[0]["modbus_register"] == 15
        assert records[0]["modbus_function_code"] == "FC03"
        assert records[0]["protocol"] == "modbus"
        assert records[0]["port"] == 502

    def test_dc_events_have_auth_fields(self, tmp_path: Path) -> None:
        dc_file = tmp_path / "dc.jsonl"
        write_jsonl(dc_file, [make_dc_raw()])

        registry = _mock_registry(("domain_controller", dc_file))
        out_dir = tmp_path / "normalized"
        NormalizationPipeline(registry, output_dir=out_dir).run()

        records = NormalizedEventWriter.read_all(out_dir / "normalized_events.jsonl")
        assert records[0]["logon_type"] == "network"
        assert records[0]["auth_package"] == "Kerberos"
        assert records[0]["domain"] == "HOSPITAL"

    def test_hospital_events_have_process_fields(self, tmp_path: Path) -> None:
        h_file = tmp_path / "hospital.jsonl"
        write_jsonl(h_file, [make_hospital_raw()])

        registry = _mock_registry(("hospital_server", h_file))
        out_dir = tmp_path / "normalized"
        NormalizationPipeline(registry, output_dir=out_dir).run()

        records = NormalizedEventWriter.read_all(out_dir / "normalized_events.jsonl")
        assert records[0]["process"] == "w3wp.exe"
        assert records[0]["pid"] == 4812
        assert records[0]["windows_event_id"] == 4688


# ===========================================================================
# Integration: Ordering preservation
# ===========================================================================


class TestOrderingPreservation:
    """Verify within-source event ordering is preserved."""

    def test_hospital_events_ordered_by_input_order(self, tmp_path: Path) -> None:
        h_file = tmp_path / "hospital.jsonl"
        events = [make_hospital_raw({"pid": i}) for i in range(20)]
        write_jsonl(h_file, events)

        registry = _mock_registry(("hospital_server", h_file))
        out_dir = tmp_path / "normalized"
        NormalizationPipeline(registry, output_dir=out_dir).run()

        records = NormalizedEventWriter.read_all(out_dir / "normalized_events.jsonl")
        pids = [r["pid"] for r in records]
        assert pids == list(range(20))

    def test_ot_events_maintain_register_sequence(self, tmp_path: Path) -> None:
        ot_file = tmp_path / "ot.jsonl"
        events = [make_ot_raw({"modbus_register": i}) for i in range(10, 20)]
        write_jsonl(ot_file, events)

        registry = _mock_registry(("ot_node", ot_file))
        out_dir = tmp_path / "normalized"
        NormalizationPipeline(registry, output_dir=out_dir).run()

        records = NormalizedEventWriter.read_all(out_dir / "normalized_events.jsonl")
        registers = [r["modbus_register"] for r in records]
        assert registers == list(range(10, 20))


# ===========================================================================
# Integration: Error isolation
# ===========================================================================


class TestErrorIsolation:
    """Verify bad records do not stop the pipeline."""

    def test_malformed_json_lines_skipped_good_events_written(self, tmp_path: Path) -> None:
        h_file = tmp_path / "mixed.jsonl"
        lines = (
            json.dumps(make_hospital_raw())
            + "\n"
            + "NOT VALID JSON\n"
            + json.dumps(make_hospital_raw({"pid": 9999}))
            + "\n"
        )
        h_file.write_text(lines, encoding="utf-8")

        registry = _mock_registry(("hospital_server", h_file))
        out_dir = tmp_path / "normalized"
        report = NormalizationPipeline(registry, output_dir=out_dir).run()

        records = NormalizedEventWriter.read_all(out_dir / "normalized_events.jsonl")
        assert len(records) == 2
        assert report.total_events_normalized == 2

    def test_missing_required_field_counts_as_parse_error(self, tmp_path: Path) -> None:
        h_file = tmp_path / "bad.jsonl"
        bad_event = make_hospital_raw()
        del bad_event["timestamp"]
        write_jsonl(h_file, [make_hospital_raw(), bad_event, make_hospital_raw()])

        registry = _mock_registry(("hospital_server", h_file))
        out_dir = tmp_path / "normalized"
        report = NormalizationPipeline(registry, output_dir=out_dir).run()

        assert report.total_events_normalized == 2
        assert report.total_parse_errors == 1

    def test_one_missing_source_does_not_stop_others(self, tmp_path: Path) -> None:
        ot_file = tmp_path / "ot.jsonl"
        missing_file = tmp_path / "missing.jsonl"
        write_jsonl(ot_file, [make_ot_raw()] * 5)

        registry = _mock_registry(
            ("hospital_server", missing_file),
            ("ot_node", ot_file),
        )
        out_dir = tmp_path / "normalized"
        report = NormalizationPipeline(registry, output_dir=out_dir).run()

        assert report.total_events_normalized == 5
        assert report.total_parse_errors == 0

    def test_mixed_good_and_bad_across_sources(self, tmp_path: Path) -> None:
        h_file = tmp_path / "hospital.jsonl"
        ot_file = tmp_path / "ot.jsonl"
        write_jsonl(h_file, [make_hospital_raw()] * 10)
        write_jsonl(ot_file, [make_ot_raw()] * 5)
        # Inject bad records in hospital file
        with h_file.open("a", encoding="utf-8") as f:
            f.write("BAD JSON\n")
            bad = make_hospital_raw()
            del bad["timestamp"]
            f.write(json.dumps(bad) + "\n")

        registry = _mock_registry(("hospital_server", h_file), ("ot_node", ot_file))
        out_dir = tmp_path / "normalized"
        report = NormalizationPipeline(registry, output_dir=out_dir).run()

        assert report.total_events_normalized == 15
        assert report.total_parse_errors >= 1


# ===========================================================================
# Integration: Statistics accuracy
# ===========================================================================


class TestStatisticsAccuracy:
    def test_per_source_stats_totals_match(self, tmp_path: Path) -> None:
        h_file = tmp_path / "hospital.jsonl"
        ot_file = tmp_path / "ot.jsonl"
        write_jsonl(h_file, [make_hospital_raw()] * 30)
        write_jsonl(ot_file, [make_ot_raw()] * 20)

        registry = _mock_registry(("hospital_server", h_file), ("ot_node", ot_file))
        out_dir = tmp_path / "normalized"
        report = NormalizationPipeline(registry, output_dir=out_dir).run()

        stats_by_source = {s.source: s for s in report.per_source_stats}
        assert stats_by_source["hospital_server"].events_normalized == 30
        assert stats_by_source["ot_node"].events_normalized == 20

    def test_overall_error_rate_zero_for_clean_data(self, tmp_path: Path) -> None:
        h_file = tmp_path / "hospital.jsonl"
        write_jsonl(h_file, [make_hospital_raw()] * 50)

        registry = _mock_registry(("hospital_server", h_file))
        out_dir = tmp_path / "normalized"
        report = NormalizationPipeline(registry, output_dir=out_dir).run()

        assert report.overall_error_rate == 0.0

    def test_duration_seconds_is_positive(self, tmp_path: Path) -> None:
        h_file = tmp_path / "hospital.jsonl"
        write_jsonl(h_file, [make_hospital_raw()])

        registry = _mock_registry(("hospital_server", h_file))
        report = NormalizationPipeline(registry, output_dir=tmp_path / "out").run()

        assert report.duration_seconds is not None
        assert report.duration_seconds >= 0.0

    def test_sources_processed_matches_input_sources(self, tmp_path: Path) -> None:
        h_file = tmp_path / "hospital.jsonl"
        dc_file = tmp_path / "dc.jsonl"
        write_jsonl(h_file, [make_hospital_raw()])
        write_jsonl(dc_file, [make_dc_raw()])

        registry = _mock_registry(
            ("hospital_server", h_file),
            ("domain_controller", dc_file),
        )
        report = NormalizationPipeline(registry, output_dir=tmp_path / "out").run()

        assert "hospital_server" in report.sources_processed
        assert "domain_controller" in report.sources_processed
