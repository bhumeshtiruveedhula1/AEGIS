"""
tests/unit/normalization/test_collector.py
==========================================
Unit tests for TelemetryCollector:
  - Source discovery via registry
  - JSONL streaming
  - Missing file handling
  - Malformed JSON lines
  - Max lines limiting
  - collect_from_file() direct API
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

from backend.normalization.collector import TelemetryCollector
from backend.normalization.models import RawRecord
from tests.unit.normalization.conftest import make_hospital_raw, make_ot_raw, write_jsonl

# ---------------------------------------------------------------------------
# Registry mock factory
# ---------------------------------------------------------------------------


def _make_mock_registry(sources: list[dict[str, Any]]) -> MagicMock:
    """
    Build a MagicMock DigitalTwinRegistry.

    sources: list of dicts with 'role' and 'host_log_path' keys.
    """
    registry = MagicMock()
    mock_sources = []
    for s in sources:
        src = MagicMock()
        src.container_role = s[
            "role"
        ]  # matches TelemetrySource.container_role (digital_twin/models.py)
        src.host_log_path = Path(s["host_log_path"])
        mock_sources.append(src)
    registry.list_telemetry_sources.return_value = mock_sources
    return registry


# ===========================================================================
# Stream records from real files
# ===========================================================================


class TestStreamRecords:
    def test_stream_records_from_single_file(self, tmp_path: Path) -> None:
        log_file = tmp_path / "hospital_server.jsonl"
        events = [make_hospital_raw(), make_hospital_raw({"event_type": "NetworkConnect"})]
        write_jsonl(log_file, events)

        registry = _make_mock_registry(
            [
                {"role": "hospital_server", "host_log_path": str(log_file)},
            ]
        )
        collector = TelemetryCollector(registry)

        records = list(collector.stream_records())
        assert len(records) == 2

    def test_stream_records_yields_raw_records(self, tmp_path: Path) -> None:
        log_file = tmp_path / "hospital.jsonl"
        write_jsonl(log_file, [make_hospital_raw()])

        registry = _make_mock_registry(
            [
                {"role": "hospital_server", "host_log_path": str(log_file)},
            ]
        )
        collector = TelemetryCollector(registry)

        records = list(collector.stream_records())
        assert all(isinstance(r, RawRecord) for r in records)

    def test_source_name_set_correctly(self, tmp_path: Path) -> None:
        log_file = tmp_path / "hospital.jsonl"
        write_jsonl(log_file, [make_hospital_raw()])

        registry = _make_mock_registry(
            [
                {"role": "hospital_server", "host_log_path": str(log_file)},
            ]
        )
        records = list(TelemetryCollector(registry).stream_records())
        assert records[0].source == "hospital_server"

    def test_line_numbers_start_at_one(self, tmp_path: Path) -> None:
        log_file = tmp_path / "hospital.jsonl"
        events = [make_hospital_raw() for _ in range(3)]
        write_jsonl(log_file, events)

        registry = _make_mock_registry(
            [
                {"role": "hospital_server", "host_log_path": str(log_file)},
            ]
        )
        records = list(TelemetryCollector(registry).stream_records())
        assert records[0].line_number == 1
        assert records[1].line_number == 2
        assert records[2].line_number == 3

    def test_multiple_sources_all_streamed(self, tmp_path: Path) -> None:
        hospital_file = tmp_path / "hospital.jsonl"
        ot_file = tmp_path / "ot.jsonl"
        write_jsonl(hospital_file, [make_hospital_raw()] * 3)
        write_jsonl(ot_file, [make_ot_raw()] * 2)

        registry = _make_mock_registry(
            [
                {"role": "hospital_server", "host_log_path": str(hospital_file)},
                {"role": "ot_node", "host_log_path": str(ot_file)},
            ]
        )
        records = list(TelemetryCollector(registry).stream_records())
        assert len(records) == 5

    def test_source_order_preserved_within_source(self, tmp_path: Path) -> None:
        log_file = tmp_path / "events.jsonl"
        events = [make_hospital_raw({"pid": i}) for i in range(5)]
        write_jsonl(log_file, events)

        registry = _make_mock_registry(
            [
                {"role": "hospital_server", "host_log_path": str(log_file)},
            ]
        )
        records = list(TelemetryCollector(registry).stream_records())
        pids = [r.raw_dict.get("pid") for r in records]
        assert pids == list(range(5))


# ===========================================================================
# Error handling
# ===========================================================================


class TestCollectorErrorHandling:
    def test_missing_file_skipped_gracefully(self, tmp_path: Path) -> None:
        missing_file = tmp_path / "does_not_exist.jsonl"
        registry = _make_mock_registry(
            [
                {"role": "hospital_server", "host_log_path": str(missing_file)},
            ]
        )
        # Should yield nothing, not raise
        records = list(TelemetryCollector(registry).stream_records())
        assert records == []

    def test_malformed_json_line_skipped(self, tmp_path: Path) -> None:
        log_file = tmp_path / "events.jsonl"
        log_file.write_text(
            '{"valid": "line"}\n' "NOT VALID JSON\n" '{"another": "valid"}\n',
            encoding="utf-8",
        )
        registry = _make_mock_registry(
            [
                {"role": "hospital_server", "host_log_path": str(log_file)},
            ]
        )
        records = list(TelemetryCollector(registry).stream_records())
        # Only 2 valid lines, malformed line skipped
        assert len(records) == 2

    def test_non_dict_json_line_skipped(self, tmp_path: Path) -> None:
        log_file = tmp_path / "events.jsonl"
        log_file.write_text(
            '{"valid": true}\n' '"just_a_string"\n' "[1, 2, 3]\n" "null\n",
            encoding="utf-8",
        )
        registry = _make_mock_registry(
            [
                {"role": "hospital_server", "host_log_path": str(log_file)},
            ]
        )
        records = list(TelemetryCollector(registry).stream_records())
        assert len(records) == 1

    def test_blank_lines_skipped(self, tmp_path: Path) -> None:
        log_file = tmp_path / "events.jsonl"
        log_file.write_text(
            '{"event": "A"}\n' "\n" "\n" '{"event": "B"}\n',
            encoding="utf-8",
        )
        registry = _make_mock_registry(
            [
                {"role": "hospital_server", "host_log_path": str(log_file)},
            ]
        )
        records = list(TelemetryCollector(registry).stream_records())
        assert len(records) == 2

    def test_empty_registry_yields_nothing(self) -> None:
        registry = MagicMock()
        registry.list_telemetry_sources.return_value = []
        records = list(TelemetryCollector(registry).stream_records())
        assert records == []

    def test_one_bad_source_does_not_stop_others(self, tmp_path: Path) -> None:
        good_file = tmp_path / "ot.jsonl"
        write_jsonl(good_file, [make_ot_raw()] * 3)

        missing_file = tmp_path / "missing.jsonl"
        # Do not create missing_file

        registry = _make_mock_registry(
            [
                {"role": "hospital_server", "host_log_path": str(missing_file)},
                {"role": "ot_node", "host_log_path": str(good_file)},
            ]
        )
        records = list(TelemetryCollector(registry).stream_records())
        # Should get the 3 ot records despite the first source being missing
        assert len(records) == 3


# ===========================================================================
# Max lines limiting
# ===========================================================================


class TestMaxLinesLimiting:
    def test_max_lines_limits_output(self, tmp_path: Path) -> None:
        log_file = tmp_path / "many.jsonl"
        write_jsonl(log_file, [make_hospital_raw()] * 100)

        registry = _make_mock_registry(
            [
                {"role": "hospital_server", "host_log_path": str(log_file)},
            ]
        )
        records = list(TelemetryCollector(registry, max_lines_per_source=10).stream_records())
        assert len(records) == 10

    def test_max_lines_zero_means_unlimited(self, tmp_path: Path) -> None:
        log_file = tmp_path / "many.jsonl"
        write_jsonl(log_file, [make_hospital_raw()] * 50)

        registry = _make_mock_registry(
            [
                {"role": "hospital_server", "host_log_path": str(log_file)},
            ]
        )
        records = list(TelemetryCollector(registry, max_lines_per_source=0).stream_records())
        assert len(records) == 50


# ===========================================================================
# collect_from_file() direct API
# ===========================================================================


class TestCollectFromFile:
    def test_collect_from_file_yields_records(self, tmp_path: Path) -> None:
        log_file = tmp_path / "direct.jsonl"
        write_jsonl(log_file, [make_hospital_raw()] * 5)

        registry = MagicMock()
        collector = TelemetryCollector(registry)

        records = list(collector.collect_from_file("hospital_server", log_file))
        assert len(records) == 5

    def test_collect_from_file_sets_source_name(self, tmp_path: Path) -> None:
        log_file = tmp_path / "direct.jsonl"
        write_jsonl(log_file, [make_ot_raw()])

        registry = MagicMock()
        records = list(TelemetryCollector(registry).collect_from_file("ot_node", log_file))
        assert records[0].source == "ot_node"

    def test_collect_from_file_missing_file_yields_nothing(self, tmp_path: Path) -> None:
        registry = MagicMock()
        records = list(
            TelemetryCollector(registry).collect_from_file(
                "hospital_server", tmp_path / "ghost.jsonl"
            )
        )
        assert records == []
