"""
tests/unit/normalization/test_models.py
========================================
Unit tests for CanonicalEvent, RawRecord, ParseStats, and ParseReport.
Verifies schema contract, field defaults, validators, and properties.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from backend.normalization.models import (
    CanonicalEvent,
    ParseReport,
    ParseStats,
    RawRecord,
)
from tests.unit.normalization.conftest import FIXED_DT, FIXED_TS, make_hospital_raw


# ===========================================================================
# CanonicalEvent
# ===========================================================================

class TestCanonicalEvent:
    """Tests for the CanonicalEvent canonical schema."""

    def _make_event(self, **overrides) -> CanonicalEvent:
        """Build a minimal valid CanonicalEvent."""
        defaults = dict(
            timestamp=FIXED_DT,
            source="hospital_server",
            event_type="ProcessCreate",
            host="hospital-server-01",
            user="svc-iis",
            resource="w3wp.exe",
            action="execute",
            result="success",
        )
        defaults.update(overrides)
        return CanonicalEvent(**defaults)

    # ── Required fields ───────────────────────────────────────────────────

    def test_minimal_construction(self) -> None:
        """CanonicalEvent constructs with only required BaseEvent fields."""
        event = self._make_event()
        assert event.source == "hospital_server"
        assert event.event_type == "ProcessCreate"
        assert event.host == "hospital-server-01"
        assert event.user == "svc-iis"
        assert event.result == "success"

    def test_event_id_auto_generated(self) -> None:
        """event_id is auto-generated as UUID v4."""
        event = self._make_event()
        assert event.event_id
        assert len(event.event_id) == 36  # UUID v4 string length

    def test_normalizer_version_default(self) -> None:
        """normalizer_version defaults to '1.0.0'."""
        event = self._make_event()
        assert event.normalizer_version == "1.0.0"

    def test_normalizer_version_validator_rejects_bad_format(self) -> None:
        """Invalid normalizer_version raises ValidationError."""
        with pytest.raises(ValidationError):
            self._make_event(normalizer_version="invalid")

    def test_normalizer_version_validator_rejects_two_parts(self) -> None:
        with pytest.raises(ValidationError):
            self._make_event(normalizer_version="1.0")

    # ── Optional fields default to None ──────────────────────────────────

    def test_optional_process_fields_default_none(self) -> None:
        event = self._make_event()
        assert event.process is None
        assert event.pid is None
        assert event.parent_process is None
        assert event.command_line is None

    def test_optional_network_fields_default_none(self) -> None:
        event = self._make_event()
        assert event.src_ip is None
        assert event.dst_ip is None
        assert event.port is None
        assert event.protocol is None
        assert event.bytes_out is None

    def test_optional_ot_fields_default_none(self) -> None:
        event = self._make_event()
        assert event.modbus_register is None
        assert event.modbus_value is None
        assert event.modbus_function_code is None
        assert event.supervisory_host is None

    def test_optional_auth_fields_default_none(self) -> None:
        event = self._make_event()
        assert event.logon_type is None
        assert event.auth_package is None
        assert event.domain is None
        assert event.windows_event_id is None

    def test_optional_file_db_fields_default_none(self) -> None:
        event = self._make_event()
        assert event.file_path is None
        assert event.db_query is None
        assert event.db_table is None

    # ── Explicit optional field values ────────────────────────────────────

    def test_process_fields_set_correctly(self) -> None:
        event = self._make_event(
            process="w3wp.exe",
            pid=4812,
            parent_process="svchost.exe",
            command_line="c:\\windows\\w3wp.exe -ap DefaultAppPool",
        )
        assert event.process == "w3wp.exe"
        assert event.pid == 4812
        assert event.parent_process == "svchost.exe"
        assert "w3wp.exe" in event.command_line

    def test_network_fields_set_correctly(self) -> None:
        event = self._make_event(
            src_ip="172.20.1.10",
            dst_ip="172.20.1.20",
            port=1433,
            protocol="tcp",
            bytes_out=2048,
        )
        assert event.src_ip == "172.20.1.10"
        assert event.dst_ip == "172.20.1.20"
        assert event.port == 1433
        assert event.protocol == "tcp"
        assert event.bytes_out == 2048

    def test_ot_fields_set_correctly(self) -> None:
        event = self._make_event(
            source="ot_node",
            event_type="ModbusRead",
            user="SCADA",
            resource="register_15",
            action="read",
            modbus_register=15,
            modbus_value=2847,
            modbus_function_code="FC03",
            supervisory_host="192.168.1.100",
        )
        assert event.modbus_register == 15
        assert event.modbus_value == 2847
        assert event.modbus_function_code == "FC03"
        assert event.supervisory_host == "192.168.1.100"

    def test_port_validates_range(self) -> None:
        """Port must be in [0, 65535]."""
        with pytest.raises(ValidationError):
            self._make_event(port=99999)

    def test_bytes_out_must_be_non_negative(self) -> None:
        with pytest.raises(ValidationError):
            self._make_event(bytes_out=-1)

    # ── Parse warnings ────────────────────────────────────────────────────

    def test_parse_warnings_default_empty(self) -> None:
        event = self._make_event()
        assert event.parse_warnings == []

    def test_parse_warnings_stored_correctly(self) -> None:
        event = self._make_event(parse_warnings=["field 'pid' not int: 'abc'"])
        assert len(event.parse_warnings) == 1
        assert "pid" in event.parse_warnings[0]

    # ── Extra fields ──────────────────────────────────────────────────────

    def test_extra_fields_default_empty(self) -> None:
        event = self._make_event()
        assert event.extra_fields == {}

    def test_extra_fields_preserved(self) -> None:
        event = self._make_event(extra_fields={"session_id": "sess-123"})
        assert event.extra_fields["session_id"] == "sess-123"

    # ── Serialisation ─────────────────────────────────────────────────────

    def test_model_dump_contains_all_schema_keys(self) -> None:
        event = self._make_event()
        dumped = event.model_dump(mode="json")
        required_keys = {
            "event_id", "timestamp", "source", "event_type", "host",
            "user", "resource", "action", "result", "normalizer_version",
            "parse_warnings", "extra_fields", "normalized_at",
        }
        assert required_keys.issubset(dumped.keys())

    def test_model_dump_json_serialisable(self) -> None:
        event = self._make_event(
            process="cmd.exe",
            src_ip="10.0.0.1",
            port=443,
        )
        json_str = json.dumps(event.model_dump(mode="json"), default=str)
        parsed = json.loads(json_str)
        assert parsed["process"] == "cmd.exe"


# ===========================================================================
# RawRecord
# ===========================================================================

class TestRawRecord:
    """Tests for the RawRecord container model."""

    def _make_record(self, **overrides) -> RawRecord:
        defaults = dict(
            source="hospital_server",
            source_file="/logs/hospital_server.jsonl",
            line_number=1,
            raw_dict={"event_type": "ProcessCreate"},
            raw_line='{"event_type":"ProcessCreate"}',
        )
        defaults.update(overrides)
        return RawRecord(**defaults)

    def test_construction_succeeds(self) -> None:
        record = self._make_record()
        assert record.source == "hospital_server"
        assert record.line_number == 1

    def test_received_at_auto_set(self) -> None:
        record = self._make_record()
        assert record.received_at is not None
        assert record.received_at.tzinfo == UTC

    def test_line_number_must_be_positive(self) -> None:
        with pytest.raises(ValidationError):
            self._make_record(line_number=0)

    def test_raw_dict_preserved(self) -> None:
        raw = {"foo": "bar", "nested": {"x": 1}}
        record = self._make_record(raw_dict=raw)
        assert record.raw_dict["foo"] == "bar"
        assert record.raw_dict["nested"]["x"] == 1


# ===========================================================================
# ParseStats
# ===========================================================================

class TestParseStats:
    """Tests for ParseStats counters and computed properties."""

    def test_all_counters_default_zero(self) -> None:
        stats = ParseStats(source="hospital_server")
        assert stats.total_lines_read == 0
        assert stats.events_normalized == 0
        assert stats.parse_errors == 0
        assert stats.validation_errors == 0
        assert stats.warnings_emitted == 0

    def test_error_rate_zero_when_no_lines(self) -> None:
        stats = ParseStats(source="ot_node")
        assert stats.error_rate == 0.0

    def test_error_rate_computed_correctly(self) -> None:
        stats = ParseStats(
            source="hospital_server",
            total_lines_read=100,
            parse_errors=3,
            validation_errors=2,
        )
        assert stats.error_rate == pytest.approx(0.05)

    def test_success_rate_is_complement_of_error_rate(self) -> None:
        stats = ParseStats(
            source="hospital_server",
            total_lines_read=100,
            parse_errors=10,
        )
        assert stats.success_rate == pytest.approx(1.0 - stats.error_rate)


# ===========================================================================
# ParseReport
# ===========================================================================

class TestParseReport:
    """Tests for ParseReport aggregate model."""

    def test_construction_with_defaults(self) -> None:
        report = ParseReport(run_id="run-001")
        assert report.run_id == "run-001"
        assert report.total_events_normalized == 0
        assert report.completed_at is None

    def test_duration_none_while_running(self) -> None:
        report = ParseReport(run_id="run-002")
        assert report.duration_seconds is None

    def test_duration_calculated_after_completion(self) -> None:
        start = datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC)
        end = datetime(2024, 1, 1, 0, 0, 30, tzinfo=UTC)
        report = ParseReport(run_id="run-003", started_at=start, completed_at=end)
        assert report.duration_seconds == pytest.approx(30.0)

    def test_overall_error_rate_with_stats(self) -> None:
        stats = ParseStats(
            source="hospital_server",
            total_lines_read=200,
            parse_errors=10,
            events_normalized=190,
        )
        report = ParseReport(run_id="run-004", per_source_stats=[stats])
        assert report.overall_error_rate == pytest.approx(0.05)

    def test_overall_error_rate_zero_when_no_stats(self) -> None:
        report = ParseReport(run_id="run-005")
        assert report.overall_error_rate == 0.0
