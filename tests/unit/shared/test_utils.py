"""
tests/unit/shared/test_utils.py
================================
Unit tests for all utility modules in backend.shared.utils.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from backend.shared.utils.datetime_utils import (
    format_iso8601,
    is_within_window,
    parse_iso8601,
    seconds_between,
    to_utc,
    truncate_to_hour,
    utcnow,
)
from backend.shared.utils.id_utils import (
    generate_id,
    id_prefix,
    is_valid_id,
    validate_id,
)
from backend.shared.utils.json_utils import (
    read_jsonl,
    safe_dumps,
    safe_loads,
    safe_loads_or_none,
    write_jsonl,
)
from backend.shared.utils.validation_utils import (
    validate_anomaly_score,
    validate_email,
    validate_hostname,
    validate_mitre_technique_id,
    validate_nonempty_string,
)


# ===========================================================================
# DateTime Utils
# ===========================================================================
class TestUTCNow:
    def test_returns_utc_aware_datetime(self) -> None:
        now = utcnow()
        assert now.tzinfo is not None
        assert now.tzinfo == UTC or now.utcoffset() == timedelta(0)

    def test_returns_recent_time(self) -> None:
        before = datetime.now(UTC)
        now = utcnow()
        after = datetime.now(UTC)
        assert before <= now <= after


class TestToUTC:
    def test_converts_naive_datetime_to_utc(self) -> None:
        naive = datetime(2024, 1, 15, 10, 30, 0)  # no tzinfo
        result = to_utc(naive)
        assert result.tzinfo == UTC

    def test_converts_aware_non_utc_to_utc(self) -> None:
        ist = timezone(timedelta(hours=5, minutes=30))
        aware = datetime(2024, 1, 15, 16, 0, 0, tzinfo=ist)
        result = to_utc(aware)
        assert result.hour == 10  # 16:00 IST = 10:30 UTC
        assert result.minute == 30

    def test_raises_for_non_datetime(self) -> None:
        with pytest.raises(TypeError):
            to_utc("2024-01-15")  # type: ignore[arg-type]


class TestParseISO8601:
    def test_parses_z_suffix(self) -> None:
        dt = parse_iso8601("2024-01-15T10:30:00Z")
        assert dt.year == 2024
        assert dt.month == 1
        assert dt.day == 15
        assert dt.tzinfo is not None

    def test_parses_offset_string(self) -> None:
        dt = parse_iso8601("2024-01-15T16:00:00+05:30")
        assert dt.tzinfo is not None
        # Should be UTC after conversion
        assert dt.utcoffset() == timedelta(0)

    def test_raises_for_invalid_string(self) -> None:
        with pytest.raises(ValueError):
            parse_iso8601("not-a-date")


class TestFormatISO8601:
    def test_formats_to_z_suffix(self) -> None:
        dt = datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC)
        result = format_iso8601(dt)
        assert result.endswith("Z")
        assert "2024-01-15T10:30:00" in result


class TestTruncateToHour:
    def test_zeros_minutes_seconds(self) -> None:
        dt = datetime(2024, 1, 15, 10, 47, 33, 123456, tzinfo=UTC)
        result = truncate_to_hour(dt)
        assert result.minute == 0
        assert result.second == 0
        assert result.microsecond == 0
        assert result.hour == 10


class TestIsWithinWindow:
    def test_returns_true_for_event_in_window(self) -> None:
        start = datetime(2024, 1, 1, tzinfo=UTC)
        end = datetime(2024, 1, 8, tzinfo=UTC)
        event = datetime(2024, 1, 4, tzinfo=UTC)
        assert is_within_window(event, start, end) is True

    def test_returns_false_for_event_before_window(self) -> None:
        start = datetime(2024, 1, 5, tzinfo=UTC)
        end = datetime(2024, 1, 8, tzinfo=UTC)
        event = datetime(2024, 1, 1, tzinfo=UTC)
        assert is_within_window(event, start, end) is False

    def test_window_is_inclusive_start_exclusive_end(self) -> None:
        start = datetime(2024, 1, 1, tzinfo=UTC)
        end = datetime(2024, 1, 2, tzinfo=UTC)
        assert is_within_window(start, start, end) is True
        assert is_within_window(end, start, end) is False


class TestSecondsBetween:
    def test_returns_positive_for_forward_time(self) -> None:
        start = datetime(2024, 1, 1, tzinfo=UTC)
        end = datetime(2024, 1, 1, 0, 1, 30, tzinfo=UTC)  # 90 seconds later
        assert seconds_between(start, end) == pytest.approx(90.0)

    def test_returns_negative_for_backward_time(self) -> None:
        start = datetime(2024, 1, 1, 0, 1, 0, tzinfo=UTC)
        end = datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC)
        assert seconds_between(start, end) < 0


# ===========================================================================
# ID Utils
# ===========================================================================
class TestGenerateId:
    def test_generates_uuid4_string(self) -> None:
        id_ = generate_id()
        assert isinstance(id_, str)
        assert len(id_) == 36  # 8-4-4-4-12 format

    def test_generates_unique_ids(self) -> None:
        ids = {generate_id() for _ in range(100)}
        assert len(ids) == 100  # no collisions


class TestIsValidId:
    def test_valid_uuid4_returns_true(self) -> None:
        assert is_valid_id("550e8400-e29b-41d4-a716-446655440000") is True

    def test_generated_id_is_valid(self) -> None:
        assert is_valid_id(generate_id()) is True

    def test_empty_string_returns_false(self) -> None:
        assert is_valid_id("") is False

    def test_non_string_returns_false(self) -> None:
        assert is_valid_id(12345) is False  # type: ignore[arg-type]

    def test_invalid_uuid_returns_false(self) -> None:
        assert is_valid_id("not-a-uuid") is False


class TestValidateId:
    def test_valid_uuid_passes(self) -> None:
        uuid = "550e8400-e29b-41d4-a716-446655440000"
        assert validate_id(uuid) == uuid

    def test_invalid_uuid_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid UUID v4"):
            validate_id("bad-id", field_name="alert_id")


class TestIdPrefix:
    def test_prefixes_id_correctly(self) -> None:
        uuid = "550e8400-e29b-41d4-a716-446655440000"
        result = id_prefix("alert", uuid)
        assert result == f"alert_{uuid}"


# ===========================================================================
# JSON Utils
# ===========================================================================
class TestSafeDumps:
    def test_serialises_plain_dict(self) -> None:
        result = safe_dumps({"key": "value"})
        assert '"key":"value"' in result

    def test_serialises_datetime_to_iso8601(self) -> None:
        dt = datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC)
        result = safe_dumps({"ts": dt})
        assert "2024-01-15" in result
        assert "Z" in result

    def test_serialises_enum_to_value(self) -> None:
        from enum import StrEnum

        class Color(StrEnum):
            RED = "red"

        result = safe_dumps({"color": Color.RED})
        assert '"red"' in result

    def test_serialises_path(self) -> None:
        import json as _json

        p = Path("/tmp/test")
        result = safe_dumps({"path": p})
        # Decode the JSON to get the actual stored value and compare
        # (raw JSON escapes backslashes on Windows: \tmp\test -> \\tmp\\test)
        decoded = _json.loads(result)
        assert decoded["path"] == str(p)


class TestSafeLoads:
    def test_parses_valid_json(self) -> None:
        obj = safe_loads('{"key": "value", "num": 42}')
        assert obj["key"] == "value"
        assert obj["num"] == 42

    def test_raises_for_empty_string(self) -> None:
        with pytest.raises(ValueError):
            safe_loads("")

    def test_raises_for_invalid_json(self) -> None:
        with pytest.raises(json.JSONDecodeError):
            safe_loads("{invalid json}")


class TestSafeLoadsOrNone:
    def test_returns_none_for_none_input(self) -> None:
        assert safe_loads_or_none(None) is None

    def test_returns_none_for_invalid_json(self) -> None:
        assert safe_loads_or_none("{bad}") is None

    def test_returns_parsed_for_valid_json(self) -> None:
        result = safe_loads_or_none('{"a": 1}')
        assert result == {"a": 1}


class TestJSONLReadWrite:
    def test_write_and_read_jsonl(self, tmp_path: Path) -> None:
        records = [
            {"id": 1, "name": "alice"},
            {"id": 2, "name": "bob"},
        ]
        filepath = tmp_path / "test.jsonl"
        count = write_jsonl(records, filepath)
        assert count == 2
        assert filepath.exists()

        read_records = read_jsonl(filepath)
        assert len(read_records) == 2
        assert read_records[0]["name"] == "alice"

    def test_write_creates_parent_dirs(self, tmp_path: Path) -> None:
        filepath = tmp_path / "nested" / "dir" / "data.jsonl"
        write_jsonl([{"test": True}], filepath)
        assert filepath.exists()


# ===========================================================================
# Validation Utils
# ===========================================================================
class TestValidateNonemptyString:
    def test_valid_string_passes(self) -> None:
        assert validate_nonempty_string("  hello  ") == "hello"

    def test_empty_string_raises(self) -> None:
        with pytest.raises(ValueError):
            validate_nonempty_string("")

    def test_whitespace_only_raises(self) -> None:
        with pytest.raises(ValueError):
            validate_nonempty_string("   ")

    def test_non_string_raises(self) -> None:
        with pytest.raises(ValueError):
            validate_nonempty_string(123)  # type: ignore[arg-type]


class TestValidateHostname:
    def test_valid_hostname_passes(self) -> None:
        assert validate_hostname("web-server-01") == "web-server-01"

    def test_ipv4_passes(self) -> None:
        assert validate_hostname("192.168.1.100") == "192.168.1.100"

    def test_hostname_lowercased(self) -> None:
        assert validate_hostname("WEB-SERVER-01") == "web-server-01"

    def test_invalid_hostname_raises(self) -> None:
        with pytest.raises(ValueError):
            validate_hostname("$$invalid$$")


class TestValidateMITRETechniqueId:
    def test_valid_technique_passes(self) -> None:
        assert validate_mitre_technique_id("T1059") == "T1059"

    def test_valid_subtechnique_passes(self) -> None:
        assert validate_mitre_technique_id("T1059.001") == "T1059.001"

    def test_lowercase_input_uppercased(self) -> None:
        assert validate_mitre_technique_id("t1059") == "T1059"

    def test_invalid_format_raises(self) -> None:
        with pytest.raises(ValueError):
            validate_mitre_technique_id("TXXXX")

    def test_tactic_id_raises(self) -> None:
        with pytest.raises(ValueError):
            validate_mitre_technique_id("TA0002")


class TestValidateAnomalyScore:
    def test_valid_score_passes(self) -> None:
        assert validate_anomaly_score(0.5) == pytest.approx(0.5)

    def test_boundary_values_pass(self) -> None:
        assert validate_anomaly_score(-1.0) == pytest.approx(-1.0)
        assert validate_anomaly_score(1.0) == pytest.approx(1.0)

    def test_score_above_1_raises(self) -> None:
        with pytest.raises(ValueError):
            validate_anomaly_score(1.5)

    def test_score_below_minus1_raises(self) -> None:
        with pytest.raises(ValueError):
            validate_anomaly_score(-1.5)


class TestValidateEmail:
    def test_valid_email_passes(self) -> None:
        assert validate_email("analyst@soc.local") == "analyst@soc.local"

    def test_email_lowercased(self) -> None:
        assert validate_email("Analyst@SOC.LOCAL") == "analyst@soc.local"

    def test_invalid_email_raises(self) -> None:
        with pytest.raises(ValueError):
            validate_email("not-an-email")
