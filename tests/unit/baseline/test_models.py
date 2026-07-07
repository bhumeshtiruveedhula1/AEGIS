"""
tests/unit/baseline/test_models.py
===================================
Unit tests for all Module 2.1 Pydantic models.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from backend.baseline.models import (
    BASELINE_SCHEMA_VERSION,
    AuthBaseline,
    BaselineBuildReport,
    BaselineManifest,
    BaselineProfile,
    CategoricalStats,
    EntityBaseline,
    EntityKey,
    ManifestEntry,
    ModbusBaseline,
    NetworkBaseline,
    NumericStats,
    ProcessBaseline,
    TimePattern,
)


# ===========================================================================
# EntityKey
# ===========================================================================

class TestEntityKey:

    def test_valid_user_key(self) -> None:
        key = EntityKey(entity_type="user", entity_id="svc-iis")
        assert key.entity_type == "user"
        assert key.entity_id == "svc-iis"

    def test_valid_host_key(self) -> None:
        key = EntityKey(entity_type="host", entity_id="hospital-server-01")
        assert key.entity_type == "host"

    def test_valid_source_key(self) -> None:
        key = EntityKey(entity_type="source", entity_id="hospital_server")
        assert key.entity_type == "source"

    def test_valid_user_host_key(self) -> None:
        key = EntityKey(entity_type="user_host", entity_id="svc-iis::hospital-server-01")
        assert key.entity_type == "user_host"

    def test_entity_id_lowercased(self) -> None:
        key = EntityKey(entity_type="user", entity_id="SVC-IIS")
        assert key.entity_id == "svc-iis"

    def test_entity_id_stripped(self) -> None:
        key = EntityKey(entity_type="host", entity_id="  hospital-01  ")
        assert key.entity_id == "hospital-01"

    def test_entity_type_lowercased(self) -> None:
        key = EntityKey(entity_type="USER", entity_id="svc-iis")
        assert key.entity_type == "user"

    def test_invalid_entity_type_raises(self) -> None:
        with pytest.raises(ValueError, match="entity_type"):
            EntityKey(entity_type="invalid", entity_id="test")

    def test_empty_entity_id_raises(self) -> None:
        with pytest.raises(ValueError, match="entity_id"):
            EntityKey(entity_type="user", entity_id="")

    def test_whitespace_only_entity_id_raises(self) -> None:
        with pytest.raises(ValueError):
            EntityKey(entity_type="user", entity_id="   ")

    def test_storage_key_format(self) -> None:
        key = EntityKey(entity_type="user", entity_id="svc-iis")
        assert key.storage_key == "user__svc-iis"

    def test_storage_key_replaces_slash(self) -> None:
        key = EntityKey(entity_type="host", entity_id="host/sub")
        assert "/" not in key.storage_key

    def test_equality(self) -> None:
        k1 = EntityKey(entity_type="user", entity_id="svc-iis")
        k2 = EntityKey(entity_type="user", entity_id="svc-iis")
        assert k1 == k2

    def test_inequality_different_type(self) -> None:
        k1 = EntityKey(entity_type="user", entity_id="svc-iis")
        k2 = EntityKey(entity_type="host", entity_id="svc-iis")
        assert k1 != k2

    def test_hashable_usable_as_dict_key(self) -> None:
        d: dict[EntityKey, int] = {}
        k = EntityKey(entity_type="user", entity_id="admin")
        d[k] = 42
        assert d[k] == 42


# ===========================================================================
# NumericStats
# ===========================================================================

class TestNumericStats:

    def test_empty_stats(self) -> None:
        s = NumericStats(field_name="pid", count=0)
        assert not s.is_populated
        assert s.mean is None
        assert s.std is None

    def test_populated_stats(self) -> None:
        s = NumericStats(
            field_name="pid",
            count=10,
            mean=500.0,
            std=50.0,
            minimum=400.0,
            maximum=600.0,
            p50=500.0,
        )
        assert s.is_populated
        assert s.mean == 500.0

    def test_count_zero_is_not_populated(self) -> None:
        s = NumericStats(field_name="port", count=0)
        assert not s.is_populated


# ===========================================================================
# CategoricalStats
# ===========================================================================

class TestCategoricalStats:

    def test_empty_stats(self) -> None:
        s = CategoricalStats(field_name="process")
        assert not s.is_populated
        assert s.count == 0

    def test_populated_stats(self) -> None:
        s = CategoricalStats(
            field_name="process",
            count=100,
            total_unique_values=5,
            value_frequencies={"w3wp.exe": 80, "cmd.exe": 20},
            seen_values={"w3wp.exe", "cmd.exe"},
        )
        assert s.is_populated

    def test_top_values_returns_sorted(self) -> None:
        s = CategoricalStats(
            field_name="process",
            count=10,
            value_frequencies={"cmd.exe": 1, "w3wp.exe": 7, "sqlservr.exe": 2},
        )
        top = s.top_values(n=2)
        assert top[0][0] == "w3wp.exe"
        assert top[1][0] == "sqlservr.exe"


# ===========================================================================
# TimePattern
# ===========================================================================

class TestTimePattern:

    def test_default_empty_pattern(self) -> None:
        tp = TimePattern()
        assert len(tp.hourly_buckets) == 24
        assert len(tp.daily_buckets) == 7
        assert all(b == 0 for b in tp.hourly_buckets)
        assert tp.total_events == 0

    def test_peak_hour_none_when_no_events(self) -> None:
        tp = TimePattern()
        assert tp.peak_hour is None

    def test_peak_hour_correct(self) -> None:
        hourly = [0] * 24
        hourly[9] = 50
        hourly[14] = 30
        tp = TimePattern(hourly_buckets=hourly, total_events=80)
        assert tp.peak_hour == 9

    def test_active_hours(self) -> None:
        hourly = [0] * 24
        hourly[8] = 5
        hourly[17] = 3
        tp = TimePattern(hourly_buckets=hourly, total_events=8)
        assert tp.active_hours == [8, 17]

    def test_invalid_hourly_length_raises(self) -> None:
        with pytest.raises(ValueError):
            TimePattern(hourly_buckets=[0] * 12)

    def test_invalid_daily_length_raises(self) -> None:
        with pytest.raises(ValueError):
            TimePattern(daily_buckets=[0] * 5)


# ===========================================================================
# NetworkBaseline
# ===========================================================================

class TestNetworkBaseline:

    def test_basic_construction(self) -> None:
        nb = NetworkBaseline(
            unique_src_ips={"10.0.1.10"},
            unique_dst_ips={"10.0.1.20"},
            port_distribution={"443": 50},
            protocol_distribution={"tcp": 50},
            connection_count=50,
        )
        assert nb.connection_count == 50
        assert "10.0.1.10" in nb.unique_src_ips

    def test_bytes_out_stats_optional(self) -> None:
        nb = NetworkBaseline()
        assert nb.bytes_out_stats is None


# ===========================================================================
# ProcessBaseline
# ===========================================================================

class TestProcessBaseline:

    def test_basic_construction(self) -> None:
        pb = ProcessBaseline(
            unique_processes={"w3wp.exe", "sqlservr.exe"},
            process_frequency={"w3wp.exe": 100, "sqlservr.exe": 20},
            process_event_count=120,
        )
        assert "w3wp.exe" in pb.unique_processes

    def test_parent_child_pairs(self) -> None:
        pb = ProcessBaseline(
            parent_child_pairs={"svchost.exe__w3wp.exe"}
        )
        assert "svchost.exe__w3wp.exe" in pb.parent_child_pairs


# ===========================================================================
# ModbusBaseline
# ===========================================================================

class TestModbusBaseline:

    def test_basic_construction(self) -> None:
        mb = ModbusBaseline(
            function_code_distribution={"FC03": 90, "FC06": 10},
            known_supervisory_hosts={"192.168.10.5"},
            modbus_event_count=100,
        )
        assert "FC03" in mb.function_code_distribution

    def test_register_stats_optional(self) -> None:
        mb = ModbusBaseline()
        assert mb.register_stats is None


# ===========================================================================
# AuthBaseline
# ===========================================================================

class TestAuthBaseline:

    def test_failure_rate_zero_with_no_events(self) -> None:
        ab = AuthBaseline()
        assert ab.failure_rate == 0.0

    def test_failure_rate_calculation(self) -> None:
        ab = AuthBaseline(failure_count=20, success_count=80)
        assert abs(ab.failure_rate - 0.2) < 1e-9

    def test_failure_rate_all_failures(self) -> None:
        ab = AuthBaseline(failure_count=10, success_count=0)
        assert ab.failure_rate == 1.0


# ===========================================================================
# EntityBaseline
# ===========================================================================

class TestEntityBaseline:

    def _key(self) -> EntityKey:
        return EntityKey(entity_type="user", entity_id="svc-iis")

    def test_minimal_construction(self) -> None:
        eb = EntityBaseline(entity_key=self._key())
        assert eb.observation_count == 0
        assert eb.baseline_version == BASELINE_SCHEMA_VERSION

    def test_failure_rate_zero_default(self) -> None:
        eb = EntityBaseline(entity_key=self._key())
        assert eb.failure_rate == 0.0

    def test_failure_rate_with_results(self) -> None:
        eb = EntityBaseline(
            entity_key=self._key(),
            result_distribution={"success": 80, "failure": 20},
        )
        assert abs(eb.failure_rate - 0.2) < 1e-9

    def test_observation_window_none_when_no_timestamps(self) -> None:
        eb = EntityBaseline(entity_key=self._key())
        assert eb.observation_window_days is None

    def test_observation_window_days(self) -> None:
        from datetime import timedelta
        first = datetime(2024, 1, 1, tzinfo=UTC)
        last = datetime(2024, 1, 11, tzinfo=UTC)
        eb = EntityBaseline(
            entity_key=self._key(),
            first_seen=first,
            last_seen=last,
        )
        assert abs(eb.observation_window_days - 10.0) < 0.001

    def test_none_sub_baselines(self) -> None:
        eb = EntityBaseline(entity_key=self._key())
        assert eb.network is None
        assert eb.process is None
        assert eb.modbus is None
        assert eb.auth is None


# ===========================================================================
# BaselineProfile
# ===========================================================================

class TestBaselineProfile:

    def test_entity_count(self) -> None:
        key = EntityKey(entity_type="user", entity_id="svc-iis")
        eb = EntityBaseline(entity_key=key)
        profile = BaselineProfile(
            profile_id="test-profile-1",
            entities={"user__svc-iis": eb},
        )
        assert profile.entity_count == 1

    def test_get_entity_returns_correct_baseline(self) -> None:
        key = EntityKey(entity_type="user", entity_id="svc-iis")
        eb = EntityBaseline(entity_key=key, observation_count=50)
        profile = BaselineProfile(
            profile_id="test-profile-1",
            entities={"user__svc-iis": eb},
        )
        result = profile.get_entity(key)
        assert result is not None
        assert result.observation_count == 50

    def test_get_entity_returns_none_for_missing(self) -> None:
        profile = BaselineProfile(profile_id="test-profile-1")
        missing_key = EntityKey(entity_type="host", entity_id="nonexistent")
        assert profile.get_entity(missing_key) is None

    def test_all_entity_keys_returns_correct_count(self) -> None:
        eb1 = EntityBaseline(entity_key=EntityKey(entity_type="user", entity_id="admin"))
        eb2 = EntityBaseline(entity_key=EntityKey(entity_type="host", entity_id="srv-01"))
        profile = BaselineProfile(
            profile_id="test-profile-1",
            entities={"user__admin": eb1, "host__srv-01": eb2},
        )
        keys = profile.all_entity_keys()
        assert len(keys) == 2


# ===========================================================================
# BaselineManifest
# ===========================================================================

class TestBaselineManifest:

    def test_empty_manifest(self) -> None:
        m = BaselineManifest()
        assert m.latest_profile_id is None
        assert m.profiles == []

    def test_add_entry_updates_latest(self) -> None:
        m = BaselineManifest()
        profile = BaselineProfile(profile_id="p1", total_events_processed=100)
        m.add_entry(profile)
        assert m.latest_profile_id == "p1"
        assert len(m.profiles) == 1

    def test_add_entry_newest_first(self) -> None:
        m = BaselineManifest()
        p1 = BaselineProfile(profile_id="p1", total_events_processed=10)
        p2 = BaselineProfile(profile_id="p2", total_events_processed=20)
        m.add_entry(p1)
        m.add_entry(p2)
        assert m.profiles[0].profile_id == "p2"
        assert m.latest_profile_id == "p2"


# ===========================================================================
# BaselineBuildReport
# ===========================================================================

class TestBaselineBuildReport:

    def test_duration_none_before_completion(self) -> None:
        r = BaselineBuildReport(profile_id="p1")
        assert r.duration_seconds is None

    def test_duration_computed_correctly(self) -> None:
        from datetime import timedelta
        start = datetime(2024, 1, 1, 10, 0, 0, tzinfo=UTC)
        end = datetime(2024, 1, 1, 10, 0, 5, tzinfo=UTC)
        r = BaselineBuildReport(
            profile_id="p1",
            started_at=start,
            completed_at=end,
        )
        assert r.duration_seconds == 5.0
