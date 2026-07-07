"""
tests/unit/baseline/test_statistics.py
=======================================
Unit tests for the pure statistics computation functions.
All tests are deterministic — no randomness, no I/O.
"""

from __future__ import annotations

import math
from datetime import UTC, datetime, timedelta

import pytest

from backend.baseline.models import EntityKey
from backend.baseline.statistics import (
    compute_auth_baseline,
    compute_categorical_stats,
    compute_entity_baseline,
    compute_modbus_baseline,
    compute_network_baseline,
    compute_numeric_stats,
    compute_process_baseline,
    compute_time_pattern,
)
from tests.unit.baseline.conftest import (
    FIXED_DT,
    make_dc_event,
    make_hospital_batch,
    make_hospital_event,
    make_ot_batch,
    make_ot_event,
)


# ===========================================================================
# compute_numeric_stats
# ===========================================================================

class TestComputeNumericStats:

    def test_empty_list_returns_zero_count(self) -> None:
        s = compute_numeric_stats("pid", [])
        assert s.count == 0
        assert s.mean is None

    def test_single_value_mean_equals_value(self) -> None:
        s = compute_numeric_stats("pid", [42])
        assert s.count == 1
        assert s.mean == 42.0
        assert s.minimum == 42.0
        assert s.maximum == 42.0

    def test_two_values_mean(self) -> None:
        s = compute_numeric_stats("pid", [10, 20])
        assert abs(s.mean - 15.0) < 1e-9

    def test_std_zero_for_single_value(self) -> None:
        s = compute_numeric_stats("pid", [100])
        assert s.std == 0.0

    def test_known_std(self) -> None:
        # Sample std of [2,4,4,4,5,5,7,9] — Bessel's correction (n-1) gives ≈2.138
        # Population std would be 2.0, but we use sample std for unbiased estimation
        import math
        vals = [2, 4, 4, 4, 5, 5, 7, 9]
        mean = sum(vals) / len(vals)
        expected_std = math.sqrt(sum((x - mean) ** 2 for x in vals) / (len(vals) - 1))
        s = compute_numeric_stats("pid", vals)
        assert abs(s.std - expected_std) < 1e-9

    def test_min_max_correct(self) -> None:
        s = compute_numeric_stats("port", [80, 443, 8080, 22])
        assert s.minimum == 22.0
        assert s.maximum == 8080.0

    def test_p50_median_of_sorted(self) -> None:
        s = compute_numeric_stats("pid", [1, 2, 3, 4, 5])
        assert s.p50 == 3.0

    def test_p25_p75(self) -> None:
        values = list(range(1, 101))  # 1–100
        s = compute_numeric_stats("bytes", values)
        assert abs(s.p25 - 25.75) < 1.0   # approximate
        assert abs(s.p75 - 75.25) < 1.0

    def test_p99_close_to_max(self) -> None:
        values = list(range(1, 101))
        s = compute_numeric_stats("bytes", values)
        assert s.p99 >= 98.0

    def test_count_correct(self) -> None:
        s = compute_numeric_stats("pid", [1, 2, 3, 4, 5, 6, 7])
        assert s.count == 7

    def test_field_name_preserved(self) -> None:
        s = compute_numeric_stats("modbus_register", [15])
        assert s.field_name == "modbus_register"

    def test_welford_m2_stored(self) -> None:
        s = compute_numeric_stats("bytes_out", [100, 200, 300])
        # welford_m2 is now a proper Pydantic field (not a private class attr)
        # so it survives JSON round-trips and incremental updates remain correct.
        assert s.welford_m2 is not None
        assert s.welford_m2 > 0

    def test_welford_m2_survives_json_roundtrip(self) -> None:
        """welford_m2 must persist through serialisation for correct incremental updates."""
        s = compute_numeric_stats("bytes_out", [100, 200, 300])
        original_m2 = s.welford_m2
        # Round-trip through JSON (as happens when baseline is saved and reloaded)
        from backend.baseline.models import NumericStats
        restored = NumericStats.model_validate_json(s.model_dump_json())
        assert restored.welford_m2 == original_m2, (
            "welford_m2 was lost during JSON round-trip — "
            "incremental std would be wrong after save/load"
        )


# ===========================================================================
# compute_categorical_stats
# ===========================================================================

class TestComputeCategoricalStats:

    def test_empty_list(self) -> None:
        s = compute_categorical_stats("process", [])
        assert s.count == 0
        assert not s.is_populated

    def test_single_value(self) -> None:
        s = compute_categorical_stats("process", ["w3wp.exe"])
        assert s.count == 1
        assert s.total_unique_values == 1
        assert "w3wp.exe" in s.seen_values

    def test_frequency_counts_correct(self) -> None:
        values = ["w3wp.exe"] * 70 + ["cmd.exe"] * 30
        s = compute_categorical_stats("process", values)
        assert s.value_frequencies["w3wp.exe"] == 70
        assert s.value_frequencies["cmd.exe"] == 30

    def test_max_values_limits_seen_set(self) -> None:
        values = [f"proc-{i}.exe" for i in range(200)]
        s = compute_categorical_stats("process", values, max_values=50)
        assert len(s.seen_values) <= 50

    def test_total_unique_values_correct(self) -> None:
        values = ["a", "b", "c", "a", "b"]
        s = compute_categorical_stats("field", values)
        assert s.total_unique_values == 3

    def test_top_values_sorted_by_frequency(self) -> None:
        values = ["a"] * 3 + ["b"] * 7 + ["c"] * 1
        s = compute_categorical_stats("field", values)
        top = s.top_values(n=2)
        assert top[0][0] == "b"
        assert top[1][0] == "a"

    def test_field_name_preserved(self) -> None:
        s = compute_categorical_stats("protocol", ["tcp"])
        assert s.field_name == "protocol"


# ===========================================================================
# compute_time_pattern
# ===========================================================================

class TestComputeTimePattern:

    def test_empty_timestamps(self) -> None:
        tp = compute_time_pattern([])
        assert tp.total_events == 0
        assert all(b == 0 for b in tp.hourly_buckets)

    def test_single_timestamp_increments_hour_bucket(self) -> None:
        ts = datetime(2024, 1, 15, 9, 30, tzinfo=UTC)   # Monday 09:30 UTC
        tp = compute_time_pattern([ts])
        assert tp.hourly_buckets[9] == 1
        assert tp.total_events == 1

    def test_single_timestamp_increments_daily_bucket(self) -> None:
        monday_ts = datetime(2024, 1, 15, 9, 30, tzinfo=UTC)  # Monday
        tp = compute_time_pattern([monday_ts])
        assert tp.daily_buckets[0] == 1  # 0=Monday

    def test_multiple_timestamps_accumulate(self) -> None:
        timestamps = [
            datetime(2024, 1, 15, 9, 0, tzinfo=UTC),
            datetime(2024, 1, 15, 9, 30, tzinfo=UTC),
            datetime(2024, 1, 15, 14, 0, tzinfo=UTC),
        ]
        tp = compute_time_pattern(timestamps)
        assert tp.hourly_buckets[9] == 2
        assert tp.hourly_buckets[14] == 1
        assert tp.total_events == 3

    def test_peak_hour_correct(self) -> None:
        timestamps = [datetime(2024, 1, 15, 3, 0, tzinfo=UTC)] * 5 + \
                     [datetime(2024, 1, 15, 9, 0, tzinfo=UTC)] * 2
        tp = compute_time_pattern(timestamps)
        assert tp.peak_hour == 3

    def test_hourly_array_length(self) -> None:
        tp = compute_time_pattern([datetime(2024, 1, 1, 0, tzinfo=UTC)])
        assert len(tp.hourly_buckets) == 24

    def test_daily_array_length(self) -> None:
        tp = compute_time_pattern([datetime(2024, 1, 1, 0, tzinfo=UTC)])
        assert len(tp.daily_buckets) == 7


# ===========================================================================
# compute_network_baseline
# ===========================================================================

class TestComputeNetworkBaseline:

    def test_returns_none_for_no_network_events(self) -> None:
        events = [
            make_hospital_event({"src_ip": None, "dst_ip": None, "port": None})
        ]
        result = compute_network_baseline(events)
        assert result is None

    def test_unique_dst_ips_collected(self) -> None:
        events = [
            make_hospital_event({"dst_ip": "10.0.1.20"}),
            make_hospital_event({"dst_ip": "10.0.1.21"}),
            make_hospital_event({"dst_ip": "10.0.1.20"}),  # duplicate
        ]
        nb = compute_network_baseline(events)
        assert nb is not None
        assert nb.unique_dst_ips == {"10.0.1.20", "10.0.1.21"}

    def test_port_distribution(self) -> None:
        events = [
            make_hospital_event({"port": 443}),
            make_hospital_event({"port": 443}),
            make_hospital_event({"port": 80}),
        ]
        nb = compute_network_baseline(events)
        assert nb is not None
        assert nb.port_distribution.get("443") == 2
        assert nb.port_distribution.get("80") == 1

    def test_protocol_distribution(self) -> None:
        events = [
            make_hospital_event({"protocol": "tcp"}),
            make_hospital_event({"protocol": "tcp"}),
            make_hospital_event({"protocol": "udp"}),
        ]
        nb = compute_network_baseline(events)
        assert nb is not None
        assert nb.protocol_distribution["tcp"] == 2
        assert nb.protocol_distribution["udp"] == 1

    def test_bytes_out_stats_populated(self) -> None:
        events = [
            make_hospital_event({"bytes_out": 1000}),
            make_hospital_event({"bytes_out": 2000}),
        ]
        nb = compute_network_baseline(events)
        assert nb is not None
        assert nb.bytes_out_stats is not None
        assert abs(nb.bytes_out_stats.mean - 1500.0) < 1e-9

    def test_bytes_out_none_when_not_present(self) -> None:
        events = [make_hospital_event({"bytes_out": None})]
        nb = compute_network_baseline(events)
        # bytes_out_stats should be None since all bytes_out values are None
        assert nb is None or nb.bytes_out_stats is None

    def test_connection_count(self) -> None:
        events = make_hospital_batch(7)
        nb = compute_network_baseline(events)
        assert nb is not None
        assert nb.connection_count == 7


# ===========================================================================
# compute_process_baseline
# ===========================================================================

class TestComputeProcessBaseline:

    def test_returns_none_for_no_process_events(self) -> None:
        events = [make_hospital_event({"process": None})]
        result = compute_process_baseline(events)
        assert result is None

    def test_unique_processes_collected(self) -> None:
        events = [
            make_hospital_event({"process": "w3wp.exe"}),
            make_hospital_event({"process": "sqlservr.exe"}),
            make_hospital_event({"process": "w3wp.exe"}),
        ]
        pb = compute_process_baseline(events)
        assert pb is not None
        assert pb.unique_processes == {"w3wp.exe", "sqlservr.exe"}

    def test_process_frequency_correct(self) -> None:
        events = [make_hospital_event({"process": "w3wp.exe"})] * 10 + \
                 [make_hospital_event({"process": "cmd.exe"})] * 3
        pb = compute_process_baseline(events)
        assert pb is not None
        assert pb.process_frequency["w3wp.exe"] == 10
        assert pb.process_frequency["cmd.exe"] == 3

    def test_parent_child_pairs(self) -> None:
        events = [make_hospital_event({
            "parent_process": "svchost.exe",
            "process": "w3wp.exe",
        })]
        pb = compute_process_baseline(events)
        assert pb is not None
        assert "svchost.exe__w3wp.exe" in pb.parent_child_pairs

    def test_pid_stats_populated(self) -> None:
        events = [
            make_hospital_event({"pid": 1000}),
            make_hospital_event({"pid": 2000}),
        ]
        pb = compute_process_baseline(events)
        assert pb is not None
        assert pb.pid_stats is not None
        assert abs(pb.pid_stats.mean - 1500.0) < 1e-9


# ===========================================================================
# compute_modbus_baseline
# ===========================================================================

class TestComputeModbusBaseline:

    def test_returns_none_for_non_ot_events(self) -> None:
        events = [make_hospital_event()]
        result = compute_modbus_baseline(events)
        assert result is None

    def test_register_stats_populated(self) -> None:
        events = make_ot_batch(5, register_start=10)
        mb = compute_modbus_baseline(events)
        assert mb is not None
        assert mb.register_stats is not None
        assert mb.register_stats.minimum == 10.0
        assert mb.register_stats.maximum == 14.0

    def test_function_code_distribution(self) -> None:
        events = [
            make_ot_event({"modbus_function_code": "FC03"}),
            make_ot_event({"modbus_function_code": "FC03"}),
            make_ot_event({"modbus_function_code": "FC06"}),
        ]
        mb = compute_modbus_baseline(events)
        assert mb is not None
        assert mb.function_code_distribution["FC03"] == 2
        assert mb.function_code_distribution["FC06"] == 1

    def test_known_supervisory_hosts(self) -> None:
        events = [
            make_ot_event({"supervisory_host": "192.168.10.5"}),
            make_ot_event({"supervisory_host": "192.168.10.6"}),
        ]
        mb = compute_modbus_baseline(events)
        assert mb is not None
        assert "192.168.10.5" in mb.known_supervisory_hosts

    def test_modbus_event_count(self) -> None:
        events = make_ot_batch(8)
        mb = compute_modbus_baseline(events)
        assert mb is not None
        assert mb.modbus_event_count == 8


# ===========================================================================
# compute_auth_baseline
# ===========================================================================

class TestComputeAuthBaseline:

    def test_returns_none_for_non_auth_events(self) -> None:
        events = [
            make_hospital_event({"logon_type": None, "auth_package": None, "windows_event_id": None})
        ]
        result = compute_auth_baseline(events)
        assert result is None

    def test_logon_type_distribution(self) -> None:
        events = [
            make_dc_event({"logon_type": "network"}),
            make_dc_event({"logon_type": "network"}),
            make_dc_event({"logon_type": "interactive"}),
        ]
        ab = compute_auth_baseline(events)
        assert ab is not None
        assert ab.logon_type_distribution["network"] == 2
        assert ab.logon_type_distribution["interactive"] == 1

    def test_auth_package_distribution(self) -> None:
        events = [
            make_dc_event({"auth_package": "Kerberos"}),
            make_dc_event({"auth_package": "NTLM"}),
        ]
        ab = compute_auth_baseline(events)
        assert ab is not None
        assert "Kerberos" in ab.auth_package_distribution

    def test_failure_count(self) -> None:
        events = [
            make_dc_event({"result": "failure"}),
            make_dc_event({"result": "failure"}),
            make_dc_event({"result": "success"}),
        ]
        ab = compute_auth_baseline(events)
        assert ab is not None
        assert ab.failure_count == 2
        assert ab.success_count == 1


# ===========================================================================
# compute_entity_baseline — the main entry point
# ===========================================================================

class TestComputeEntityBaseline:

    def test_empty_events_returns_zero_count(self) -> None:
        key = EntityKey(entity_type="user", entity_id="svc-iis")
        eb = compute_entity_baseline(key, [])
        assert eb.observation_count == 0

    def test_observation_count_correct(self) -> None:
        key = EntityKey(entity_type="user", entity_id="svc-iis")
        events = make_hospital_batch(25)
        eb = compute_entity_baseline(key, events)
        assert eb.observation_count == 25

    def test_entity_key_preserved(self) -> None:
        key = EntityKey(entity_type="host", entity_id="hospital-server-01")
        eb = compute_entity_baseline(key, make_hospital_batch(5))
        assert eb.entity_key == key

    def test_event_type_distribution_populated(self) -> None:
        key = EntityKey(entity_type="user", entity_id="svc-iis")
        events = make_hospital_batch(10)
        eb = compute_entity_baseline(key, events)
        assert "ProcessCreate" in eb.event_type_distribution
        assert eb.event_type_distribution["ProcessCreate"] == 10

    def test_action_distribution_populated(self) -> None:
        key = EntityKey(entity_type="user", entity_id="svc-iis")
        events = make_hospital_batch(10)
        eb = compute_entity_baseline(key, events)
        assert "execute" in eb.action_distribution

    def test_result_distribution_populated(self) -> None:
        key = EntityKey(entity_type="user", entity_id="svc-iis")
        events = make_hospital_batch(10)
        eb = compute_entity_baseline(key, events)
        assert "success" in eb.result_distribution

    def test_time_pattern_populated(self) -> None:
        key = EntityKey(entity_type="user", entity_id="svc-iis")
        events = make_hospital_batch(10)
        eb = compute_entity_baseline(key, events)
        assert eb.time_pattern.total_events == 10

    def test_network_baseline_populated_for_hospital_events(self) -> None:
        key = EntityKey(entity_type="user", entity_id="svc-iis")
        events = make_hospital_batch(10)
        eb = compute_entity_baseline(key, events)
        assert eb.network is not None
        assert eb.network.connection_count == 10

    def test_process_baseline_populated_for_hospital_events(self) -> None:
        key = EntityKey(entity_type="user", entity_id="svc-iis")
        events = make_hospital_batch(5)
        eb = compute_entity_baseline(key, events)
        assert eb.process is not None
        assert "w3wp.exe" in eb.process.unique_processes

    def test_modbus_baseline_populated_for_ot_events(self) -> None:
        key = EntityKey(entity_type="host", entity_id="ot-node-01")
        events = make_ot_batch(10)
        eb = compute_entity_baseline(key, events)
        assert eb.modbus is not None
        assert eb.modbus.modbus_event_count == 10

    def test_auth_baseline_populated_for_dc_events(self) -> None:
        key = EntityKey(entity_type="host", entity_id="dc01")
        events = [make_dc_event() for _ in range(5)]
        eb = compute_entity_baseline(key, events)
        assert eb.auth is not None
        assert eb.auth.auth_event_count == 5

    def test_first_seen_last_seen(self) -> None:
        key = EntityKey(entity_type="user", entity_id="svc-iis")
        events = make_hospital_batch(5)
        eb = compute_entity_baseline(key, events)
        assert eb.first_seen is not None
        assert eb.last_seen is not None
        assert eb.first_seen <= eb.last_seen

    def test_modbus_none_for_non_ot_entity(self) -> None:
        key = EntityKey(entity_type="user", entity_id="svc-iis")
        events = make_hospital_batch(5)
        eb = compute_entity_baseline(key, events)
        assert eb.modbus is None

    def test_resource_stats_populated(self) -> None:
        key = EntityKey(entity_type="user", entity_id="svc-iis")
        events = make_hospital_batch(10)
        eb = compute_entity_baseline(key, events)
        assert eb.resource_stats is not None
        assert eb.resource_stats.count == 10
