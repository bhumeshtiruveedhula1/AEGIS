"""
tests/unit/features/test_extractors.py
========================================
Unit tests for all 8 feature extractors.
Tests are grouped by extractor class.
All tests verify deterministic behavior and cold-start safety.
"""

from __future__ import annotations

import pytest

from backend.features.extractors import safe_z_score, safe_percentile_rank, binary, safe_frequency, frequency_rank
from backend.features.extractors.temporal import TemporalExtractor
from backend.features.extractors.frequency import FrequencyExtractor
from backend.features.extractors.network import NetworkExtractor
from backend.features.extractors.process import ProcessExtractor
from backend.features.extractors.auth import AuthExtractor
from backend.features.extractors.ot import OTExtractor
from backend.features.extractors.baseline import BaselinePresenceExtractor
from backend.features.extractors.entity_activity import EntityActivityExtractor

from tests.unit.features.conftest import (
    FIXED_TS,
    FIXED_TS_NIGHT,
    FIXED_TS_WEEKEND,
    make_hospital_event,
    make_dc_event,
    make_ot_event,
    make_attacker_event,
    make_hospital_baseline,
    make_dc_baseline,
    make_ot_baseline,
)


# ===========================================================================
# Numeric helpers
# ===========================================================================

class TestSafeZScore:

    def test_known_value(self) -> None:
        # (110 - 100) / 10 = 1.0
        assert abs(safe_z_score(110.0, 100.0, 10.0) - 1.0) < 1e-9

    def test_zero_std_returns_zero(self) -> None:
        assert safe_z_score(50.0, 100.0, 0.0) == 0.0

    def test_none_mean_returns_zero(self) -> None:
        assert safe_z_score(50.0, None, 10.0) == 0.0

    def test_none_std_returns_zero(self) -> None:
        assert safe_z_score(50.0, 100.0, None) == 0.0

    def test_negative_z_score(self) -> None:
        assert abs(safe_z_score(90.0, 100.0, 10.0) - (-1.0)) < 1e-9

    def test_value_at_mean_returns_zero(self) -> None:
        assert safe_z_score(100.0, 100.0, 10.0) == 0.0


class TestSafePercentileRank:

    def test_below_p25(self) -> None:
        assert safe_percentile_rank(10.0, 25.0, 50.0, 75.0, 95.0) == 0.0

    def test_between_p25_p50(self) -> None:
        assert safe_percentile_rank(30.0, 25.0, 50.0, 75.0, 95.0) == 1.0

    def test_between_p50_p75(self) -> None:
        assert safe_percentile_rank(60.0, 25.0, 50.0, 75.0, 95.0) == 2.0

    def test_between_p75_p95(self) -> None:
        assert safe_percentile_rank(80.0, 25.0, 50.0, 75.0, 95.0) == 3.0

    def test_above_p95(self) -> None:
        assert safe_percentile_rank(100.0, 25.0, 50.0, 75.0, 95.0) == 4.0

    def test_none_percentile_returns_zero(self) -> None:
        assert safe_percentile_rank(50.0, None, 50.0, 75.0, 95.0) == 0.0


class TestBinary:

    def test_true_returns_one(self) -> None:
        assert binary(True) == 1.0

    def test_false_returns_zero(self) -> None:
        assert binary(False) == 0.0

    def test_none_returns_zero(self) -> None:
        assert binary(None) == 0.0


class TestSafeFrequency:

    def test_known_value(self) -> None:
        dist = {"tcp": 50, "udp": 10}
        assert safe_frequency("tcp", dist) == 50.0

    def test_lowercase_lookup(self) -> None:
        dist = {"tcp": 50}
        assert safe_frequency("TCP", dist) == 50.0

    def test_missing_value_returns_zero(self) -> None:
        dist = {"tcp": 50}
        assert safe_frequency("http", dist) == 0.0

    def test_none_distribution_returns_zero(self) -> None:
        assert safe_frequency("tcp", None) == 0.0

    def test_none_value_returns_zero(self) -> None:
        assert safe_frequency(None, {"tcp": 50}) == 0.0


# ===========================================================================
# TemporalExtractor
# ===========================================================================

class TestTemporalExtractor:

    def test_produces_all_feature_names(self) -> None:
        ext = TemporalExtractor()
        result, _ = ext.safe_extract(make_hospital_event(), None)
        assert set(result.keys()) == set(ext.feature_names)

    def test_hour_of_day_correct(self) -> None:
        ext = TemporalExtractor()
        result, _ = ext.safe_extract(make_hospital_event(), None)
        assert result["hour_of_day"] == 9.0

    def test_day_of_week_monday(self) -> None:
        ext = TemporalExtractor()
        result, _ = ext.safe_extract(make_hospital_event(), None)
        assert result["day_of_week"] == 0.0  # Monday

    def test_is_business_hours_true(self) -> None:
        ext = TemporalExtractor()
        result, _ = ext.safe_extract(make_hospital_event(), None)
        assert result["is_business_hours"] == 1.0

    def test_is_business_hours_false_night(self) -> None:
        ext = TemporalExtractor()
        event = make_hospital_event({"timestamp": FIXED_TS_NIGHT})
        result, _ = ext.safe_extract(event, None)
        assert result["is_business_hours"] == 0.0

    def test_is_business_hours_false_weekend(self) -> None:
        ext = TemporalExtractor()
        event = make_hospital_event({"timestamp": FIXED_TS_WEEKEND})
        result, _ = ext.safe_extract(event, None)
        assert result["is_business_hours"] == 0.0

    def test_cold_start_hour_freq_zero(self) -> None:
        ext = TemporalExtractor()
        result, _ = ext.safe_extract(make_hospital_event(), None)
        assert result["hour_baseline_frequency"] == 0.0

    def test_hour_baseline_frequency_nonzero_with_baseline(self) -> None:
        ext = TemporalExtractor()
        baseline = make_hospital_baseline()
        result, _ = ext.safe_extract(make_hospital_event(), baseline)
        assert result["hour_baseline_frequency"] > 0.0

    def test_is_peak_hour_true_when_at_peak(self) -> None:
        ext = TemporalExtractor()
        baseline = make_hospital_baseline()  # peak at hour 9
        event = make_hospital_event()  # timestamp at 09:30
        result, _ = ext.safe_extract(event, baseline)
        assert result["is_peak_hour"] == 1.0

    def test_is_peak_hour_false_when_off_peak(self) -> None:
        ext = TemporalExtractor()
        baseline = make_hospital_baseline()  # peak at hour 9
        event = make_hospital_event({"timestamp": FIXED_TS_NIGHT})  # hour 2
        result, _ = ext.safe_extract(event, baseline)
        assert result["is_peak_hour"] == 0.0

    def test_all_values_finite(self) -> None:
        import math
        ext = TemporalExtractor()
        result, _ = ext.safe_extract(make_hospital_event(), make_hospital_baseline())
        assert all(math.isfinite(v) for v in result.values())


# ===========================================================================
# FrequencyExtractor
# ===========================================================================

class TestFrequencyExtractor:

    def test_produces_all_feature_names(self) -> None:
        ext = FrequencyExtractor()
        result, _ = ext.safe_extract(make_hospital_event(), None)
        assert set(result.keys()) == set(ext.feature_names)

    def test_cold_start_all_zero_except_result_is_failure(self) -> None:
        ext = FrequencyExtractor()
        result, _ = ext.safe_extract(make_hospital_event(), None)
        # result_is_failure should be 0.0 for a "success" event
        assert result["result_is_failure"] == 0.0
        assert result["event_type_frequency"] == 0.0

    def test_result_is_failure_true(self) -> None:
        ext = FrequencyExtractor()
        event = make_hospital_event({"result": "failure"})
        result, _ = ext.safe_extract(event, None)
        assert result["result_is_failure"] == 1.0

    def test_event_type_frequency_with_baseline(self) -> None:
        ext = FrequencyExtractor()
        baseline = make_hospital_baseline()
        result, _ = ext.safe_extract(make_hospital_event(), baseline)
        assert result["event_type_frequency"] == 80.0

    def test_event_type_frequency_rank_zero_for_most_common(self) -> None:
        ext = FrequencyExtractor()
        baseline = make_hospital_baseline()
        result, _ = ext.safe_extract(make_hospital_event(), baseline)
        assert result["event_type_frequency_rank"] == 0.0  # ProcessCreate is most common

    def test_result_failure_rate_baseline(self) -> None:
        ext = FrequencyExtractor()
        baseline = make_hospital_baseline()
        result, _ = ext.safe_extract(make_hospital_event(), baseline)
        assert abs(result["result_failure_rate_baseline"] - 5/100) < 1e-6

    def test_observation_count(self) -> None:
        ext = FrequencyExtractor()
        baseline = make_hospital_baseline()
        result, _ = ext.safe_extract(make_hospital_event(), baseline)
        assert result["entity_observation_count"] == 100.0

    def test_baseline_window_days_positive(self) -> None:
        ext = FrequencyExtractor()
        baseline = make_hospital_baseline()
        result, _ = ext.safe_extract(make_hospital_event(), baseline)
        assert result["baseline_window_days"] > 0.0


# ===========================================================================
# NetworkExtractor
# ===========================================================================

class TestNetworkExtractor:

    def test_produces_all_feature_names(self) -> None:
        ext = NetworkExtractor()
        result, _ = ext.safe_extract(make_hospital_event(), None)
        assert set(result.keys()) == set(ext.feature_names)

    def test_cold_start_all_zero(self) -> None:
        ext = NetworkExtractor()
        result, _ = ext.safe_extract(make_hospital_event(), None)
        assert all(v == 0.0 for v in result.values())

    def test_known_dst_ip_not_novel(self) -> None:
        ext = NetworkExtractor()
        baseline = make_hospital_baseline()
        # 10.0.1.20 is in baseline
        result, _ = ext.safe_extract(make_hospital_event(), baseline)
        assert result["dst_ip_is_novel"] == 0.0

    def test_unknown_dst_ip_is_novel(self) -> None:
        ext = NetworkExtractor()
        baseline = make_hospital_baseline()
        event = make_hospital_event({"dst_ip": "192.168.99.99"})
        result, _ = ext.safe_extract(event, baseline)
        assert result["dst_ip_is_novel"] == 1.0

    def test_known_port_not_novel(self) -> None:
        ext = NetworkExtractor()
        baseline = make_hospital_baseline()
        result, _ = ext.safe_extract(make_hospital_event(), baseline)
        assert result["port_is_novel"] == 0.0

    def test_unknown_port_is_novel(self) -> None:
        ext = NetworkExtractor()
        baseline = make_hospital_baseline()
        event = make_hospital_event({"port": 9999})
        result, _ = ext.safe_extract(event, baseline)
        assert result["port_is_novel"] == 1.0

    def test_bytes_out_z_score_zero_at_mean(self) -> None:
        ext = NetworkExtractor()
        baseline = make_hospital_baseline()
        # bytes_out at mean (512)
        event = make_hospital_event({"bytes_out": 512})
        result, _ = ext.safe_extract(event, baseline)
        assert abs(result["bytes_out_z_score"]) < 1e-6

    def test_bytes_out_z_score_nonzero_above_mean(self) -> None:
        ext = NetworkExtractor()
        baseline = make_hospital_baseline()
        event = make_hospital_event({"bytes_out": 612})  # 100 bytes above mean
        result, _ = ext.safe_extract(event, baseline)
        assert result["bytes_out_z_score"] > 0.0

    def test_unique_dst_ips_baseline_count(self) -> None:
        ext = NetworkExtractor()
        baseline = make_hospital_baseline()
        result, _ = ext.safe_extract(make_hospital_event(), baseline)
        assert result["unique_dst_ips_baseline"] == 2.0  # 2 in baseline


# ===========================================================================
# ProcessExtractor
# ===========================================================================

class TestProcessExtractor:

    def test_produces_all_feature_names(self) -> None:
        ext = ProcessExtractor()
        result, _ = ext.safe_extract(make_hospital_event(), None)
        assert set(result.keys()) == set(ext.feature_names)

    def test_non_process_event_all_zero_except_has_cmd(self) -> None:
        ext = ProcessExtractor()
        ot_event = make_ot_event()  # no process field
        result, _ = ext.safe_extract(ot_event, None)
        assert result["process_is_novel"] == 0.0
        assert result["has_command_line"] == 0.0

    def test_known_process_not_novel(self) -> None:
        ext = ProcessExtractor()
        baseline = make_hospital_baseline()
        result, _ = ext.safe_extract(make_hospital_event(), baseline)
        assert result["process_is_novel"] == 0.0

    def test_unknown_process_is_novel(self) -> None:
        ext = ProcessExtractor()
        baseline = make_hospital_baseline()
        event = make_hospital_event({"process": "evil.exe"})
        result, _ = ext.safe_extract(event, baseline)
        assert result["process_is_novel"] == 1.0

    def test_known_parent_not_novel(self) -> None:
        ext = ProcessExtractor()
        baseline = make_hospital_baseline()
        result, _ = ext.safe_extract(make_hospital_event(), baseline)
        assert result["parent_process_is_novel"] == 0.0

    def test_unknown_parent_is_novel(self) -> None:
        ext = ProcessExtractor()
        baseline = make_hospital_baseline()
        event = make_hospital_event({"parent_process": "cmd.exe"})
        result, _ = ext.safe_extract(event, baseline)
        assert result["parent_process_is_novel"] == 1.0

    def test_known_pair_not_novel(self) -> None:
        ext = ProcessExtractor()
        baseline = make_hospital_baseline()
        # "svchost.exe__w3wp.exe" is in baseline
        result, _ = ext.safe_extract(make_hospital_event(), baseline)
        assert result["parent_child_pair_is_novel"] == 0.0

    def test_unknown_pair_is_novel(self) -> None:
        ext = ProcessExtractor()
        baseline = make_hospital_baseline()
        event = make_hospital_event({"parent_process": "explorer.exe", "process": "w3wp.exe"})
        result, _ = ext.safe_extract(event, baseline)
        assert result["parent_child_pair_is_novel"] == 1.0

    def test_has_command_line_true(self) -> None:
        ext = ProcessExtractor()
        result, _ = ext.safe_extract(make_hospital_event(), None)
        assert result["has_command_line"] == 1.0

    def test_has_command_line_false(self) -> None:
        ext = ProcessExtractor()
        event = make_hospital_event({"command_line": None})
        result, _ = ext.safe_extract(event, None)
        assert result["has_command_line"] == 0.0

    def test_unique_processes_baseline_count(self) -> None:
        ext = ProcessExtractor()
        baseline = make_hospital_baseline()
        result, _ = ext.safe_extract(make_hospital_event(), baseline)
        assert result["unique_processes_baseline"] == 2.0


# ===========================================================================
# AuthExtractor
# ===========================================================================

class TestAuthExtractor:

    def test_produces_all_feature_names(self) -> None:
        ext = AuthExtractor()
        result, _ = ext.safe_extract(make_dc_event(), None)
        assert set(result.keys()) == set(ext.feature_names)

    def test_non_auth_event_all_zero(self) -> None:
        ext = AuthExtractor()
        ot_event = make_ot_event()  # no auth context
        result, _ = ext.safe_extract(ot_event, None)
        assert all(v == 0.0 for v in result.values())

    def test_known_logon_type_not_novel(self) -> None:
        ext = AuthExtractor()
        baseline = make_dc_baseline()
        result, _ = ext.safe_extract(make_dc_event(), baseline)
        assert result["logon_type_is_novel"] == 0.0

    def test_novel_logon_type(self) -> None:
        ext = AuthExtractor()
        baseline = make_dc_baseline()
        event = make_dc_event({"logon_type": "batch"})  # not in baseline
        result, _ = ext.safe_extract(event, baseline)
        assert result["logon_type_is_novel"] == 1.0

    def test_known_auth_package_not_novel(self) -> None:
        ext = AuthExtractor()
        baseline = make_dc_baseline()
        result, _ = ext.safe_extract(make_dc_event(), baseline)
        assert result["auth_package_is_novel"] == 0.0

    def test_novel_auth_package(self) -> None:
        ext = AuthExtractor()
        baseline = make_dc_baseline()
        event = make_dc_event({"auth_package": "Digest"})  # not in baseline
        result, _ = ext.safe_extract(event, baseline)
        assert result["auth_package_is_novel"] == 1.0

    def test_auth_failure_rate_baseline(self) -> None:
        ext = AuthExtractor()
        baseline = make_dc_baseline()
        result, _ = ext.safe_extract(make_dc_event(), baseline)
        # failure_count=5, success_count=45 → rate = 5/50 = 0.1
        assert abs(result["auth_failure_rate_baseline"] - 0.1) < 1e-6

    def test_windows_event_id_known_not_novel(self) -> None:
        ext = AuthExtractor()
        baseline = make_dc_baseline()
        result, _ = ext.safe_extract(make_dc_event(), baseline)
        assert result["windows_event_id_is_novel"] == 0.0

    def test_windows_event_id_novel(self) -> None:
        ext = AuthExtractor()
        baseline = make_dc_baseline()
        event = make_dc_event({"windows_event_id": 4672})  # not in baseline
        result, _ = ext.safe_extract(event, baseline)
        assert result["windows_event_id_is_novel"] == 1.0


# ===========================================================================
# OTExtractor
# ===========================================================================

class TestOTExtractor:

    def test_produces_all_feature_names(self) -> None:
        ext = OTExtractor()
        result, _ = ext.safe_extract(make_ot_event(), None)
        assert set(result.keys()) == set(ext.feature_names)

    def test_non_ot_event_all_zero(self) -> None:
        ext = OTExtractor()
        result, _ = ext.safe_extract(make_hospital_event(), None)
        assert all(v == 0.0 for v in result.values())

    def test_register_in_range(self) -> None:
        ext = OTExtractor()
        baseline = make_ot_baseline()  # min=5, max=30
        result, _ = ext.safe_extract(make_ot_event(), baseline)
        assert result["modbus_register_is_in_range"] == 1.0

    def test_register_out_of_range(self) -> None:
        ext = OTExtractor()
        baseline = make_ot_baseline()
        event = make_ot_event({"modbus_register": 9999})
        result, _ = ext.safe_extract(event, baseline)
        assert result["modbus_register_is_in_range"] == 0.0

    def test_known_function_code_not_novel(self) -> None:
        ext = OTExtractor()
        baseline = make_ot_baseline()
        result, _ = ext.safe_extract(make_ot_event(), baseline)
        assert result["modbus_function_code_is_novel"] == 0.0

    def test_novel_function_code(self) -> None:
        ext = OTExtractor()
        baseline = make_ot_baseline()
        event = make_ot_event({"modbus_function_code": "FC16"})
        result, _ = ext.safe_extract(event, baseline)
        assert result["modbus_function_code_is_novel"] == 1.0

    def test_known_supervisory_host_not_novel(self) -> None:
        ext = OTExtractor()
        baseline = make_ot_baseline()
        result, _ = ext.safe_extract(make_ot_event(), baseline)
        assert result["supervisory_host_is_novel"] == 0.0

    def test_novel_supervisory_host(self) -> None:
        ext = OTExtractor()
        baseline = make_ot_baseline()
        event = make_ot_event({"supervisory_host": "10.99.99.99"})
        result, _ = ext.safe_extract(event, baseline)
        assert result["supervisory_host_is_novel"] == 1.0

    def test_register_z_score_at_mean(self) -> None:
        ext = OTExtractor()
        baseline = make_ot_baseline()  # mean=15
        event = make_ot_event({"modbus_register": 15})
        result, _ = ext.safe_extract(event, baseline)
        assert abs(result["modbus_register_z_score"]) < 1e-6


# ===========================================================================
# BaselinePresenceExtractor
# ===========================================================================

class TestBaselinePresenceExtractor:

    def test_all_zero_when_no_context(self) -> None:
        ext = BaselinePresenceExtractor()
        result, _ = ext.safe_extract(make_hospital_event(), None)
        assert all(v == 0.0 for v in result.values())

    def test_has_user_baseline_true(self) -> None:
        ext = BaselinePresenceExtractor()
        ext.set_context({"has_user_baseline": True})
        result, _ = ext.safe_extract(make_hospital_event(), None)
        assert result["has_user_baseline"] == 1.0

    def test_has_host_baseline_true(self) -> None:
        ext = BaselinePresenceExtractor()
        ext.set_context({"has_host_baseline": True})
        result, _ = ext.safe_extract(make_hospital_event(), None)
        assert result["has_host_baseline"] == 1.0

    def test_partial_context(self) -> None:
        ext = BaselinePresenceExtractor()
        ext.set_context({"has_user_baseline": True, "has_source_baseline": True})
        result, _ = ext.safe_extract(make_hospital_event(), None)
        assert result["has_user_baseline"] == 1.0
        assert result["has_host_baseline"] == 0.0
        assert result["has_source_baseline"] == 1.0
        assert result["has_user_host_baseline"] == 0.0


# ===========================================================================
# EntityActivityExtractor
# ===========================================================================

class TestEntityActivityExtractor:

    def test_all_zero_cold_start(self) -> None:
        ext = EntityActivityExtractor()
        result, _ = ext.safe_extract(make_hospital_event(), None)
        assert all(v == 0.0 for v in result.values())

    def test_unique_dst_ips_count(self) -> None:
        ext = EntityActivityExtractor()
        baseline = make_hospital_baseline()
        result, _ = ext.safe_extract(make_hospital_event(), baseline)
        assert result["entity_unique_dst_ips"] == 2.0

    def test_unique_processes_count(self) -> None:
        ext = EntityActivityExtractor()
        baseline = make_hospital_baseline()
        result, _ = ext.safe_extract(make_hospital_event(), baseline)
        assert result["entity_unique_processes"] == 2.0

    def test_auth_failure_count(self) -> None:
        ext = EntityActivityExtractor()
        baseline = make_dc_baseline()
        result, _ = ext.safe_extract(make_dc_event(), baseline)
        assert result["entity_auth_failure_count"] == 5.0

    def test_modbus_event_count(self) -> None:
        ext = EntityActivityExtractor()
        baseline = make_ot_baseline()
        result, _ = ext.safe_extract(make_ot_event(), baseline)
        assert result["entity_modbus_event_count"] == 200.0

    def test_no_auth_baseline_returns_zero(self) -> None:
        ext = EntityActivityExtractor()
        baseline = make_hospital_baseline()  # no auth sub-baseline
        result, _ = ext.safe_extract(make_hospital_event(), baseline)
        assert result["entity_auth_failure_count"] == 0.0
