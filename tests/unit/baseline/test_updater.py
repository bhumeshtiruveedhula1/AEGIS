"""
tests/unit/baseline/test_updater.py
=====================================
Unit tests for BaselineUpdater — incremental merge.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from backend.baseline.models import EntityBaseline, EntityKey
from backend.baseline.statistics import compute_entity_baseline
from backend.baseline.updater import BaselineUpdater, _merge_time_patterns
from tests.unit.baseline.conftest import (
    FIXED_DT,
    FIXED_DT_NIGHT,
    make_dc_event,
    make_hospital_batch,
    make_hospital_event,
    make_ot_batch,
    make_ot_event,
)


# ===========================================================================
# No-op on empty new events
# ===========================================================================

class TestNoopUpdate:

    def test_empty_new_events_returns_existing(self) -> None:
        key = EntityKey(entity_type="user", entity_id="svc-iis")
        existing = compute_entity_baseline(key, make_hospital_batch(10))
        updater = BaselineUpdater()
        result = updater.update(existing, [])
        assert result is existing  # exact same object

    def test_existing_not_mutated(self) -> None:
        key = EntityKey(entity_type="user", entity_id="svc-iis")
        existing = compute_entity_baseline(key, make_hospital_batch(10))
        original_count = existing.observation_count
        updater = BaselineUpdater()
        updater.update(existing, make_hospital_batch(5))
        assert existing.observation_count == original_count  # original unchanged


# ===========================================================================
# Observation count
# ===========================================================================

class TestObservationCount:

    def test_count_increases_by_new_events(self) -> None:
        key = EntityKey(entity_type="user", entity_id="svc-iis")
        existing = compute_entity_baseline(key, make_hospital_batch(10))
        updater = BaselineUpdater()
        updated = updater.update(existing, make_hospital_batch(5))
        assert updated.observation_count == 15

    def test_count_accumulates_across_multiple_updates(self) -> None:
        key = EntityKey(entity_type="user", entity_id="svc-iis")
        updater = BaselineUpdater()
        current = compute_entity_baseline(key, make_hospital_batch(10))
        for _ in range(5):
            current = updater.update(current, make_hospital_batch(2))
        assert current.observation_count == 20


# ===========================================================================
# Universal distributions
# ===========================================================================

class TestDistributionMerge:

    def test_event_type_distribution_merged(self) -> None:
        key = EntityKey(entity_type="user", entity_id="svc-iis")
        existing = compute_entity_baseline(key, make_hospital_batch(10))
        new_events = [make_hospital_event({"event_type": "NetworkConnect"})]
        updater = BaselineUpdater()
        updated = updater.update(existing, new_events)
        assert "ProcessCreate" in updated.event_type_distribution
        assert "NetworkConnect" in updated.event_type_distribution

    def test_result_failure_added_to_distribution(self) -> None:
        key = EntityKey(entity_type="user", entity_id="svc-iis")
        existing = compute_entity_baseline(key, make_hospital_batch(10))
        new_events = [make_hospital_event({"result": "failure"})]
        updater = BaselineUpdater()
        updated = updater.update(existing, new_events)
        assert "failure" in updated.result_distribution

    def test_source_distribution_merged(self) -> None:
        key = EntityKey(entity_type="user", entity_id="svc-iis")
        # Start with hospital events
        existing = compute_entity_baseline(key, make_hospital_batch(5))
        # Add dc events for same user
        new_events = [make_dc_event({"user": "svc-iis"})]
        updater = BaselineUpdater()
        updated = updater.update(existing, new_events)
        assert "hospital_server" in updated.source_distribution
        assert "domain_controller" in updated.source_distribution


# ===========================================================================
# Temporal pattern merge
# ===========================================================================

class TestTimePatternMerge:

    def test_hourly_buckets_summed(self) -> None:
        key = EntityKey(entity_type="user", entity_id="svc-iis")
        # Events at 09:30
        existing = compute_entity_baseline(key, make_hospital_batch(5))
        # New events at 02:00 UTC (night)
        new_events = [make_hospital_event({"timestamp": FIXED_DT_NIGHT.isoformat()})]
        updater = BaselineUpdater()
        updated = updater.update(existing, new_events)
        assert updated.time_pattern.hourly_buckets[9] > 0
        assert updated.time_pattern.hourly_buckets[2] > 0

    def test_total_events_summed(self) -> None:
        key = EntityKey(entity_type="user", entity_id="svc-iis")
        existing = compute_entity_baseline(key, make_hospital_batch(10))
        updater = BaselineUpdater()
        updated = updater.update(existing, make_hospital_batch(5))
        assert updated.time_pattern.total_events == 15


# ===========================================================================
# Observation window
# ===========================================================================

class TestObservationWindow:

    def test_first_seen_updated_to_earlier_time(self) -> None:
        key = EntityKey(entity_type="user", entity_id="svc-iis")
        # Build with events at FIXED_DT (Jan 15)
        existing = compute_entity_baseline(key, make_hospital_batch(5))
        # New events BEFORE first_seen (Jan 1)
        early_ts = datetime(2024, 1, 1, 9, 0, tzinfo=UTC)
        new_events = [make_hospital_event({"timestamp": early_ts.isoformat()})]
        updater = BaselineUpdater()
        updated = updater.update(existing, new_events)
        assert updated.first_seen == early_ts

    def test_last_seen_updated_to_later_time(self) -> None:
        key = EntityKey(entity_type="user", entity_id="svc-iis")
        existing = compute_entity_baseline(key, make_hospital_batch(5))
        late_ts = datetime(2024, 6, 1, 9, 0, tzinfo=UTC)
        new_events = [make_hospital_event({"timestamp": late_ts.isoformat()})]
        updater = BaselineUpdater()
        updated = updater.update(existing, new_events)
        assert updated.last_seen == late_ts


# ===========================================================================
# Network baseline merge
# ===========================================================================

class TestNetworkMerge:

    def test_new_dst_ip_added_to_set(self) -> None:
        key = EntityKey(entity_type="user", entity_id="svc-iis")
        existing = compute_entity_baseline(key, make_hospital_batch(5))
        new_events = [make_hospital_event({"dst_ip": "192.168.99.99"})]
        updater = BaselineUpdater()
        updated = updater.update(existing, new_events)
        assert updated.network is not None
        assert "192.168.99.99" in updated.network.unique_dst_ips

    def test_connection_count_summed(self) -> None:
        key = EntityKey(entity_type="user", entity_id="svc-iis")
        existing = compute_entity_baseline(key, make_hospital_batch(10))
        updater = BaselineUpdater()
        updated = updater.update(existing, make_hospital_batch(5))
        assert updated.network is not None
        assert updated.network.connection_count == 15


# ===========================================================================
# Process baseline merge
# ===========================================================================

class TestProcessMerge:

    def test_new_process_added_to_unique_set(self) -> None:
        key = EntityKey(entity_type="user", entity_id="svc-iis")
        existing = compute_entity_baseline(key, make_hospital_batch(5))
        new_events = [make_hospital_event({"process": "powershell.exe"})]
        updater = BaselineUpdater()
        updated = updater.update(existing, new_events)
        assert updated.process is not None
        assert "powershell.exe" in updated.process.unique_processes

    def test_process_frequency_merged(self) -> None:
        key = EntityKey(entity_type="user", entity_id="svc-iis")
        existing = compute_entity_baseline(key, make_hospital_batch(10))
        original_count = existing.process.process_frequency.get("w3wp.exe", 0)
        updater = BaselineUpdater()
        updated = updater.update(existing, make_hospital_batch(3))
        assert updated.process.process_frequency["w3wp.exe"] == original_count + 3


# ===========================================================================
# Modbus baseline merge
# ===========================================================================

class TestModbusMerge:

    def test_new_supervisory_host_added(self) -> None:
        key = EntityKey(entity_type="host", entity_id="ot-node-01")
        existing = compute_entity_baseline(key, make_ot_batch(5))
        new_events = [make_ot_event({"supervisory_host": "192.168.10.99"})]
        updater = BaselineUpdater()
        updated = updater.update(existing, new_events)
        assert updated.modbus is not None
        assert "192.168.10.99" in updated.modbus.known_supervisory_hosts

    def test_modbus_event_count_summed(self) -> None:
        key = EntityKey(entity_type="host", entity_id="ot-node-01")
        existing = compute_entity_baseline(key, make_ot_batch(10))
        updater = BaselineUpdater()
        updated = updater.update(existing, make_ot_batch(5))
        assert updated.modbus is not None
        assert updated.modbus.modbus_event_count == 15


# ===========================================================================
# _merge_time_patterns helper
# ===========================================================================

class TestMergeTimePatterns:

    def test_element_wise_addition(self) -> None:
        from backend.baseline.statistics import compute_time_pattern
        ts1 = [datetime(2024, 1, 15, 9, 0, tzinfo=UTC)] * 3
        ts2 = [datetime(2024, 1, 15, 9, 0, tzinfo=UTC)] * 2
        tp1 = compute_time_pattern(ts1)
        tp2 = compute_time_pattern(ts2)
        merged = _merge_time_patterns(tp1, tp2)
        assert merged.hourly_buckets[9] == 5
        assert merged.total_events == 5
