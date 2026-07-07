"""
tests/unit/baseline/test_aggregator.py
=======================================
Unit tests for EventAggregator — entity grouping logic.
"""

from __future__ import annotations

import pytest

from backend.baseline.aggregator import EventAggregator
from backend.baseline.models import EntityKey
from tests.unit.baseline.conftest import (
    make_attacker_event,
    make_dc_event,
    make_hospital_batch,
    make_hospital_event,
    make_mixed_events,
    make_ot_event,
)


# ===========================================================================
# Dimension configuration
# ===========================================================================

class TestDimensionConfiguration:

    def test_default_dimensions_all_four(self) -> None:
        agg = EventAggregator()
        assert agg.dimensions == frozenset({"user", "host", "source", "user_host"})

    def test_restrict_to_user_only(self) -> None:
        agg = EventAggregator(dimensions={"user"})
        assert agg.dimensions == frozenset({"user"})

    def test_restrict_to_host_and_source(self) -> None:
        agg = EventAggregator(dimensions={"host", "source"})
        assert "user" not in agg.dimensions
        assert "host" in agg.dimensions

    def test_invalid_dimension_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid"):
            EventAggregator(dimensions={"user", "invalid"})

    def test_empty_dimensions_raises(self) -> None:
        # An empty set would be technically valid but useless — no key extraction
        agg = EventAggregator(dimensions=set())
        groups = agg.aggregate([make_hospital_event()])
        assert groups == {}


# ===========================================================================
# Aggregation correctness
# ===========================================================================

class TestAggregationCorrectness:

    def test_empty_events_returns_empty_dict(self) -> None:
        agg = EventAggregator()
        result = agg.aggregate([])
        assert result == {}

    def test_single_event_creates_4_groups(self) -> None:
        agg = EventAggregator()
        result = agg.aggregate([make_hospital_event()])
        assert len(result) == 4  # user, host, source, user_host

    def test_user_key_correctly_identified(self) -> None:
        agg = EventAggregator(dimensions={"user"})
        result = agg.aggregate([make_hospital_event()])
        keys = list(result.keys())
        assert any(k.entity_type == "user" and k.entity_id == "svc-iis" for k in keys)

    def test_host_key_correctly_identified(self) -> None:
        agg = EventAggregator(dimensions={"host"})
        result = agg.aggregate([make_hospital_event()])
        keys = list(result.keys())
        assert any(k.entity_type == "host" and k.entity_id == "hospital-server-01" for k in keys)

    def test_source_key_correctly_identified(self) -> None:
        agg = EventAggregator(dimensions={"source"})
        result = agg.aggregate([make_hospital_event()])
        keys = list(result.keys())
        assert any(k.entity_type == "source" and k.entity_id == "hospital_server" for k in keys)

    def test_user_host_key_format(self) -> None:
        agg = EventAggregator(dimensions={"user_host"})
        result = agg.aggregate([make_hospital_event()])
        keys = list(result.keys())
        assert any(
            k.entity_type == "user_host"
            and k.entity_id == "svc-iis::hospital-server-01"
            for k in keys
        )

    def test_multiple_events_same_user_grouped_together(self) -> None:
        agg = EventAggregator(dimensions={"user"})
        events = make_hospital_batch(10, user="svc-iis")
        result = agg.aggregate(events)
        user_key = EntityKey(entity_type="user", entity_id="svc-iis")
        assert len(result[user_key]) == 10

    def test_different_users_separate_groups(self) -> None:
        agg = EventAggregator(dimensions={"user"})
        events = (
            [make_hospital_event({"user": "svc-iis"})] * 5 +
            [make_hospital_event({"user": "admin"})] * 3
        )
        result = agg.aggregate(events)
        key_svc = EntityKey(entity_type="user", entity_id="svc-iis")
        key_admin = EntityKey(entity_type="user", entity_id="admin")
        assert len(result[key_svc]) == 5
        assert len(result[key_admin]) == 3

    def test_multiple_sources_produce_separate_source_groups(self) -> None:
        agg = EventAggregator(dimensions={"source"})
        events = [
            make_hospital_event(),
            make_dc_event(),
            make_ot_event(),
        ]
        result = agg.aggregate(events)
        sources = {k.entity_id for k in result if k.entity_type == "source"}
        assert sources == {"hospital_server", "domain_controller", "ot_node"}

    def test_event_references_not_duplicated(self) -> None:
        """Events in groups are references, not copies (no duplication)."""
        agg = EventAggregator(dimensions={"user", "host"})
        event = make_hospital_event()
        result = agg.aggregate([event])
        all_events = [e for events in result.values() for e in events]
        # Should be exactly 2 references (one for user, one for host)
        assert len(all_events) == 2
        # But both should be the same object
        assert all(e is event for e in all_events)

    def test_mixed_events_all_4_sources(self) -> None:
        agg = EventAggregator()
        events = make_mixed_events(hospital=10, dc=5, ot=3, attacker=2)
        result = agg.aggregate(events)
        source_groups = {k for k in result if k.entity_type == "source"}
        source_ids = {k.entity_id for k in source_groups}
        assert "hospital_server" in source_ids
        assert "domain_controller" in source_ids
        assert "ot_node" in source_ids
        assert "attacker" in source_ids


# ===========================================================================
# ID normalisation
# ===========================================================================

class TestIdNormalisation:

    def test_user_uppercased_in_raw_is_lowercased(self) -> None:
        agg = EventAggregator(dimensions={"user"})
        event = make_hospital_event({"user": "SVC-IIS"})
        result = agg.aggregate([event])
        assert any(k.entity_id == "svc-iis" for k in result if k.entity_type == "user")

    def test_host_uppercased_is_lowercased(self) -> None:
        agg = EventAggregator(dimensions={"host"})
        event = make_hospital_event({"host": "HOSPITAL-SERVER-01"})
        result = agg.aggregate([event])
        assert any(k.entity_id == "hospital-server-01" for k in result if k.entity_type == "host")


# ===========================================================================
# aggregate_stream
# ===========================================================================

class TestAggregateStream:

    def test_aggregate_stream_generator(self) -> None:
        agg = EventAggregator(dimensions={"user"})
        events = make_hospital_batch(10)

        def gen():
            yield from events

        result = agg.aggregate_stream(gen())
        user_key = EntityKey(entity_type="user", entity_id="svc-iis")
        assert user_key in result
        assert len(result[user_key]) == 10


# ===========================================================================
# group_counts
# ===========================================================================

class TestGroupCounts:

    def test_group_counts_correct(self) -> None:
        agg = EventAggregator()
        events = (
            [make_hospital_event({"user": "a", "host": "h1"})] * 3 +
            [make_hospital_event({"user": "b", "host": "h1"})] * 2
        )
        groups = agg.aggregate(events)
        counts = agg.group_counts(groups)
        # 2 distinct users (a, b), 1 distinct host (h1), 1 source, 2 user_host
        assert counts["user"] == 2
        assert counts["host"] == 1
        assert counts["source"] == 1
        assert counts["user_host"] == 2
