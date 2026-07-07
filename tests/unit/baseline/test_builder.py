"""
tests/unit/baseline/test_builder.py
=====================================
Unit tests for BaselineBuilder — full build orchestration.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from backend.baseline.builder import BaselineBuilder
from backend.baseline.exceptions import BaselineInputError
from backend.baseline.models import BaselineProfile, EntityKey
from tests.unit.baseline.conftest import (
    make_dc_event,
    make_hospital_batch,
    make_mixed_events,
    make_ot_batch,
    write_events_jsonl,
)


# ===========================================================================
# build_from_events — in-memory build
# ===========================================================================

class TestBuildFromEvents:

    def test_returns_baseline_profile(self) -> None:
        builder = BaselineBuilder()
        events = make_hospital_batch(10)
        profile = builder.build_from_events(events)
        assert isinstance(profile, BaselineProfile)

    def test_profile_id_is_uuid(self) -> None:
        builder = BaselineBuilder()
        profile = builder.build_from_events(make_hospital_batch(5))
        import uuid
        uuid.UUID(profile.profile_id)  # Raises if invalid

    def test_total_events_correct(self) -> None:
        builder = BaselineBuilder()
        events = make_hospital_batch(20)
        profile = builder.build_from_events(events)
        assert profile.total_events_processed == 20

    def test_entity_count_nonzero(self) -> None:
        builder = BaselineBuilder()
        events = make_hospital_batch(10)
        profile = builder.build_from_events(events)
        assert profile.entity_count > 0

    def test_four_entity_dimensions_produced(self) -> None:
        builder = BaselineBuilder()
        events = make_hospital_batch(10)
        profile = builder.build_from_events(events)
        # Each event contributes to user, host, source, user_host = 4 entities
        types = {k.entity_type for k in profile.all_entity_keys()}
        assert "user" in types
        assert "host" in types
        assert "source" in types
        assert "user_host" in types

    def test_empty_events_produces_profile_with_zero_entities(self) -> None:
        builder = BaselineBuilder()
        profile = builder.build_from_events([])
        assert profile.entity_count == 0
        assert profile.total_events_processed == 0

    def test_user_entity_baseline_has_correct_observation_count(self) -> None:
        builder = BaselineBuilder()
        events = make_hospital_batch(15)
        profile = builder.build_from_events(events)
        user_key = EntityKey(entity_type="user", entity_id="svc-iis")
        eb = profile.get_entity(user_key)
        assert eb is not None
        assert eb.observation_count == 15

    def test_mixed_sources_produce_multiple_source_entities(self) -> None:
        builder = BaselineBuilder()
        events = make_mixed_events(hospital=10, dc=5, ot=5, attacker=2)
        profile = builder.build_from_events(events)
        source_keys = [k for k in profile.all_entity_keys() if k.entity_type == "source"]
        assert len(source_keys) == 4

    def test_last_report_set_after_build(self) -> None:
        builder = BaselineBuilder()
        builder.build_from_events(make_hospital_batch(5))
        assert builder.last_report is not None
        assert builder.last_report.total_events_read == 5

    def test_last_report_duration_positive(self) -> None:
        builder = BaselineBuilder()
        builder.build_from_events(make_hospital_batch(50))
        assert builder.last_report is not None
        assert builder.last_report.duration_seconds is not None
        assert builder.last_report.duration_seconds >= 0

    def test_entity_type_counts_populated(self) -> None:
        builder = BaselineBuilder()
        events = make_hospital_batch(10)
        profile = builder.build_from_events(events)
        assert "user" in profile.entity_type_counts
        assert "host" in profile.entity_type_counts

    def test_restrict_to_user_dimension_only(self) -> None:
        builder = BaselineBuilder(dimensions={"user"})
        events = make_hospital_batch(10)
        profile = builder.build_from_events(events)
        types = {k.entity_type for k in profile.all_entity_keys()}
        assert types == {"user"}

    def test_two_builds_produce_different_profile_ids(self) -> None:
        builder = BaselineBuilder()
        events = make_hospital_batch(5)
        p1 = builder.build_from_events(events)
        p2 = builder.build_from_events(events)
        assert p1.profile_id != p2.profile_id

    def test_deterministic_entity_count_same_input(self) -> None:
        builder = BaselineBuilder()
        events = make_hospital_batch(10)
        p1 = builder.build_from_events(events)
        p2 = builder.build_from_events(events)
        assert p1.entity_count == p2.entity_count

    def test_ot_entity_has_modbus_baseline(self) -> None:
        builder = BaselineBuilder(dimensions={"host"})
        events = make_ot_batch(10)
        profile = builder.build_from_events(events)
        ot_key = EntityKey(entity_type="host", entity_id="ot-node-01")
        eb = profile.get_entity(ot_key)
        assert eb is not None
        assert eb.modbus is not None

    def test_dc_entity_has_auth_baseline(self) -> None:
        builder = BaselineBuilder(dimensions={"host"})
        events = [make_dc_event() for _ in range(5)]
        profile = builder.build_from_events(events)
        dc_key = EntityKey(entity_type="host", entity_id="dc01")
        eb = profile.get_entity(dc_key)
        assert eb is not None
        assert eb.auth is not None


# ===========================================================================
# build_from_file — file-based build
# ===========================================================================

class TestBuildFromFile:

    def test_build_from_existing_file(self, tmp_path: Path, normalized_jsonl: Path) -> None:
        builder = BaselineBuilder(input_file=normalized_jsonl)
        profile = builder.build_from_file()
        assert isinstance(profile, BaselineProfile)
        assert profile.total_events_processed == 30

    def test_missing_file_raises_input_error(self, tmp_path: Path) -> None:
        missing = tmp_path / "missing.jsonl"
        builder = BaselineBuilder(input_file=missing)
        with pytest.raises(BaselineInputError):
            builder.build_from_file()

    def test_empty_file_raises_input_error(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty.jsonl"
        empty.write_text("", encoding="utf-8")
        builder = BaselineBuilder(input_file=empty)
        with pytest.raises(BaselineInputError):
            builder.build_from_file()

    def test_last_report_input_file_set(self, normalized_jsonl: Path) -> None:
        builder = BaselineBuilder(input_file=normalized_jsonl)
        builder.build_from_file()
        assert builder.last_report is not None
        assert builder.last_report.input_file is not None

    def test_full_normalized_output_all_sources(
        self, tmp_path: Path, full_normalized_jsonl: Path
    ) -> None:
        builder = BaselineBuilder(input_file=full_normalized_jsonl)
        profile = builder.build_from_file()
        # 30+20+15+5=70 events
        assert profile.total_events_processed == 70
        source_keys = [k for k in profile.all_entity_keys() if k.entity_type == "source"]
        assert len(source_keys) == 4
