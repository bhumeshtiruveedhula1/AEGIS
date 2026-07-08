"""
tests/unit/features/test_models.py
====================================
Unit tests for Feature Engine data models.
"""

from __future__ import annotations

import math

import pytest

from backend.features.models import (
    FEATURE_DIMENSION,
    FEATURE_GROUPS,
    FEATURE_SCHEMA_VERSION,
    ALL_FEATURE_NAMES,
    FeaturePipelineReport,
    FeatureRecord,
    FeatureSchema,
    FeatureVector,
)
from backend.baseline.models import EntityKey
from tests.unit.features.conftest import make_hospital_event, FIXED_TS


# ===========================================================================
# Schema constants
# ===========================================================================

class TestSchemaConstants:

    def test_feature_dimension_matches_all_names(self) -> None:
        assert FEATURE_DIMENSION == len(ALL_FEATURE_NAMES)

    def test_feature_dimension_is_56(self) -> None:
        assert FEATURE_DIMENSION == 56

    def test_all_groups_present(self) -> None:
        expected = {"temporal", "frequency", "network", "process", "auth", "ot",
                    "baseline_presence", "entity_activity"}
        assert set(FEATURE_GROUPS.keys()) == expected

    def test_group_feature_names_sum_to_dimension(self) -> None:
        total = sum(len(names) for names in FEATURE_GROUPS.values())
        assert total == FEATURE_DIMENSION

    def test_all_feature_names_unique(self) -> None:
        assert len(ALL_FEATURE_NAMES) == len(set(ALL_FEATURE_NAMES))

    def test_schema_version_format(self) -> None:
        parts = FEATURE_SCHEMA_VERSION.split(".")
        assert len(parts) == 3
        assert all(p.isdigit() for p in parts)


# ===========================================================================
# FeatureSchema
# ===========================================================================

class TestFeatureSchema:

    def test_index_of_known_feature(self) -> None:
        schema = FeatureSchema()
        idx = schema.index_of("hour_of_day")
        assert idx == 0

    def test_index_of_last_feature(self) -> None:
        schema = FeatureSchema()
        idx = schema.index_of(ALL_FEATURE_NAMES[-1])
        assert idx == FEATURE_DIMENSION - 1

    def test_index_of_unknown_raises_key_error(self) -> None:
        schema = FeatureSchema()
        with pytest.raises(KeyError):
            schema.index_of("nonexistent_feature")

    def test_group_of_known_feature(self) -> None:
        schema = FeatureSchema()
        assert schema.group_of("hour_of_day") == "temporal"
        assert schema.group_of("dst_ip_is_novel") == "network"
        assert schema.group_of("modbus_register_z_score") == "ot"

    def test_group_of_unknown_returns_none(self) -> None:
        schema = FeatureSchema()
        assert schema.group_of("nonexistent") is None

    def test_feature_dimension_correct(self) -> None:
        schema = FeatureSchema()
        assert schema.feature_dimension == FEATURE_DIMENSION


# ===========================================================================
# FeatureVector
# ===========================================================================

class TestFeatureVector:
    """Tests for FeatureVector construction, validation, and helpers."""

    def _make_key(self) -> EntityKey:
        return EntityKey(entity_type="user", entity_id="svc-iis")

    def test_empty_values_filled_with_zeros(self) -> None:
        key = self._make_key()
        vec = FeatureVector(entity_key=key, values={})
        assert len(vec.values) == FEATURE_DIMENSION
        assert all(v == 0.0 for v in vec.values.values())

    def test_partial_values_filled_with_zeros(self) -> None:
        key = self._make_key()
        vec = FeatureVector(entity_key=key, values={"hour_of_day": 9.0})
        assert vec.values["hour_of_day"] == 9.0
        assert vec.values["day_of_week"] == 0.0

    def test_nan_values_replaced_with_zero(self) -> None:
        key = self._make_key()
        vec = FeatureVector(entity_key=key, values={"hour_of_day": float("nan")})
        assert vec.values["hour_of_day"] == 0.0

    def test_inf_values_replaced_with_zero(self) -> None:
        key = self._make_key()
        vec = FeatureVector(entity_key=key, values={"hour_of_day": float("inf")})
        assert vec.values["hour_of_day"] == 0.0

    def test_negative_inf_replaced_with_zero(self) -> None:
        key = self._make_key()
        vec = FeatureVector(entity_key=key, values={"hour_of_day": float("-inf")})
        assert vec.values["hour_of_day"] == 0.0

    def test_to_array_length_correct(self) -> None:
        key = self._make_key()
        vec = FeatureVector(entity_key=key, values={})
        arr = vec.to_array()
        assert len(arr) == FEATURE_DIMENSION

    def test_to_array_order_matches_all_feature_names(self) -> None:
        key = self._make_key()
        values = {name: float(i) for i, name in enumerate(ALL_FEATURE_NAMES)}
        vec = FeatureVector(entity_key=key, values=values)
        arr = vec.to_array()
        for i, name in enumerate(ALL_FEATURE_NAMES):
            assert arr[i] == float(i)

    def test_group_temporal(self) -> None:
        key = self._make_key()
        vec = FeatureVector(entity_key=key, values={"hour_of_day": 9.0})
        grp = vec.group("temporal")
        assert "hour_of_day" in grp
        assert "dst_ip_is_novel" not in grp

    def test_group_unknown_raises_key_error(self) -> None:
        key = self._make_key()
        vec = FeatureVector(entity_key=key, values={})
        with pytest.raises(KeyError):
            vec.group("invalid_group")

    def test_get_known_feature(self) -> None:
        key = self._make_key()
        vec = FeatureVector(entity_key=key, values={"hour_of_day": 9.0})
        assert vec.get("hour_of_day") == 9.0

    def test_get_missing_returns_default(self) -> None:
        key = self._make_key()
        vec = FeatureVector(entity_key=key, values={})
        assert vec.get("nonexistent", 99.0) == 99.0

    def test_is_valid_all_zeros(self) -> None:
        key = self._make_key()
        vec = FeatureVector(entity_key=key, values={})
        assert vec.is_valid()

    def test_novelty_flags_returns_is_novel_features(self) -> None:
        key = self._make_key()
        vec = FeatureVector(entity_key=key, values={"dst_ip_is_novel": 1.0})
        flags = vec.novelty_flags()
        assert "dst_ip_is_novel" in flags
        assert "hour_of_day" not in flags

    def test_novelty_count_zero_when_no_novelty(self) -> None:
        key = self._make_key()
        vec = FeatureVector(entity_key=key, values={})
        assert vec.novelty_count() == 0

    def test_novelty_count_correct_when_flagged(self) -> None:
        key = self._make_key()
        vec = FeatureVector(entity_key=key, values={
            "dst_ip_is_novel": 1.0,
            "process_is_novel": 1.0,
            "supervisory_host_is_novel": 0.0,
        })
        assert vec.novelty_count() == 2

    def test_schema_version_set_correctly(self) -> None:
        key = self._make_key()
        vec = FeatureVector(entity_key=key, values={})
        assert vec.schema_version == FEATURE_SCHEMA_VERSION


# ===========================================================================
# FeatureRecord
# ===========================================================================

class TestFeatureRecord:

    def _make_record(self) -> FeatureRecord:
        key = EntityKey(entity_type="user", entity_id="svc-iis")
        vec = FeatureVector(entity_key=key, values={"hour_of_day": 9.0})
        event = make_hospital_event()
        return FeatureRecord(
            event_id=event.event_id,
            event_type=event.event_type,
            event_source=event.source,
            event_timestamp=event.timestamp,
            event_host=str(event.host),
            event_user=str(event.user),
            entity_key=key,
            baseline_available=True,
            feature_vector=vec,
        )

    def test_record_has_record_id(self) -> None:
        r = self._make_record()
        import uuid
        uuid.UUID(r.record_id)

    def test_to_flat_dict_contains_all_features(self) -> None:
        r = self._make_record()
        flat = r.to_flat_dict()
        assert "feat_hour_of_day" in flat
        assert flat["feat_hour_of_day"] == 9.0

    def test_to_flat_dict_contains_metadata(self) -> None:
        r = self._make_record()
        flat = r.to_flat_dict()
        assert "event_id" in flat
        assert "entity_type" in flat
        assert flat["entity_type"] == "user"

    def test_to_flat_dict_length(self) -> None:
        r = self._make_record()
        flat = r.to_flat_dict()
        # metadata keys + feat_ keys
        feat_keys = [k for k in flat if k.startswith("feat_")]
        assert len(feat_keys) == FEATURE_DIMENSION

    def test_schema_version_in_record(self) -> None:
        r = self._make_record()
        assert r.schema_version == FEATURE_SCHEMA_VERSION


# ===========================================================================
# FeaturePipelineReport
# ===========================================================================

class TestFeaturePipelineReport:

    def test_duration_none_when_not_completed(self) -> None:
        report = FeaturePipelineReport(completed_at=None)
        assert report.duration_seconds is None

    def test_duration_positive_when_completed(self) -> None:
        from datetime import timedelta
        from datetime import UTC
        start = FIXED_TS
        report = FeaturePipelineReport(
            started_at=start,
            completed_at=start.replace(second=5),
        )
        assert report.duration_seconds is not None
        assert report.duration_seconds >= 0

    def test_cold_start_true_when_no_baseline(self) -> None:
        report = FeaturePipelineReport(baseline_available=False)
        assert report.cold_start is True

    def test_cold_start_false_when_baseline_present(self) -> None:
        report = FeaturePipelineReport(baseline_available=True)
        assert report.cold_start is False

    def test_records_per_second_none_when_not_completed(self) -> None:
        report = FeaturePipelineReport(completed_at=None)
        assert report.records_per_second is None
