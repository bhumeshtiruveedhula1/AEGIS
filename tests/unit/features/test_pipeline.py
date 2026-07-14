"""
tests/unit/features/test_pipeline.py
======================================
Unit tests for FeaturePipeline.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from backend.baseline.models import EntityKey
from backend.baseline.reader_api import BaselineReader
from backend.features.models import ALL_FEATURE_NAMES, FEATURE_DIMENSION
from backend.features.pipeline import FeaturePipeline
from tests.unit.features.conftest import (
    make_dc_event,
    make_hospital_baseline,
    make_hospital_event,
    make_ot_event,
)


def _make_mock_reader(
    user_baseline=None,
    host_baseline=None,
    source_baseline=None,
    user_host_baseline=None,
    is_ready: bool = True,
) -> MagicMock:
    """Build a mock BaselineReader that returns specific baselines."""
    reader = MagicMock(spec=BaselineReader)
    reader.is_ready = is_ready
    reader.profile_id = "test-profile-001"

    def get_entity(key: EntityKey):
        if key.entity_type == "user":
            return user_baseline
        if key.entity_type == "host":
            return host_baseline
        if key.entity_type == "source":
            return source_baseline
        if key.entity_type == "user_host":
            return user_host_baseline
        return None

    reader.get_entity.side_effect = get_entity
    return reader


# ===========================================================================
# FeaturePipeline — cold start (no baseline)
# ===========================================================================


class TestFeaturePipelineColdStart:
    def test_returns_records_on_cold_start(self) -> None:
        reader = _make_mock_reader(is_ready=False)
        pipeline = FeaturePipeline(baseline_reader=reader)
        records = pipeline.process_event(make_hospital_event())
        # Should still emit records (cold-start records with 0.0 defaults)
        assert len(records) > 0

    def test_cold_start_baseline_available_is_false(self) -> None:
        reader = _make_mock_reader(is_ready=False)
        pipeline = FeaturePipeline(baseline_reader=reader)
        records = pipeline.process_event(make_hospital_event())
        assert all(not r.baseline_available for r in records)

    def test_cold_start_vector_length(self) -> None:
        reader = _make_mock_reader(is_ready=False)
        pipeline = FeaturePipeline(baseline_reader=reader)
        records = pipeline.process_event(make_hospital_event())
        for r in records:
            assert len(r.feature_vector.to_array()) == FEATURE_DIMENSION

    def test_cold_start_all_novelty_flags_zero(self) -> None:
        reader = _make_mock_reader(is_ready=False)
        pipeline = FeaturePipeline(baseline_reader=reader)
        records = pipeline.process_event(make_hospital_event())
        for r in records:
            assert r.feature_vector.novelty_count() == 0


# ===========================================================================
# FeaturePipeline — with baseline
# ===========================================================================


class TestFeaturePipelineWithBaseline:
    def test_baseline_available_true(self) -> None:
        baseline = make_hospital_baseline()
        reader = _make_mock_reader(user_baseline=baseline)
        pipeline = FeaturePipeline(baseline_reader=reader)
        records = pipeline.process_event(make_hospital_event())
        assert any(r.baseline_available for r in records)

    def test_known_process_not_novel(self) -> None:
        baseline = make_hospital_baseline()
        reader = _make_mock_reader(user_baseline=baseline)
        pipeline = FeaturePipeline(baseline_reader=reader)
        records = pipeline.process_event(make_hospital_event())
        # Select the user record — only user_baseline is provided in this test.
        # Each dimension uses its own baseline; user record has baseline_available=True.
        user_record = next(r for r in records if r.entity_key.entity_type == "user")
        assert user_record.feature_vector.get("process_is_novel") == 0.0

    def test_novel_process_flagged(self) -> None:
        baseline = make_hospital_baseline()
        reader = _make_mock_reader(user_baseline=baseline)
        pipeline = FeaturePipeline(baseline_reader=reader)
        event = make_hospital_event({"process": "evil.exe"})
        records = pipeline.process_event(event)
        # Select the user record — only user_baseline is provided in this test.
        # Each dimension uses its own baseline; user record has baseline_available=True
        # and correctly detects the novel process against the user entity's history.
        user_record = next(r for r in records if r.entity_key.entity_type == "user")
        assert user_record.feature_vector.get("process_is_novel") == 1.0

    def test_novel_dst_ip_flagged(self) -> None:
        baseline = make_hospital_baseline()
        reader = _make_mock_reader(user_baseline=baseline)
        pipeline = FeaturePipeline(baseline_reader=reader)
        event = make_hospital_event({"dst_ip": "10.99.99.99"})
        records = pipeline.process_event(event)
        # Select the user record — only user_baseline is provided in this test.
        # Each dimension uses its own baseline; user record has baseline_available=True
        # and correctly detects the novel destination IP against the user entity's history.
        user_record = next(r for r in records if r.entity_key.entity_type == "user")
        assert user_record.feature_vector.get("dst_ip_is_novel") == 1.0


# ===========================================================================
# FeaturePipeline — entity dimensions
# ===========================================================================


class TestFeaturePipelineDimensions:
    def test_emits_4_records_for_full_event(self) -> None:
        reader = _make_mock_reader()
        pipeline = FeaturePipeline(baseline_reader=reader, emit_all_dimensions=True)
        records = pipeline.process_event(make_hospital_event())
        # user, host, source, user_host
        assert len(records) == 4

    def test_primary_only_emits_1_record(self) -> None:
        reader = _make_mock_reader()
        pipeline = FeaturePipeline(baseline_reader=reader, primary_only=True)
        records = pipeline.process_event(make_hospital_event())
        assert len(records) == 1

    def test_entity_keys_cover_all_dimensions(self) -> None:
        reader = _make_mock_reader()
        pipeline = FeaturePipeline(baseline_reader=reader, emit_all_dimensions=True)
        records = pipeline.process_event(make_hospital_event())
        dims = {r.entity_key.entity_type for r in records}
        assert "user" in dims
        assert "host" in dims
        assert "source" in dims

    def test_baseline_presence_flags_correct(self) -> None:
        baseline = make_hospital_baseline()
        # Only user baseline available
        reader = _make_mock_reader(user_baseline=baseline)
        pipeline = FeaturePipeline(baseline_reader=reader)
        records = pipeline.process_event(make_hospital_event())
        # All records share the same baseline-presence context (injected by pipeline)
        # regardless of which dimension they represent.
        assert records[0].feature_vector.get("has_user_baseline") == 1.0
        assert records[0].feature_vector.get("has_host_baseline") == 0.0

    def test_each_dimension_uses_own_baseline(self) -> None:
        """
        Regression test for A1: each emitted FeatureRecord must use its own
        dimension's baseline, not the primary baseline shared across all dimensions.

        Setup: user_baseline exists (knows svchost.exe), host_baseline does NOT.
        Expected: user record sees process as not novel (known in user baseline).
                  host record sees process as novel (no host baseline -> 0.0 default).
        """
        baseline = make_hospital_baseline()  # knows svchost.exe
        reader = _make_mock_reader(user_baseline=baseline)  # only user baseline set
        pipeline = FeaturePipeline(baseline_reader=reader)
        event = make_hospital_event()  # process=svchost.exe (known in baseline)
        records = pipeline.process_event(event)

        user_record = next(r for r in records if r.entity_key.entity_type == "user")
        host_record = next(r for r in records if r.entity_key.entity_type == "host")

        # user has a baseline -> process_is_novel must be 0.0 (known process)
        assert user_record.baseline_available is True
        assert user_record.feature_vector.get("process_is_novel") == 0.0

        # host has NO baseline -> process_is_novel is 0.0 (cold-start default, not novel)
        # This is the correct cold-start behaviour: we cannot assert novelty without a baseline.
        assert host_record.baseline_available is False
        assert host_record.feature_vector.get("process_is_novel") == 0.0


# ===========================================================================
# FeaturePipeline — process_batch
# ===========================================================================


class TestFeaturePipelineBatch:
    def test_batch_returns_records_and_report(self) -> None:
        reader = _make_mock_reader(is_ready=False)
        pipeline = FeaturePipeline(baseline_reader=reader)
        events = [make_hospital_event(), make_dc_event(), make_ot_event()]
        records, report = pipeline.process_batch(events)
        assert len(records) > 0
        assert report.events_read == 3

    def test_batch_report_records_written(self) -> None:
        reader = _make_mock_reader(is_ready=False)
        pipeline = FeaturePipeline(baseline_reader=reader)
        events = [make_hospital_event()] * 5
        records, report = pipeline.process_batch(events)
        assert report.feature_records_written == len(records)

    def test_empty_batch(self) -> None:
        reader = _make_mock_reader(is_ready=False)
        pipeline = FeaturePipeline(baseline_reader=reader)
        records, report = pipeline.process_batch([])
        assert records == []
        assert report.events_read == 0


# ===========================================================================
# FeaturePipeline — determinism
# ===========================================================================


class TestFeaturePipelineDeterminism:
    def test_same_input_same_output(self) -> None:
        baseline = make_hospital_baseline()
        reader = _make_mock_reader(user_baseline=baseline)
        pipeline = FeaturePipeline(baseline_reader=reader, primary_only=True)
        event = make_hospital_event()
        records_a = pipeline.process_event(event)
        records_b = pipeline.process_event(event)
        assert records_a[0].feature_vector.to_array() == records_b[0].feature_vector.to_array()

    def test_feature_vector_length_57(self) -> None:
        # auth_unexpected_failure added to FEATURE_GROUPS['frequency'] during ML lab build
        baseline = make_hospital_baseline()
        reader = _make_mock_reader(user_baseline=baseline)
        pipeline = FeaturePipeline(baseline_reader=reader, primary_only=True)
        records = pipeline.process_event(make_hospital_event())
        assert len(records[0].feature_vector.to_array()) == 57

    def test_all_feature_names_present_in_vector(self) -> None:
        reader = _make_mock_reader(is_ready=False)
        pipeline = FeaturePipeline(baseline_reader=reader, primary_only=True)
        records = pipeline.process_event(make_hospital_event())
        vec = records[0].feature_vector
        for name in ALL_FEATURE_NAMES:
            assert name in vec.values, f"Missing feature: {name}"
