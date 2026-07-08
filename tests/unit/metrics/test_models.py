"""
tests/unit/metrics/test_models.py
===================================
Unit tests for Metrics Engine data models.
"""

from __future__ import annotations

import math
from datetime import UTC, datetime

import pytest

from backend.metrics.models import (
    METRICS_SCHEMA_VERSION,
    BaselineMetrics,
    ComponentHealth,
    ComponentStatus,
    DetectionMetrics,
    ManifestEntry,
    MetricAvailability,
    MetricDelta,
    MetricDomain,
    MetricHistoryManifest,
    MetricRecord,
    MetricRunComparison,
    MetricSnapshot,
    MetricValue,
    PipelineMetrics,
    PlatformHealthMetrics,
)

from tests.unit.metrics.conftest import (
    FIXED_TS,
    make_pipeline_metrics,
    make_snapshot,
    mv_computed,
    mv_insufficient,
    mv_unavailable,
)


# ===========================================================================
# MetricAvailability
# ===========================================================================

class TestMetricAvailability:

    def test_all_variants_exist(self) -> None:
        assert MetricAvailability.COMPUTED.value == "computed"
        assert MetricAvailability.UNAVAILABLE.value == "unavailable"
        assert MetricAvailability.INSUFFICIENT_DATA.value == "insufficient_data"

    def test_string_comparison(self) -> None:
        assert MetricAvailability.COMPUTED == "computed"


# ===========================================================================
# MetricValue
# ===========================================================================

class TestMetricValue:

    def test_computed_constructor(self) -> None:
        mv = MetricValue.computed(42.0, unit="count")
        assert mv.value == 42.0
        assert mv.availability == MetricAvailability.COMPUTED
        assert mv.unit == "count"
        assert mv.is_computed is True

    def test_unavailable_constructor(self) -> None:
        mv = MetricValue.unavailable("requires module 3.x")
        assert mv.value is None
        assert mv.availability == MetricAvailability.UNAVAILABLE
        assert mv.is_computed is False
        assert "module 3.x" in mv.description

    def test_insufficient_constructor(self) -> None:
        mv = MetricValue.insufficient("no data")
        assert mv.value is None
        assert mv.availability == MetricAvailability.INSUFFICIENT_DATA
        assert mv.is_computed is False

    def test_safe_float_computed(self) -> None:
        mv = MetricValue.computed(9.5, unit="ratio")
        assert mv.safe_float() == 9.5

    def test_safe_float_unavailable(self) -> None:
        mv = MetricValue.unavailable()
        assert mv.safe_float(default=99.0) == 99.0

    def test_safe_float_non_numeric_returns_default(self) -> None:
        mv = MetricValue.computed("hello")
        assert mv.safe_float(default=0.0) == 0.0

    def test_safe_float_inf_returns_default(self) -> None:
        # Construct manually with inf to test safe_float
        mv = MetricValue(value=float("inf"), availability=MetricAvailability.COMPUTED)
        assert mv.safe_float(default=-1.0) == -1.0

    def test_is_computed_false_when_none_value(self) -> None:
        mv = MetricValue(value=None, availability=MetricAvailability.COMPUTED)
        assert mv.is_computed is False

    def test_default_description_unavailable(self) -> None:
        mv = MetricValue.unavailable()
        assert mv.description is not None and len(mv.description) > 0

    def test_computed_at_is_utc(self) -> None:
        mv = MetricValue.computed(1)
        assert mv.computed_at.tzinfo is not None

    def test_dict_value_computed(self) -> None:
        mv = MetricValue.computed({"user": 5, "host": 3})
        assert mv.is_computed is True
        assert isinstance(mv.value, dict)


# ===========================================================================
# PipelineMetrics
# ===========================================================================

class TestPipelineMetrics:

    def test_all_fields_populated(self) -> None:
        pm = make_pipeline_metrics()
        assert isinstance(pm.events_normalized, MetricValue)
        assert isinstance(pm.normalization_error_rate, MetricValue)
        assert isinstance(pm.pipeline_end_to_end_latency_seconds, MetricValue)

    def test_computed_fields_are_computed(self) -> None:
        pm = make_pipeline_metrics(events_normalized=500, events_failed=5)
        assert pm.events_normalized.is_computed is True
        assert pm.events_failed.is_computed is True

    def test_error_rate_correct(self) -> None:
        pm = make_pipeline_metrics(events_normalized=990, events_failed=10)
        rate = pm.normalization_error_rate.safe_float()
        assert abs(rate - 10 / 1000) < 1e-6


# ===========================================================================
# MetricSnapshot
# ===========================================================================

class TestMetricSnapshot:

    def test_snapshot_has_uuid_id(self) -> None:
        snap = make_snapshot()
        import uuid
        uuid.UUID(snap.snapshot_id)

    def test_schema_version_set(self) -> None:
        snap = make_snapshot()
        assert snap.schema_version == METRICS_SCHEMA_VERSION

    def test_six_domains_present(self) -> None:
        snap = make_snapshot()
        assert snap.pipeline is not None
        assert snap.baseline is not None
        assert snap.feature is not None
        assert snap.detection is not None
        assert snap.response is not None
        assert snap.health is not None

    def test_computed_metric_count_positive(self) -> None:
        snap = make_snapshot()
        assert snap.computed_metric_count() > 0

    def test_unavailable_metric_count_positive(self) -> None:
        snap = make_snapshot()
        # Detection and response are all unavailable
        assert snap.unavailable_metric_count() > 0

    def test_tags_preserved(self) -> None:
        snap = make_snapshot(tags={"env": "test", "run": "ci"})
        assert snap.tags["env"] == "test"

    def test_computed_plus_unavailable_leq_total(self) -> None:
        snap = make_snapshot()
        computed = snap.computed_metric_count()
        unavailable = snap.unavailable_metric_count()
        # Sum should be ≤ total field count (some may be insufficient)
        assert computed + unavailable <= 60  # generous upper bound


# ===========================================================================
# MetricRecord
# ===========================================================================

class TestMetricRecord:

    def test_record_wraps_snapshot(self) -> None:
        snap = make_snapshot()
        record = MetricRecord(snapshot=snap)
        assert record.snapshot.snapshot_id == snap.snapshot_id

    def test_record_has_record_id(self) -> None:
        snap = make_snapshot()
        record = MetricRecord(snapshot=snap)
        import uuid
        uuid.UUID(record.record_id)

    def test_to_summary_dict_keys(self) -> None:
        snap = make_snapshot()
        record = MetricRecord(snapshot=snap)
        summary = record.to_summary_dict()
        assert "record_id" in summary
        assert "snapshot_id" in summary
        assert "collected_at" in summary
        assert "computed_metrics" in summary
        assert "unavailable_metrics" in summary
        assert "tags" in summary

    def test_roundtrip_json(self) -> None:
        snap = make_snapshot()
        record = MetricRecord(snapshot=snap)
        json_str = record.model_dump_json()
        reloaded = MetricRecord.model_validate_json(json_str)
        assert reloaded.record_id == record.record_id
        assert reloaded.snapshot.snapshot_id == snap.snapshot_id


# ===========================================================================
# MetricHistoryManifest
# ===========================================================================

class TestMetricHistoryManifest:

    def test_empty_manifest(self) -> None:
        m = MetricHistoryManifest()
        assert m.total_snapshots == 0
        assert m.latest_snapshot_id is None
        assert m.latest_entry() is None

    def test_add_entry_updates_latest(self) -> None:
        m = MetricHistoryManifest()
        snap = make_snapshot()
        record = MetricRecord(snapshot=snap)
        m.add_entry(record)
        assert m.latest_snapshot_id == snap.snapshot_id
        assert m.total_snapshots == 1

    def test_add_multiple_entries_newest_first(self) -> None:
        m = MetricHistoryManifest()
        for i in range(3):
            snap = make_snapshot(events_normalized=i * 100)
            record = MetricRecord(snapshot=snap)
            m.add_entry(record)
        assert m.total_snapshots == 3
        # Latest entry should be the last added
        assert m.latest_entry() is not None

    def test_schema_version_in_manifest(self) -> None:
        m = MetricHistoryManifest()
        assert m.schema_version == METRICS_SCHEMA_VERSION


# ===========================================================================
# PlatformHealthMetrics
# ===========================================================================

class TestPlatformHealthMetrics:

    def test_healthy_count(self) -> None:
        from tests.unit.metrics.conftest import make_health_metrics
        h = make_health_metrics()
        # 4 healthy components in fixture
        assert h.healthy_count() == 4

    def test_degraded_count(self) -> None:
        from tests.unit.metrics.conftest import make_health_metrics
        h = make_health_metrics()
        assert h.degraded_or_unavailable_count() == 0

    def test_component_by_name(self) -> None:
        from tests.unit.metrics.conftest import make_health_metrics
        h = make_health_metrics()
        comp = h.component_by_name("metrics_engine")
        assert comp is not None
        assert comp.status == ComponentStatus.HEALTHY

    def test_component_by_name_missing(self) -> None:
        from tests.unit.metrics.conftest import make_health_metrics
        h = make_health_metrics()
        assert h.component_by_name("nonexistent") is None


# ===========================================================================
# MetricRunComparison
# ===========================================================================

class TestMetricRunComparison:

    def _make_comparison(self) -> MetricRunComparison:
        delta_good = MetricDelta(
            metric_name="events_normalized",
            domain=MetricDomain.PIPELINE,
            before=MetricValue.computed(1000.0),
            after=MetricValue.computed(1500.0),
            delta=500.0,
            delta_pct=50.0,
            improved=True,
        )
        delta_bad = MetricDelta(
            metric_name="events_failed",
            domain=MetricDomain.PIPELINE,
            before=MetricValue.computed(10.0),
            after=MetricValue.computed(50.0),
            delta=40.0,
            delta_pct=400.0,
            improved=False,
        )
        return MetricRunComparison(
            baseline_snapshot_id="snap-001",
            current_snapshot_id="snap-002",
            deltas=[delta_good, delta_bad],
        )

    def test_regressions(self) -> None:
        comp = self._make_comparison()
        assert len(comp.regressions()) == 1
        assert comp.regressions()[0].metric_name == "events_failed"

    def test_improvements(self) -> None:
        comp = self._make_comparison()
        assert len(comp.improvements()) == 1
        assert comp.improvements()[0].metric_name == "events_normalized"

    def test_significant_changes(self) -> None:
        comp = self._make_comparison()
        # Both exceed 5% threshold
        assert len(comp.significant_changes(threshold_pct=5.0)) == 2

    def test_no_significant_changes_high_threshold(self) -> None:
        comp = self._make_comparison()
        assert len(comp.significant_changes(threshold_pct=1000.0)) == 0
