"""
tests/unit/metrics/test_collectors.py
========================================
Unit tests for all 5 metric collectors.
Tests verify:
  - Correct domain and name registration
  - COMPUTED values from real data
  - INSUFFICIENT_DATA when no data provided
  - UNAVAILABLE for future-module collectors
  - Isolation: missing data doesn't crash
"""

from __future__ import annotations

import pytest

from backend.metrics.collectors import get_all_collectors, get_collector_names
from backend.metrics.collectors.baseline import BaselineMetricsCollector
from backend.metrics.collectors.detection import DetectionMetricsCollector
from backend.metrics.collectors.feature import FeatureMetricsCollector
from backend.metrics.collectors.health import PlatformHealthCollector
from backend.metrics.collectors.pipeline import PipelineMetricsCollector
from backend.metrics.collectors.response import ResponseMetricsCollector
from backend.metrics.models import MetricAvailability, MetricDomain

from tests.unit.metrics.conftest import (
    make_baseline_profile,
    make_feature_pipeline_report,
    make_mock_norm_report,
)


# ===========================================================================
# Registry
# ===========================================================================

class TestCollectorRegistry:

    def test_all_six_collectors_registered(self) -> None:
        names = get_collector_names()
        assert "pipeline" in names
        assert "baseline" in names
        assert "feature" in names
        assert "detection" in names
        assert "response" in names
        assert "platform_health" in names

    def test_get_all_collectors_returns_instances(self) -> None:
        collectors = get_all_collectors()
        assert len(collectors) == 6

    def test_collector_names_unique(self) -> None:
        names = get_collector_names()
        assert len(names) == len(set(names))

    def test_collectors_have_correct_domain(self) -> None:
        domain_map = {c.name: c.domain for c in get_all_collectors()}
        assert domain_map["pipeline"] == MetricDomain.PIPELINE
        assert domain_map["baseline"] == MetricDomain.BASELINE
        assert domain_map["feature"] == MetricDomain.FEATURE
        assert domain_map["detection"] == MetricDomain.DETECTION
        assert domain_map["response"] == MetricDomain.RESPONSE
        assert domain_map["platform_health"] == MetricDomain.PLATFORM_HEALTH


# ===========================================================================
# PipelineMetricsCollector
# ===========================================================================

class TestPipelineCollector:

    def test_cold_start_all_insufficient(self) -> None:
        c = PipelineMetricsCollector()
        result = c.collect()
        assert result.events_normalized.availability == MetricAvailability.INSUFFICIENT_DATA

    def test_with_norm_report_events_computed(self) -> None:
        c = PipelineMetricsCollector()
        norm = make_mock_norm_report(normalized=1000, failed=10, duration=5.0)
        result = c.collect(norm_report=norm)
        assert result.events_normalized.is_computed
        assert result.events_normalized.safe_float() == 1000.0

    def test_error_rate_correct(self) -> None:
        c = PipelineMetricsCollector()
        norm = make_mock_norm_report(normalized=990, failed=10)
        result = c.collect(norm_report=norm)
        assert abs(result.normalization_error_rate.safe_float() - 10 / 1000) < 1e-6

    def test_event_rate_computed(self) -> None:
        c = PipelineMetricsCollector()
        norm = make_mock_norm_report(normalized=1000, duration=5.0)
        result = c.collect(norm_report=norm)
        assert result.event_processing_rate.is_computed
        assert abs(result.event_processing_rate.safe_float() - 200.0) < 1e-2

    def test_feature_report_computed(self) -> None:
        c = PipelineMetricsCollector()
        feat = make_feature_pipeline_report(records=500, duration=2.0)
        result = c.collect(feature_report=feat)
        assert result.feature_records_produced.is_computed
        assert result.feature_records_produced.safe_float() == 500.0

    def test_feature_without_norm_no_crash(self) -> None:
        c = PipelineMetricsCollector()
        feat = make_feature_pipeline_report()
        result = c.collect(feature_report=feat)
        # norm fields should be insufficient
        assert result.events_normalized.availability == MetricAvailability.INSUFFICIENT_DATA
        # feature fields should be computed
        assert result.feature_records_produced.is_computed

    def test_end_to_end_latency_both_reports(self) -> None:
        c = PipelineMetricsCollector()
        norm = make_mock_norm_report(duration=5.0)
        feat = make_feature_pipeline_report(duration=2.0)
        result = c.collect(norm_report=norm, feature_report=feat)
        assert result.pipeline_end_to_end_latency_seconds.is_computed
        assert abs(result.pipeline_end_to_end_latency_seconds.safe_float() - 7.0) < 0.1

    def test_sources_processed_computed(self) -> None:
        c = PipelineMetricsCollector()
        norm = make_mock_norm_report(sources=4)
        result = c.collect(norm_report=norm)
        assert result.sources_processed.is_computed
        assert result.sources_processed.safe_float() == 4.0

    def test_zero_normalized_error_rate_insufficient(self) -> None:
        """Zero events → cannot compute meaningful error rate."""
        from unittest.mock import MagicMock
        c = PipelineMetricsCollector()
        norm = MagicMock()
        norm.events_normalized = 0
        norm.events_failed = 0
        norm.duration_seconds = 1.0
        norm.sources_processed = 0
        result = c.collect(norm_report=norm)
        assert result.normalization_error_rate.availability == MetricAvailability.INSUFFICIENT_DATA

    def test_safe_collect_never_raises(self) -> None:
        c = PipelineMetricsCollector()
        # Pass completely garbage kwargs
        result = c.safe_collect(norm_report="not_a_report", feature_report=42)
        # Must return something (or None) — never raise
        # Result may be None if an exception occurred


# ===========================================================================
# BaselineMetricsCollector
# ===========================================================================

class TestBaselineCollector:

    def test_cold_start_all_insufficient(self) -> None:
        c = BaselineMetricsCollector()
        result = c.collect()
        assert result.entity_count.availability == MetricAvailability.INSUFFICIENT_DATA

    def test_entity_count_computed(self) -> None:
        c = BaselineMetricsCollector()
        profile = make_baseline_profile(entity_count=5)
        result = c.collect(baseline_profile=profile)
        assert result.entity_count.is_computed
        assert result.entity_count.safe_float() == 5.0

    def test_total_events_computed(self) -> None:
        c = BaselineMetricsCollector()
        profile = make_baseline_profile(entity_count=3)
        result = c.collect(baseline_profile=profile)
        assert result.total_events_in_baseline.is_computed
        assert result.total_events_in_baseline.safe_float() == 100.0  # from fixture

    def test_mean_observations_computed(self) -> None:
        c = BaselineMetricsCollector()
        profile = make_baseline_profile(entity_count=3)
        result = c.collect(baseline_profile=profile)
        assert result.mean_observations_per_entity.is_computed
        # observation_count = 20 + i*5 for i in range(3) → 20, 25, 30 → mean=25
        assert abs(result.mean_observations_per_entity.safe_float() - 25.0) < 0.1

    def test_min_max_observations(self) -> None:
        c = BaselineMetricsCollector()
        profile = make_baseline_profile(entity_count=3)
        result = c.collect(baseline_profile=profile)
        assert result.min_observations_per_entity.is_computed
        assert result.max_observations_per_entity.is_computed
        assert result.min_observations_per_entity.safe_float() < result.max_observations_per_entity.safe_float()

    def test_baseline_age_computed(self) -> None:
        c = BaselineMetricsCollector()
        profile = make_baseline_profile(entity_count=1)
        result = c.collect(baseline_profile=profile)
        assert result.baseline_age_hours.is_computed
        assert result.baseline_age_hours.safe_float() > 0.0

    def test_sub_baseline_count_network(self) -> None:
        c = BaselineMetricsCollector()
        profile = make_baseline_profile(entity_count=3)
        result = c.collect(baseline_profile=profile)
        assert result.entities_with_network_baseline.is_computed
        assert result.entities_with_network_baseline.safe_float() == 3.0

    def test_sub_baseline_count_process_zero(self) -> None:
        """No entities in fixture have ProcessBaseline."""
        c = BaselineMetricsCollector()
        profile = make_baseline_profile(entity_count=3)
        result = c.collect(baseline_profile=profile)
        assert result.entities_with_process_baseline.safe_float() == 0.0

    def test_entity_type_breakdown_is_dict(self) -> None:
        c = BaselineMetricsCollector()
        profile = make_baseline_profile(entity_count=3)
        result = c.collect(baseline_profile=profile)
        assert result.entity_type_breakdown.is_computed
        assert isinstance(result.entity_type_breakdown.value, dict)


# ===========================================================================
# FeatureMetricsCollector
# ===========================================================================

class TestFeatureCollector:

    def test_schema_constants_always_computed(self) -> None:
        """Schema constants are always available regardless of data."""
        c = FeatureMetricsCollector()
        result = c.collect()
        assert result.feature_schema_version.is_computed
        assert result.feature_dimension.is_computed
        assert result.feature_dimension.safe_float() == 56.0

    def test_with_feature_report(self) -> None:
        c = FeatureMetricsCollector()
        feat = make_feature_pipeline_report(records=500, errors=2, warnings=5)
        result = c.collect(feature_report=feat)
        assert result.total_feature_records.is_computed
        assert result.total_feature_records.safe_float() == 500.0

    def test_error_rate_computed(self) -> None:
        c = FeatureMetricsCollector()
        feat = make_feature_pipeline_report(records=500, errors=5)
        result = c.collect(feature_report=feat)
        assert result.extraction_error_rate.is_computed
        assert abs(result.extraction_error_rate.safe_float() - 5 / 500) < 1e-9

    def test_cold_start_metrics_with_no_data_insufficient(self) -> None:
        c = FeatureMetricsCollector()
        result = c.collect()
        assert result.cold_start_fraction.availability == MetricAvailability.INSUFFICIENT_DATA

    def test_novelty_stats_all_insufficient_no_data(self) -> None:
        c = FeatureMetricsCollector()
        result = c.collect()
        assert result.mean_novelty_count.availability == MetricAvailability.INSUFFICIENT_DATA
        assert result.novelty_rate.availability == MetricAvailability.INSUFFICIENT_DATA

    def test_zero_records_error_rate_insufficient(self) -> None:
        c = FeatureMetricsCollector()
        feat = make_feature_pipeline_report(records=0, errors=0)
        result = c.collect(feature_report=feat)
        assert result.extraction_error_rate.availability == MetricAvailability.INSUFFICIENT_DATA


# ===========================================================================
# DetectionMetricsCollector
# ===========================================================================

class TestDetectionCollector:

    def test_all_metrics_unavailable(self) -> None:
        c = DetectionMetricsCollector()
        result = c.collect()
        assert result.mean_time_to_detect_seconds.availability == MetricAvailability.UNAVAILABLE
        assert result.detection_rate.availability == MetricAvailability.UNAVAILABLE
        assert result.false_positive_rate.availability == MetricAvailability.UNAVAILABLE
        assert result.alerts_generated.availability == MetricAvailability.UNAVAILABLE

    def test_safe_collect_returns_model(self) -> None:
        c = DetectionMetricsCollector()
        result = c.safe_collect()
        assert result is not None

    def test_unavailable_values_have_reason(self) -> None:
        c = DetectionMetricsCollector()
        result = c.collect()
        assert result.detection_rate.description is not None


# ===========================================================================
# ResponseMetricsCollector
# ===========================================================================

class TestResponseCollector:

    def test_all_metrics_unavailable(self) -> None:
        c = ResponseMetricsCollector()
        result = c.collect()
        assert result.mean_time_to_respond_seconds.availability == MetricAvailability.UNAVAILABLE
        assert result.automation_coverage.availability == MetricAvailability.UNAVAILABLE
        assert result.audit_coverage.availability == MetricAvailability.UNAVAILABLE
        assert result.actions_executed.availability == MetricAvailability.UNAVAILABLE

    def test_safe_collect_returns_model(self) -> None:
        c = ResponseMetricsCollector()
        result = c.safe_collect()
        assert result is not None


# ===========================================================================
# PlatformHealthCollector
# ===========================================================================

class TestHealthCollector:

    def test_schema_versions_computed(self) -> None:
        c = PlatformHealthCollector()
        result = c.collect()
        assert result.normalization_schema_version.is_computed
        assert result.baseline_schema_version.is_computed
        assert result.feature_schema_version.is_computed
        assert result.metrics_schema_version.is_computed

    def test_components_not_empty(self) -> None:
        c = PlatformHealthCollector()
        result = c.collect()
        assert len(result.components) > 0

    def test_future_modules_not_implemented(self) -> None:
        from backend.metrics.models import ComponentStatus
        c = PlatformHealthCollector()
        result = c.collect()
        future = [comp for comp in result.components if comp.status == ComponentStatus.NOT_IMPLEMENTED]
        assert len(future) >= 2  # detection_core, response_orchestrator, llm_enrichment

    def test_metrics_engine_self_reports_healthy(self) -> None:
        from backend.metrics.models import ComponentStatus
        c = PlatformHealthCollector()
        result = c.collect()
        metrics_comp = result.component_by_name("metrics_engine")
        assert metrics_comp is not None
        assert metrics_comp.status == ComponentStatus.HEALTHY

    def test_app_environment_computed(self) -> None:
        c = PlatformHealthCollector()
        result = c.collect()
        assert result.app_environment.is_computed
        assert result.app_environment.value in ("development", "staging", "production")

    def test_feature_flags_is_list(self) -> None:
        c = PlatformHealthCollector()
        result = c.collect()
        assert result.feature_flags_enabled.is_computed
        assert isinstance(result.feature_flags_enabled.value, list)
