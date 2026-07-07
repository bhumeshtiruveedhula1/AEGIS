"""
tests/unit/metrics/conftest.py
================================
Shared fixtures for Module 2.3 metrics tests.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from backend.baseline.models import (
    AuthBaseline,
    BaselineProfile,
    EntityBaseline,
    EntityKey,
    ModbusBaseline,
    NetworkBaseline,
    NumericStats,
    ProcessBaseline,
    TimePattern,
)
from backend.features.models import (
    FEATURE_SCHEMA_VERSION,
    FeaturePipelineReport,
    FeatureRecord,
    FeatureVector,
)
from backend.metrics.models import (
    BaselineMetrics,
    DetectionMetrics,
    FeatureMetrics,
    MetricAvailability,
    MetricDomain,
    MetricSnapshot,
    MetricValue,
    PipelineMetrics,
    PlatformHealthMetrics,
    ResponseMetrics,
    ComponentHealth,
    ComponentStatus,
)
from backend.shared.utils.id_utils import generate_id

FIXED_TS = datetime(2024, 1, 15, 9, 30, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# MetricValue factories
# ---------------------------------------------------------------------------

def mv_computed(value: Any, unit: str = "count") -> MetricValue:
    return MetricValue.computed(value, unit=unit)


def mv_unavailable() -> MetricValue:
    return MetricValue.unavailable("Test unavailable.")


def mv_insufficient() -> MetricValue:
    return MetricValue.insufficient("Test insufficient data.")


# ---------------------------------------------------------------------------
# Domain model factories
# ---------------------------------------------------------------------------

def make_pipeline_metrics(
    events_normalized: int = 1000,
    events_failed: int = 10,
    duration: float = 5.0,
    feature_records: int = 4000,
) -> PipelineMetrics:
    error_rate = events_failed / (events_normalized + events_failed)
    return PipelineMetrics(
        events_normalized=mv_computed(events_normalized),
        events_failed=mv_computed(events_failed),
        normalization_error_rate=mv_computed(round(error_rate, 6), unit="ratio"),
        sources_processed=mv_computed(4),
        normalization_duration_seconds=mv_computed(duration, unit="seconds"),
        event_processing_rate=mv_computed(round(events_normalized / duration, 2), unit="events/second"),
        feature_records_produced=mv_computed(feature_records),
        feature_extraction_errors=mv_computed(2),
        feature_generation_rate=mv_computed(round(feature_records / duration, 2), unit="records/second"),
        feature_extraction_duration_seconds=mv_computed(2.5, unit="seconds"),
        pipeline_end_to_end_latency_seconds=mv_computed(round(duration + 2.5, 2), unit="seconds"),
    )


def make_baseline_metrics(entity_count: int = 50) -> BaselineMetrics:
    return BaselineMetrics(
        entity_count=mv_computed(entity_count),
        entity_type_breakdown=mv_computed({"user": 25, "host": 15, "source": 10}),
        baseline_coverage_ratio=mv_computed(0.05, unit="ratio"),
        total_events_in_baseline=mv_computed(1000),
        mean_observations_per_entity=mv_computed(20.0),
        min_observations_per_entity=mv_computed(5),
        max_observations_per_entity=mv_computed(150),
        mean_baseline_window_days=mv_computed(13.5, unit="days"),
        baseline_age_hours=mv_computed(2.5, unit="hours"),
        baseline_profile_id=mv_computed("test-profile-001"),
        entities_with_network_baseline=mv_computed(40),
        entities_with_process_baseline=mv_computed(30),
        entities_with_auth_baseline=mv_computed(15),
        entities_with_modbus_baseline=mv_computed(5),
    )


def make_feature_metrics() -> FeatureMetrics:
    return FeatureMetrics(
        feature_schema_version=mv_computed(FEATURE_SCHEMA_VERSION),
        feature_dimension=mv_computed(56),
        total_feature_records=mv_computed(4000),
        unique_entities_extracted=mv_computed(50),
        baseline_available_fraction=mv_computed(0.8, unit="ratio"),
        cold_start_fraction=mv_computed(0.2, unit="ratio"),
        mean_novelty_count=mv_computed(1.5),
        max_novelty_count=mv_computed(8),
        novelty_rate=mv_computed(0.35, unit="ratio"),
        extraction_error_rate=mv_computed(0.001, unit="ratio"),
        extraction_warning_rate=mv_computed(0.005, unit="ratio"),
    )


def make_detection_metrics() -> DetectionMetrics:
    return DetectionMetrics(
        mean_time_to_detect_seconds=mv_unavailable(),
        detection_rate=mv_unavailable(),
        false_positive_rate=mv_unavailable(),
        true_positive_count=mv_unavailable(),
        false_positive_count=mv_unavailable(),
        alerts_generated=mv_unavailable(),
        anomaly_score_mean=mv_unavailable(),
        anomaly_score_p95=mv_unavailable(),
    )


def make_response_metrics() -> ResponseMetrics:
    return ResponseMetrics(
        mean_time_to_respond_seconds=mv_unavailable(),
        automation_coverage=mv_unavailable(),
        audit_coverage=mv_unavailable(),
        actions_executed=mv_unavailable(),
        actions_approved=mv_unavailable(),
        actions_rejected=mv_unavailable(),
    )


def make_health_metrics() -> PlatformHealthMetrics:
    return PlatformHealthMetrics(
        normalization_schema_version=mv_computed("1.0"),
        baseline_schema_version=mv_computed("1.0.0"),
        feature_schema_version=mv_computed(FEATURE_SCHEMA_VERSION),
        metrics_schema_version=mv_computed("1.0.0"),
        components=[
            ComponentHealth(name="normalization_pipeline", status=ComponentStatus.HEALTHY),
            ComponentHealth(name="baseline_system", status=ComponentStatus.HEALTHY),
            ComponentHealth(name="feature_engine", status=ComponentStatus.HEALTHY),
            ComponentHealth(name="metrics_engine", status=ComponentStatus.HEALTHY),
            ComponentHealth(name="detection_core", status=ComponentStatus.NOT_IMPLEMENTED),
        ],
        feature_flags_enabled=mv_computed(["feature_ingestion_enabled"]),
        app_environment=mv_computed("development"),
        collection_timestamp=mv_computed(FIXED_TS.isoformat()),
    )


def make_snapshot(
    events_normalized: int = 1000,
    entity_count: int = 50,
    tags: dict | None = None,
) -> MetricSnapshot:
    return MetricSnapshot(
        collected_at=FIXED_TS,
        collection_duration_seconds=0.05,
        pipeline=make_pipeline_metrics(events_normalized=events_normalized),
        baseline=make_baseline_metrics(entity_count=entity_count),
        feature=make_feature_metrics(),
        detection=make_detection_metrics(),
        response=make_response_metrics(),
        health=make_health_metrics(),
        tags=tags or {},
    )


# ---------------------------------------------------------------------------
# Baseline data factories (from Module 2.1 models)
# ---------------------------------------------------------------------------

def make_baseline_profile(entity_count: int = 3) -> BaselineProfile:
    entities = {}
    entity_types = ["user", "host", "source"]
    for i in range(entity_count):
        etype = entity_types[i % len(entity_types)]
        key = EntityKey(entity_type=etype, entity_id=f"entity-{i}")
        bl = EntityBaseline(
            entity_key=key,
            observation_count=20 + i * 5,
            first_seen=datetime(2024, 1, 1, tzinfo=UTC),
            last_seen=datetime(2024, 1, 14, tzinfo=UTC),
            event_type_distribution={"NetworkConnect": 20},
            action_distribution={"connect": 20},
            result_distribution={"success": 18, "failure": 2},
            source_distribution={etype: 20},
            time_pattern=TimePattern(
                hourly_buckets=[0] * 24,
                daily_buckets=[0] * 7,
                total_events=20,
            ),
            network=NetworkBaseline(
                unique_src_ips={"10.0.0.1"},
                unique_dst_ips={"10.0.0.2"},
                port_distribution={"443": 20},
                protocol_distribution={"tcp": 20},
                connection_count=20,
            ),
        )
        entities[key.storage_key] = bl

    return BaselineProfile(
        profile_id=generate_id(),
        built_at=datetime(2024, 1, 14, 7, 0, tzinfo=UTC),
        total_events_processed=100,
        entities=entities,
        entity_type_counts={
            et: sum(1 for k in entities if k.startswith(et)) for et in entity_types
        },
    )


def make_feature_pipeline_report(
    records: int = 500,
    errors: int = 2,
    warnings: int = 5,
    duration: float = 1.5,
) -> FeaturePipelineReport:
    from datetime import timedelta
    return FeaturePipelineReport(
        started_at=FIXED_TS,
        completed_at=FIXED_TS + timedelta(seconds=duration),
        events_read=100,
        events_skipped=0,
        feature_records_written=records,
        entities_extracted=50,
        baseline_available=True,
        baseline_profile_id="test-profile-001",
        extraction_errors=errors,
        extraction_warnings=warnings,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
    )


def make_mock_norm_report(
    normalized: int = 1000,
    failed: int = 10,
    duration: float = 5.0,
    sources: int = 4,
) -> MagicMock:
    report = MagicMock()
    report.events_normalized = normalized
    report.events_failed = failed
    report.duration_seconds = duration
    report.sources_processed = sources
    report.started_at = FIXED_TS
    report.completed_at = FIXED_TS
    return report


# ---------------------------------------------------------------------------
# pytest fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def pipeline_metrics() -> PipelineMetrics:
    return make_pipeline_metrics()


@pytest.fixture
def baseline_metrics() -> BaselineMetrics:
    return make_baseline_metrics()


@pytest.fixture
def feature_metrics() -> FeatureMetrics:
    return make_feature_metrics()


@pytest.fixture
def metric_snapshot() -> MetricSnapshot:
    return make_snapshot()


@pytest.fixture
def baseline_profile() -> BaselineProfile:
    return make_baseline_profile(entity_count=5)


@pytest.fixture
def feature_pipeline_report() -> FeaturePipelineReport:
    return make_feature_pipeline_report()


@pytest.fixture
def mock_norm_report() -> MagicMock:
    return make_mock_norm_report()
