"""
backend.metrics — Metrics Collection & Evaluation Engine
=========================================================
Module 2.3 — Operation AEGIS Phase 2

Public API surface for the Metrics Engine.

The Metrics Engine is the platform's permanent observability and
evaluation subsystem. It collects, computes, persists and exposes
engineering metrics across all platform modules.

Quick Start
-----------
    from backend.metrics import MetricService, MetricDomain, MetricReader

    # Collect metrics after a pipeline run
    service = MetricService()
    snapshot = service.collect_all(
        norm_report=norm_report,
        feature_report=feature_report,
        feature_records=feature_records,
        baseline_profile=profile,
        baseline_reader=reader,
    )

    # Query the latest snapshot
    reader = service.reader
    events = reader.get_value(snapshot, MetricDomain.PIPELINE, "events_normalized")

    # Health status
    status = service.get_platform_status()

    # Trend analysis
    trend = reader.trend(MetricDomain.PIPELINE, "events_normalized")

    # Run comparison
    comparison = reader.compare_last_two()
"""

from __future__ import annotations

# Core models
from backend.metrics.models import (
    METRICS_SCHEMA_VERSION,
    BaselineMetrics,
    ComponentHealth,
    ComponentStatus,
    DetectionMetrics,
    FeatureMetrics,
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
    ResponseMetrics,
)

# Service, store and reader
from backend.metrics.service import MetricService
from backend.metrics.store import MetricStore
from backend.metrics.reader import MetricReader

# Exceptions
from backend.metrics.exceptions import (
    MetricCollectionError,
    MetricQueryError,
    MetricRegistryError,
    MetricStorageError,
    MetricVersionError,
    MetricsError,
)

# Collector utilities
from backend.metrics.collectors import (
    BaseCollector,
    get_all_collectors,
    get_collector_names,
    register_collector,
)

__all__ = [
    # Schema
    "METRICS_SCHEMA_VERSION",
    # Core models
    "MetricAvailability",
    "MetricValue",
    "MetricDomain",
    "PipelineMetrics",
    "BaselineMetrics",
    "FeatureMetrics",
    "DetectionMetrics",
    "ResponseMetrics",
    "ComponentStatus",
    "ComponentHealth",
    "PlatformHealthMetrics",
    "MetricSnapshot",
    "MetricRecord",
    "ManifestEntry",
    "MetricHistoryManifest",
    "MetricDelta",
    "MetricRunComparison",
    # Service layer
    "MetricService",
    "MetricStore",
    "MetricReader",
    # Exceptions
    "MetricsError",
    "MetricCollectionError",
    "MetricQueryError",
    "MetricRegistryError",
    "MetricStorageError",
    "MetricVersionError",
    # Collector extension
    "BaseCollector",
    "get_all_collectors",
    "get_collector_names",
    "register_collector",
]
