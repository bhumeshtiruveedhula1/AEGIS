"""
backend.metrics.models — Metrics Engine Data Models
====================================================
Module 2.3 — Metrics Collection & Evaluation Engine

This module defines the complete type hierarchy for platform metrics.

Model Hierarchy
---------------
  MetricAvailability      — enum: COMPUTED | UNAVAILABLE | INSUFFICIENT_DATA
  MetricValue             — a single typed metric value with availability status
  MetricDomain            — enum identifying the six metric domains
  PipelineMetrics         — event throughput, processing rates, pipeline latency
  BaselineMetrics         — baseline coverage, entity statistics, staleness
  FeatureMetrics          — feature vector quality, novelty rates, dimension stats
  DetectionMetrics        — MTTD, detection rate, FP rate (future modules)
  ResponseMetrics         — MTTR, automation coverage (future modules)
  PlatformHealthMetrics   — component health, schema versions, uptime indicators
  MetricSnapshot          — complete snapshot across all domains for one run
  MetricRecord            — serialisable output record written to JSONL
  MetricHistoryManifest   — index of all stored snapshots (fast lookup)
  MetricRunComparison     — delta between two MetricSnapshots

Schema Version
--------------
METRICS_SCHEMA_VERSION = "1.0.0"
Bump on breaking changes (removing fields, changing types).

Availability Contract
---------------------
A metric value is ONLY marked COMPUTED when real data exists.
UNAVAILABLE = future module not yet implemented.
INSUFFICIENT_DATA = module exists but has no data for this run.
Downstream consumers MUST check availability before using a value.
"""

from __future__ import annotations

import math
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Generic, TypeVar

from pydantic import Field, field_validator

from backend.shared.models import CyberShieldBaseModel
from backend.shared.utils.id_utils import generate_id


# ---------------------------------------------------------------------------
# Schema version sentinel
# ---------------------------------------------------------------------------

METRICS_SCHEMA_VERSION = "1.0.0"


# ---------------------------------------------------------------------------
# MetricAvailability — honest data quality classification
# ---------------------------------------------------------------------------

class MetricAvailability(str, Enum):
    """
    Data availability classification for a single metric value.

    COMPUTED         — Value was computed from real data. Safe to consume.
    UNAVAILABLE      — Producing module not yet implemented (future phases).
    INSUFFICIENT_DATA— Module exists but had no data for this collection run.

    Downstream consumers MUST check availability before using a value.
    Never fabricate: if data is missing, use UNAVAILABLE or INSUFFICIENT_DATA.
    """

    COMPUTED = "computed"
    UNAVAILABLE = "unavailable"
    INSUFFICIENT_DATA = "insufficient_data"


# ---------------------------------------------------------------------------
# MetricValue — a typed metric value with availability + metadata
# ---------------------------------------------------------------------------

T = TypeVar("T", float, int, str, bool, dict, list)


class MetricValue(CyberShieldBaseModel, Generic[T]):
    """
    A single platform metric value with full provenance.

    Type-agnostic container that records:
    - The computed value (may be None if unavailable)
    - Why the value is available or not (availability)
    - When it was computed
    - An optional human-readable explanation

    Usage
    -----
    >>> # Computed value
    >>> MetricValue(value=0.95, availability=MetricAvailability.COMPUTED,
    ...             unit="ratio", description="Detection rate this run")

    >>> # Unavailable (future module)
    >>> MetricValue.unavailable("Requires Isolation Forest (Module 2.4+)")

    >>> # Insufficient data
    >>> MetricValue.insufficient("No normalized events found for this run")
    """

    value: T | None = Field(
        default=None,
        description="The metric value. None when not available.",
    )
    availability: MetricAvailability = Field(
        description="Whether this value was computed or is unavailable.",
    )
    unit: str | None = Field(
        default=None,
        description="Unit of measurement (e.g. 'seconds', 'ratio', 'count/s').",
    )
    description: str | None = Field(
        default=None,
        description="Human-readable explanation of this metric.",
    )
    computed_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp when this value was computed.",
    )

    @classmethod
    def computed(
        cls,
        value: Any,
        *,
        unit: str | None = None,
        description: str | None = None,
    ) -> "MetricValue":
        """Convenience constructor for a COMPUTED metric."""
        return cls(
            value=value,
            availability=MetricAvailability.COMPUTED,
            unit=unit,
            description=description,
        )

    @classmethod
    def unavailable(cls, reason: str | None = None) -> "MetricValue":
        """
        Construct an UNAVAILABLE metric.

        Use when the producing module is not yet implemented.
        """
        return cls(
            value=None,
            availability=MetricAvailability.UNAVAILABLE,
            description=reason or "Requires a future module not yet implemented.",
        )

    @classmethod
    def insufficient(cls, reason: str | None = None) -> "MetricValue":
        """
        Construct an INSUFFICIENT_DATA metric.

        Use when the module exists but had no data for this run.
        """
        return cls(
            value=None,
            availability=MetricAvailability.INSUFFICIENT_DATA,
            description=reason or "Module active but no data available for this run.",
        )

    @property
    def is_computed(self) -> bool:
        """True only when availability == COMPUTED and value is not None."""
        return self.availability == MetricAvailability.COMPUTED and self.value is not None

    def safe_float(self, default: float = 0.0) -> float:
        """
        Return value as float if COMPUTED and finite. Otherwise return default.
        Safe for use in arithmetic without checking availability first.
        """
        if not self.is_computed or self.value is None:
            return default
        try:
            f = float(self.value)  # type: ignore[arg-type]
            return f if math.isfinite(f) else default
        except (TypeError, ValueError):
            return default


# ---------------------------------------------------------------------------
# MetricDomain — identifies the six metric domains
# ---------------------------------------------------------------------------

class MetricDomain(str, Enum):
    """Six metric domains covering all platform subsystems."""

    PIPELINE = "pipeline"
    BASELINE = "baseline"
    FEATURE = "feature"
    DETECTION = "detection"
    RESPONSE = "response"
    PLATFORM_HEALTH = "platform_health"


# ---------------------------------------------------------------------------
# PipelineMetrics — Module 1.3 / 2.2 throughput and latency
# ---------------------------------------------------------------------------

class PipelineMetrics(CyberShieldBaseModel):
    """
    Event ingestion, normalization and feature extraction pipeline metrics.

    Available now from Module 1.3 pipeline reports and Module 2.2 feature
    pipeline reports. All per-run measurements.

    Computed From
    -------------
    - ParseReport (Module 1.3): events normalized, errors, sources, run duration
    - FeaturePipelineReport (Module 2.2): records written, extraction errors, latency
    """

    # ── Event ingestion & normalization ──────────────────────────────────────
    events_normalized: MetricValue = Field(
        description="Total events successfully normalized in this run.",
    )
    events_failed: MetricValue = Field(
        description="Total events that failed normalization.",
    )
    normalization_error_rate: MetricValue = Field(
        description="Fraction of events that failed normalization (0.0–1.0).",
    )
    sources_processed: MetricValue = Field(
        description="Number of distinct telemetry sources processed.",
    )
    normalization_duration_seconds: MetricValue = Field(
        description="Wall-clock time for the normalization pipeline run.",
    )
    event_processing_rate: MetricValue = Field(
        description="Events normalized per second during this run.",
    )

    # ── Feature extraction ────────────────────────────────────────────────
    feature_records_produced: MetricValue = Field(
        description="Total FeatureRecord objects written in this run.",
    )
    feature_extraction_errors: MetricValue = Field(
        description="Number of feature extraction errors encountered.",
    )
    feature_generation_rate: MetricValue = Field(
        description="Feature records produced per second.",
    )
    feature_extraction_duration_seconds: MetricValue = Field(
        description="Wall-clock time for the feature extraction run.",
    )

    # ── Pipeline health ───────────────────────────────────────────────────
    pipeline_end_to_end_latency_seconds: MetricValue = Field(
        description="Total elapsed time from raw log read to feature write.",
    )


# ---------------------------------------------------------------------------
# BaselineMetrics — Module 2.1 baseline quality and coverage
# ---------------------------------------------------------------------------

class BaselineMetrics(CyberShieldBaseModel):
    """
    Behavioral baseline quality, coverage, and staleness metrics.

    Available now from BaselineProfile and BaselineReader.

    Computed From
    -------------
    - BaselineProfile: entity_count, entity_type_counts, total_events_processed
    - EntityBaseline: observation_count, observation_window_days, sub-baselines
    - BaselineManifest: profile history, staleness computation
    """

    # ── Coverage ──────────────────────────────────────────────────────────
    entity_count: MetricValue = Field(
        description="Total distinct entities with a behavioral baseline.",
    )
    entity_type_breakdown: MetricValue = Field(
        description="Count of entities per entity dimension (user/host/source/user_host).",
    )
    baseline_coverage_ratio: MetricValue = Field(
        description="Fraction of observed entities with a complete baseline.",
    )

    # ── Data quality ──────────────────────────────────────────────────────
    total_events_in_baseline: MetricValue = Field(
        description="Total CanonicalEvents that contributed to this baseline.",
    )
    mean_observations_per_entity: MetricValue = Field(
        description="Average observation count per entity in the baseline.",
    )
    min_observations_per_entity: MetricValue = Field(
        description="Minimum observation count across all entities.",
    )
    max_observations_per_entity: MetricValue = Field(
        description="Maximum observation count across all entities.",
    )
    mean_baseline_window_days: MetricValue = Field(
        description="Average duration of entity baseline windows in days.",
    )

    # ── Staleness ─────────────────────────────────────────────────────────
    baseline_age_hours: MetricValue = Field(
        description="Hours since the current baseline was built.",
    )
    baseline_profile_id: MetricValue = Field(
        description="Profile ID of the currently loaded baseline.",
    )

    # ── Sub-baseline availability ─────────────────────────────────────────
    entities_with_network_baseline: MetricValue = Field(
        description="Count of entities with a NetworkBaseline.",
    )
    entities_with_process_baseline: MetricValue = Field(
        description="Count of entities with a ProcessBaseline.",
    )
    entities_with_auth_baseline: MetricValue = Field(
        description="Count of entities with an AuthBaseline.",
    )
    entities_with_modbus_baseline: MetricValue = Field(
        description="Count of entities with a ModbusBaseline.",
    )


# ---------------------------------------------------------------------------
# FeatureMetrics — Module 2.2 feature vector quality
# ---------------------------------------------------------------------------

class FeatureMetrics(CyberShieldBaseModel):
    """
    Feature vector quality, novelty statistics, and schema metrics.

    Available now from FeaturePipelineReport and FeatureRecord analysis.

    Computed From
    -------------
    - FeaturePipelineReport: records written, errors, baseline availability
    - FeatureRecord analysis: novelty counts, cold-start fraction
    - FeatureSchema: dimension, version
    """

    # ── Schema identity ───────────────────────────────────────────────────
    feature_schema_version: MetricValue = Field(
        description="Feature schema version used in the last extraction run.",
    )
    feature_dimension: MetricValue = Field(
        description="Number of features in each feature vector.",
    )

    # ── Production statistics ──────────────────────────────────────────────
    total_feature_records: MetricValue = Field(
        description="Total FeatureRecord objects in the feature output.",
    )
    unique_entities_extracted: MetricValue = Field(
        description="Number of distinct entity dimensions with feature vectors.",
    )
    baseline_available_fraction: MetricValue = Field(
        description="Fraction of events where a baseline was available during extraction.",
    )
    cold_start_fraction: MetricValue = Field(
        description="Fraction of feature records produced without a baseline (cold-start).",
    )

    # ── Novelty statistics ─────────────────────────────────────────────────
    mean_novelty_count: MetricValue = Field(
        description="Average number of novelty flags fired per feature record.",
    )
    max_novelty_count: MetricValue = Field(
        description="Maximum novelty flags in any single feature record.",
    )
    novelty_rate: MetricValue = Field(
        description="Fraction of feature records with at least one novelty flag.",
    )

    # ── Quality ───────────────────────────────────────────────────────────
    extraction_error_rate: MetricValue = Field(
        description="Fraction of feature records with extraction errors.",
    )
    extraction_warning_rate: MetricValue = Field(
        description="Fraction of feature records with extraction warnings.",
    )


# ---------------------------------------------------------------------------
# DetectionMetrics — future Module 2.4 (anomaly detection)
# ---------------------------------------------------------------------------

class DetectionMetrics(CyberShieldBaseModel):
    """
    Detection quality and operational metrics.

    These metrics require the Behavioral Detection Core (Module 2.4+),
    which is not yet implemented. All values are UNAVAILABLE in this release.

    When Module 2.4 integrates with the Metrics Engine, it will populate
    these fields by calling MetricService.record_detection_event().

    Computed From (future)
    ----------------------
    - DetectionResult objects from Isolation Forest (Module 2.4)
    - Alert records from AlertEngine (Module 2.5+)
    - Ground truth labels (evaluation scenario)
    """

    mean_time_to_detect_seconds: MetricValue = Field(
        description="Average seconds from event occurrence to detection. Requires Module 2.4.",
    )
    detection_rate: MetricValue = Field(
        description="Fraction of true attacks detected. Requires labeled evaluation data.",
    )
    false_positive_rate: MetricValue = Field(
        description="Fraction of alerts that are not real attacks. Requires labels.",
    )
    true_positive_count: MetricValue = Field(
        description="Count of correctly detected attack events. Requires labels.",
    )
    false_positive_count: MetricValue = Field(
        description="Count of false alert events. Requires labels.",
    )
    alerts_generated: MetricValue = Field(
        description="Total alerts generated in this evaluation window.",
    )
    anomaly_score_mean: MetricValue = Field(
        description="Mean anomaly score across all scored events. Requires Module 2.4.",
    )
    anomaly_score_p95: MetricValue = Field(
        description="95th percentile anomaly score. Requires Module 2.4.",
    )


# ---------------------------------------------------------------------------
# ResponseMetrics — future Module 3.x (response orchestration)
# ---------------------------------------------------------------------------

class ResponseMetrics(CyberShieldBaseModel):
    """
    Response and orchestration metrics.

    All values are UNAVAILABLE until Module 3.x (Response Orchestration).

    Computed From (future)
    ----------------------
    - ResponseAction records from Module 3.x
    - Approval workflow timing data
    - Action execution results
    """

    mean_time_to_respond_seconds: MetricValue = Field(
        description="Average seconds from alert to response action. Requires Module 3.x.",
    )
    automation_coverage: MetricValue = Field(
        description="Fraction of responses executed automatically vs manual. Requires Module 3.x.",
    )
    audit_coverage: MetricValue = Field(
        description="Fraction of response actions with full audit trail. Requires Module 3.x.",
    )
    actions_executed: MetricValue = Field(
        description="Total response actions executed in this window. Requires Module 3.x.",
    )
    actions_approved: MetricValue = Field(
        description="Total human-approved actions. Requires Module 3.x.",
    )
    actions_rejected: MetricValue = Field(
        description="Total rejected or cancelled actions. Requires Module 3.x.",
    )


# ---------------------------------------------------------------------------
# PlatformHealthMetrics — cross-module health and version tracking
# ---------------------------------------------------------------------------

class ComponentStatus(str, Enum):
    """Health status of a platform component."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    NOT_IMPLEMENTED = "not_implemented"


class ComponentHealth(CyberShieldBaseModel):
    """Health snapshot for a single platform component."""

    name: str = Field(description="Component identifier (e.g. 'baseline_reader').")
    status: ComponentStatus = Field(description="Current health status.")
    version: str | None = Field(default=None, description="Schema/code version.")
    detail: str | None = Field(default=None, description="Status detail message.")
    checked_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class PlatformHealthMetrics(CyberShieldBaseModel):
    """
    Cross-module health indicators and schema version tracking.

    Always fully computed — every component can report its own status
    regardless of whether downstream modules are implemented.

    Computed From
    -------------
    - BaselineReader.is_ready
    - FeatureSchema constants
    - Settings feature flags
    - File system presence checks
    """

    # ── Schema versions ───────────────────────────────────────────────────
    normalization_schema_version: MetricValue = Field(
        description="CanonicalEvent normalizer_version string.",
    )
    baseline_schema_version: MetricValue = Field(
        description="BASELINE_SCHEMA_VERSION constant.",
    )
    feature_schema_version: MetricValue = Field(
        description="FEATURE_SCHEMA_VERSION constant.",
    )
    metrics_schema_version: MetricValue = Field(
        description="METRICS_SCHEMA_VERSION constant.",
    )

    # ── Component health ──────────────────────────────────────────────────
    components: list[ComponentHealth] = Field(
        default_factory=list,
        description="Health status of each platform component.",
    )

    # ── Feature flags (from config) ───────────────────────────────────────
    feature_flags_enabled: MetricValue = Field(
        description="List of currently enabled feature flag names.",
    )

    # ── Environment ───────────────────────────────────────────────────────
    app_environment: MetricValue = Field(
        description="Deployment environment (development/staging/production).",
    )
    collection_timestamp: MetricValue = Field(
        description="UTC timestamp when this health snapshot was collected.",
    )

    def component_by_name(self, name: str) -> ComponentHealth | None:
        """Return the ComponentHealth for a named component, or None."""
        for c in self.components:
            if c.name == name:
                return c
        return None

    def healthy_count(self) -> int:
        """Return count of HEALTHY components."""
        return sum(1 for c in self.components if c.status == ComponentStatus.HEALTHY)

    def degraded_or_unavailable_count(self) -> int:
        """Return count of components in a non-healthy state."""
        return sum(
            1 for c in self.components
            if c.status in (ComponentStatus.DEGRADED, ComponentStatus.UNAVAILABLE)
        )


# ---------------------------------------------------------------------------
# MetricSnapshot — complete metrics across all domains for one collection run
# ---------------------------------------------------------------------------

class MetricSnapshot(CyberShieldBaseModel):
    """
    Complete platform metrics snapshot collected in one run.

    One MetricSnapshot is produced per MetricService.collect_all() call.
    Each snapshot captures all six metric domains simultaneously.

    Persistence
    -----------
    MetricSnapshot objects are serialised to JSONL by MetricStore.
    The MetricHistoryManifest indexes all stored snapshots.

    Versioning
    ----------
    METRICS_SCHEMA_VERSION must be checked before consuming stored snapshots.
    """

    snapshot_id: str = Field(
        default_factory=generate_id,
        description="UUID v4 identifying this metric collection run.",
    )
    schema_version: str = Field(
        default=METRICS_SCHEMA_VERSION,
        description="Metrics schema version.",
    )
    collected_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp when this snapshot was collected.",
    )
    collection_duration_seconds: float | None = Field(
        default=None,
        description="Time taken to collect all metrics.",
    )

    # ── Six metric domains ────────────────────────────────────────────────
    pipeline: PipelineMetrics = Field(
        description="Pipeline throughput and latency metrics.",
    )
    baseline: BaselineMetrics = Field(
        description="Baseline coverage and quality metrics.",
    )
    feature: FeatureMetrics = Field(
        description="Feature vector quality and novelty metrics.",
    )
    detection: DetectionMetrics = Field(
        description="Detection quality metrics (partially unavailable).",
    )
    response: ResponseMetrics = Field(
        description="Response and orchestration metrics (unavailable).",
    )
    health: PlatformHealthMetrics = Field(
        description="Platform component health and version metrics.",
    )

    # ── Tags for filtering ────────────────────────────────────────────────
    tags: dict[str, str] = Field(
        default_factory=dict,
        description="Key-value tags for filtering and grouping snapshots.",
    )

    def computed_metric_count(self) -> int:
        """Return the count of COMPUTED metric values across all domains."""
        total = 0
        for domain_obj in [self.pipeline, self.baseline, self.feature,
                           self.detection, self.response, self.health]:
            for field_name in type(domain_obj).model_fields:
                val = getattr(domain_obj, field_name, None)
                if isinstance(val, MetricValue) and val.is_computed:
                    total += 1
        return total

    def unavailable_metric_count(self) -> int:
        """Return the count of UNAVAILABLE metric values across all domains."""
        total = 0
        for domain_obj in [self.pipeline, self.baseline, self.feature,
                           self.detection, self.response, self.health]:
            for field_name in type(domain_obj).model_fields:
                val = getattr(domain_obj, field_name, None)
                if isinstance(val, MetricValue):
                    if val.availability == MetricAvailability.UNAVAILABLE:
                        total += 1
        return total


# ---------------------------------------------------------------------------
# MetricRecord — serialisable JSONL output record
# ---------------------------------------------------------------------------

class MetricRecord(CyberShieldBaseModel):
    """
    Serialisable output record written to the metrics JSONL file.

    Wraps a MetricSnapshot with additional storage metadata.
    This is the atomic unit stored by MetricStore.
    """

    record_id: str = Field(default_factory=generate_id)
    snapshot: MetricSnapshot = Field(description="The complete metric snapshot.")
    written_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def to_summary_dict(self) -> dict[str, Any]:
        """
        Return a lightweight dict summary of this record.
        Used in manifest entries and quick lookups.
        """
        return {
            "record_id": self.record_id,
            "snapshot_id": self.snapshot.snapshot_id,
            "collected_at": self.snapshot.collected_at.isoformat(),
            "schema_version": self.snapshot.schema_version,
            "computed_metrics": self.snapshot.computed_metric_count(),
            "unavailable_metrics": self.snapshot.unavailable_metric_count(),
            "tags": self.snapshot.tags,
        }


# ---------------------------------------------------------------------------
# MetricHistoryManifest — index of all stored snapshots
# ---------------------------------------------------------------------------

class ManifestEntry(CyberShieldBaseModel):
    """Single entry in the metrics history manifest."""

    record_id: str
    snapshot_id: str
    collected_at: datetime
    schema_version: str
    computed_metrics: int
    unavailable_metrics: int
    tags: dict[str, str] = Field(default_factory=dict)


class MetricHistoryManifest(CyberShieldBaseModel):
    """
    Index of all stored MetricRecord snapshots.

    Written to data/metrics/manifest.json after every collection run.
    Allows fast lookup without loading the full JSONL history.
    """

    last_updated: datetime = Field(default_factory=lambda: datetime.now(UTC))
    schema_version: str = Field(default=METRICS_SCHEMA_VERSION)
    latest_snapshot_id: str | None = Field(default=None)
    total_snapshots: int = Field(default=0, ge=0)
    entries: list[ManifestEntry] = Field(
        default_factory=list,
        description="All entries in reverse-chronological order (newest first).",
    )

    def add_entry(self, record: MetricRecord) -> None:
        """Insert a new entry at the front of the list."""
        entry = ManifestEntry(
            record_id=record.record_id,
            snapshot_id=record.snapshot.snapshot_id,
            collected_at=record.snapshot.collected_at,
            schema_version=record.snapshot.schema_version,
            computed_metrics=record.snapshot.computed_metric_count(),
            unavailable_metrics=record.snapshot.unavailable_metric_count(),
            tags=record.snapshot.tags,
        )
        self.entries.insert(0, entry)
        self.latest_snapshot_id = record.snapshot.snapshot_id
        self.total_snapshots = len(self.entries)
        object.__setattr__(self, "last_updated", datetime.now(UTC))

    def latest_entry(self) -> ManifestEntry | None:
        """Return the most recent entry, or None if no snapshots stored."""
        return self.entries[0] if self.entries else None


# ---------------------------------------------------------------------------
# MetricRunComparison — delta between two MetricSnapshots
# ---------------------------------------------------------------------------

class MetricDelta(CyberShieldBaseModel):
    """Delta of a single MetricValue between two snapshots."""

    metric_name: str
    domain: MetricDomain
    before: MetricValue
    after: MetricValue
    delta: float | None = Field(
        default=None,
        description="Numeric delta (after - before). None if not numeric or unavailable.",
    )
    delta_pct: float | None = Field(
        default=None,
        description="Percentage change. None if denominator is zero or unavailable.",
    )
    improved: bool | None = Field(
        default=None,
        description="True if improvement, False if regression. None if indeterminate.",
    )


class MetricRunComparison(CyberShieldBaseModel):
    """
    Structured comparison of two MetricSnapshots.

    Produced by MetricReader.compare_snapshots() for trend analysis
    and run-over-run regression detection.
    """

    baseline_snapshot_id: str
    current_snapshot_id: str
    compared_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    deltas: list[MetricDelta] = Field(default_factory=list)

    def regressions(self) -> list[MetricDelta]:
        """Return deltas where improved=False (metric got worse)."""
        return [d for d in self.deltas if d.improved is False]

    def improvements(self) -> list[MetricDelta]:
        """Return deltas where improved=True."""
        return [d for d in self.deltas if d.improved is True]

    def significant_changes(self, threshold_pct: float = 5.0) -> list[MetricDelta]:
        """Return deltas where absolute percentage change exceeds threshold."""
        return [
            d for d in self.deltas
            if d.delta_pct is not None and abs(d.delta_pct) >= threshold_pct
        ]
