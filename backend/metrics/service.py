"""
backend.metrics.service — Metric Service
=========================================
Module 2.3 — Metrics Collection & Evaluation Engine

MetricService is the top-level orchestrator for the metrics subsystem.

Responsibilities
----------------
1. Wire all registered collectors with the data they need
2. Execute each collector in isolation via safe_collect()
3. Assemble a complete MetricSnapshot from all domain results
4. Delegate persistence to MetricStore
5. Expose a clean API for application code and API endpoints

Usage
-----
    # Collect and persist metrics for the current platform state
    service = MetricService()
    snapshot = service.collect_all(
        norm_report=normalization_report,
        feature_report=feature_pipeline_report,
        feature_records=feature_records,
        baseline_profile=baseline_profile,
        baseline_reader=baseline_reader,
    )

    # Query history
    reader = service.reader
    trend = reader.trend(MetricDomain.PIPELINE, "events_normalized")
    comparison = reader.compare_last_two()

    # Platform status for health endpoints
    status = service.get_platform_status()

Integration Points
------------------
- Normalization (Module 1.3): pass NormalizationPipelineReport as norm_report
- Feature Engine (Module 2.2): pass FeaturePipelineReport + FeatureRecords
- Baseline System (Module 2.1): pass BaselineProfile + BaselineReader
- Detection Core (Module 2.4+): pass detection_results to collect_all()
- Response Module (3.x+): pass response_actions to collect_all()
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Any

import structlog

from backend.metrics.collectors import get_all_collectors
from backend.metrics.exceptions import MetricCollectionError
from backend.metrics.models import (
    METRICS_SCHEMA_VERSION,
    DetectionMetrics,
    FeatureMetrics,
    BaselineMetrics,
    MetricAvailability,
    MetricDomain,
    MetricRecord,
    MetricSnapshot,
    MetricValue,
    PipelineMetrics,
    PlatformHealthMetrics,
    ResponseMetrics,
)
from backend.metrics.reader import MetricReader
from backend.metrics.store import MetricStore

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Default domain models — returned when a collector fails catastrophically
# ---------------------------------------------------------------------------

def _all_unavailable_pipeline() -> PipelineMetrics:
    _r = "Collector failed — see logs."
    return PipelineMetrics(**{f: MetricValue.unavailable(_r) for f in PipelineMetrics.model_fields})


def _all_unavailable_baseline() -> BaselineMetrics:
    _r = "Collector failed — see logs."
    return BaselineMetrics(**{f: MetricValue.unavailable(_r) for f in BaselineMetrics.model_fields})


def _all_unavailable_feature() -> FeatureMetrics:
    _r = "Collector failed — see logs."
    return FeatureMetrics(**{f: MetricValue.unavailable(_r) for f in FeatureMetrics.model_fields})


def _all_unavailable_detection() -> DetectionMetrics:
    _r = "Collector failed — see logs."
    return DetectionMetrics(**{f: MetricValue.unavailable(_r) for f in DetectionMetrics.model_fields})


def _all_unavailable_response() -> ResponseMetrics:
    _r = "Collector failed — see logs."
    return ResponseMetrics(**{f: MetricValue.unavailable(_r) for f in ResponseMetrics.model_fields})


def _all_unavailable_health() -> PlatformHealthMetrics:
    return PlatformHealthMetrics(
        normalization_schema_version=MetricValue.unavailable("Collector failed."),
        baseline_schema_version=MetricValue.unavailable("Collector failed."),
        feature_schema_version=MetricValue.unavailable("Collector failed."),
        metrics_schema_version=MetricValue.unavailable("Collector failed."),
        feature_flags_enabled=MetricValue.unavailable("Collector failed."),
        app_environment=MetricValue.unavailable("Collector failed."),
        collection_timestamp=MetricValue.unavailable("Collector failed."),
        components=[],
    )


_DOMAIN_FALLBACKS = {
    MetricDomain.PIPELINE: _all_unavailable_pipeline,
    MetricDomain.BASELINE: _all_unavailable_baseline,
    MetricDomain.FEATURE: _all_unavailable_feature,
    MetricDomain.DETECTION: _all_unavailable_detection,
    MetricDomain.RESPONSE: _all_unavailable_response,
    MetricDomain.PLATFORM_HEALTH: _all_unavailable_health,
}


# ---------------------------------------------------------------------------
# MetricService
# ---------------------------------------------------------------------------

class MetricService:
    """
    Top-level metrics orchestrator.

    Parameters
    ----------
    store_dir : Override the metric storage directory.
    tags      : Default tags applied to every snapshot (e.g. {"env": "prod"}).
    """

    def __init__(
        self,
        *,
        store_dir: Any = None,
        tags: dict[str, str] | None = None,
    ) -> None:
        self._store = MetricStore(store_dir=store_dir)
        self._reader = MetricReader(store=self._store)
        self._default_tags = tags or {}
        # Pre-load collectors once — they are stateless, so re-use is safe
        self._collectors = get_all_collectors()
        logger.info(
            "metric_service_initialised",
            collectors=[c.name for c in self._collectors],
            schema_version=METRICS_SCHEMA_VERSION,
        )

    @property
    def reader(self) -> MetricReader:
        """Return the read-only query interface."""
        return self._reader

    @property
    def store(self) -> MetricStore:
        """Return the underlying metric store."""
        return self._store

    # ── Primary collection API ───────────────────────────────────────────

    def collect_all(
        self,
        *,
        norm_report: Any = None,
        feature_report: Any = None,
        feature_records: list | None = None,
        baseline_profile: Any = None,
        baseline_reader: Any = None,
        tags: dict[str, str] | None = None,
        persist: bool = True,
    ) -> MetricSnapshot:
        """
        Collect metrics across all domains and optionally persist the snapshot.

        Each collector runs in isolation — one failure does not prevent others.
        All collector failures are logged and produce UNAVAILABLE domain metrics.

        Parameters
        ----------
        norm_report     : NormalizationPipelineReport from Module 1.3.
        feature_report  : FeaturePipelineReport from Module 2.2.
        feature_records : List of FeatureRecord from Module 2.2.
        baseline_profile: BaselineProfile from Module 2.1.
        baseline_reader : BaselineReader from Module 2.1.
        tags            : Run-specific tags (merged with default tags).
        persist         : If True, save snapshot to MetricStore (default: True).

        Returns
        -------
        MetricSnapshot — fully populated snapshot across all six domains.
        """
        collection_start = time.perf_counter()
        started_at = datetime.now(UTC)

        # Shared kwargs for all collectors
        collector_kwargs: dict[str, Any] = {
            "norm_report": norm_report,
            "feature_report": feature_report,
            "feature_records": feature_records or [],
            "baseline_profile": baseline_profile,
            "baseline_reader": baseline_reader,
        }

        # Collect all domains
        domain_results: dict[MetricDomain, Any] = {}
        for collector in self._collectors:
            result = collector.safe_collect(**collector_kwargs)
            if result is None:
                logger.error(
                    "metric_collector_catastrophic_failure",
                    collector=collector.name,
                    domain=collector.domain.value,
                )
                fallback_fn = _DOMAIN_FALLBACKS.get(collector.domain)
                result = fallback_fn() if fallback_fn else None
            domain_results[collector.domain] = result

        collection_duration = time.perf_counter() - collection_start

        # Assemble snapshot
        snapshot = MetricSnapshot(
            collected_at=started_at,
            collection_duration_seconds=round(collection_duration, 4),
            pipeline=domain_results.get(MetricDomain.PIPELINE) or _all_unavailable_pipeline(),
            baseline=domain_results.get(MetricDomain.BASELINE) or _all_unavailable_baseline(),
            feature=domain_results.get(MetricDomain.FEATURE) or _all_unavailable_feature(),
            detection=domain_results.get(MetricDomain.DETECTION) or _all_unavailable_detection(),
            response=domain_results.get(MetricDomain.RESPONSE) or _all_unavailable_response(),
            health=domain_results.get(MetricDomain.PLATFORM_HEALTH) or _all_unavailable_health(),
            tags={**self._default_tags, **(tags or {})},
        )

        logger.info(
            "metric_collection_complete",
            snapshot_id=snapshot.snapshot_id,
            computed=snapshot.computed_metric_count(),
            unavailable=snapshot.unavailable_metric_count(),
            duration_s=collection_duration,
        )

        # Persist
        if persist:
            self._store.save(snapshot)

        return snapshot

    # ── Convenience API ──────────────────────────────────────────────────

    def collect_pipeline_only(
        self,
        *,
        norm_report: Any = None,
        feature_report: Any = None,
        feature_records: list | None = None,
        persist: bool = False,
    ) -> MetricSnapshot:
        """
        Convenience method to collect only pipeline + feature + health metrics.

        Useful after a pipeline run when no baseline data is available.
        """
        return self.collect_all(
            norm_report=norm_report,
            feature_report=feature_report,
            feature_records=feature_records,
            tags={"scope": "pipeline_only"},
            persist=persist,
        )

    def get_platform_status(self) -> dict[str, Any]:
        """
        Return a compact dict describing current platform health.

        Suitable for health check endpoints and monitoring dashboards.
        Reads the latest stored snapshot — does NOT trigger a new collection.
        """
        latest = self._reader.latest_snapshot()
        if latest is None:
            return {
                "status": "no_data",
                "message": "No metrics collected yet. Run MetricService.collect_all().",
                "schema_version": METRICS_SCHEMA_VERSION,
                "snapshot_count": 0,
            }

        healthy = latest.health.healthy_count()
        degraded = latest.health.degraded_or_unavailable_count()
        total = len(latest.health.components)

        if degraded == 0:
            overall = "healthy"
        elif healthy > degraded:
            overall = "degraded"
        else:
            overall = "critical"

        return {
            "status": overall,
            "schema_version": METRICS_SCHEMA_VERSION,
            "collected_at": latest.collected_at.isoformat(),
            "snapshot_id": latest.snapshot_id,
            "snapshot_count": self._reader.snapshot_count(),
            "components": {
                c.name: {"status": str(c.status), "detail": c.detail}
                for c in latest.health.components
            },
            "metrics_summary": {
                "computed": latest.computed_metric_count(),
                "unavailable": latest.unavailable_metric_count(),
            },
            "pipeline": {
                "events_normalized": latest.pipeline.events_normalized.safe_float(),
                "event_processing_rate": latest.pipeline.event_processing_rate.safe_float(),
                "feature_records_produced": latest.pipeline.feature_records_produced.safe_float(),
            },
            "baseline": {
                "entity_count": latest.baseline.entity_count.safe_float(),
                "baseline_age_hours": latest.baseline.baseline_age_hours.safe_float(),
            },
            "feature": {
                "total_feature_records": latest.feature.total_feature_records.safe_float(),
                "novelty_rate": latest.feature.novelty_rate.safe_float(),
                "cold_start_fraction": latest.feature.cold_start_fraction.safe_float(),
            },
        }

    def compare_last_runs(self) -> dict[str, Any] | None:
        """
        Compare the two most recent collection runs.

        Returns a serialisable summary dict or None if < 2 snapshots exist.
        """
        comparison = self._reader.compare_last_two()
        if comparison is None:
            return None

        return {
            "baseline_snapshot_id": comparison.baseline_snapshot_id,
            "current_snapshot_id": comparison.current_snapshot_id,
            "compared_at": comparison.compared_at.isoformat(),
            "regressions": [
                {
                    "metric": d.metric_name,
                    "domain": str(d.domain),
                    "before": d.before.safe_float(),
                    "after": d.after.safe_float(),
                    "delta": d.delta,
                    "delta_pct": d.delta_pct,
                }
                for d in comparison.regressions()
            ],
            "improvements": [
                {
                    "metric": d.metric_name,
                    "domain": str(d.domain),
                    "delta": d.delta,
                    "delta_pct": d.delta_pct,
                }
                for d in comparison.improvements()
            ],
            "significant_changes": len(comparison.significant_changes()),
        }
