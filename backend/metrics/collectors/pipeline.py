"""
backend.metrics.collectors.pipeline — Pipeline Metrics Collector
================================================================
Module 2.3 — Metrics Collection & Evaluation Engine

Collects PipelineMetrics from:
  - NormalizationPipelineReport  (Module 1.3 output)
  - FeaturePipelineReport        (Module 2.2 output)

Both reports are passed as keyword arguments by MetricService.
If neither is available, all metrics return INSUFFICIENT_DATA.

Available Metrics (fully computed when data is present)
-------------------------------------------------------
- events_normalized            from normalization report
- events_failed                from normalization report
- normalization_error_rate     computed: failed / (normalized + failed)
- sources_processed            from normalization report
- normalization_duration_seconds from normalization report
- event_processing_rate        computed: normalized / duration
- feature_records_produced     from feature report
- feature_extraction_errors    from feature report
- feature_generation_rate      computed: records / duration
- feature_extraction_duration_seconds from feature report
- pipeline_end_to_end_latency_seconds sum of both durations (best estimate)
"""

from __future__ import annotations

from typing import Any

from backend.metrics.collectors import BaseCollector, register_collector
from backend.metrics.models import (
    MetricDomain,
    MetricValue,
    PipelineMetrics,
)


@register_collector
class PipelineMetricsCollector(BaseCollector):
    """Collects pipeline throughput, rate and latency metrics."""

    @property
    def domain(self) -> MetricDomain:
        return MetricDomain.PIPELINE

    @property
    def name(self) -> str:
        return "pipeline"

    def collect(self, **kwargs: Any) -> PipelineMetrics:
        """
        Compute PipelineMetrics from available pipeline reports.

        Keyword Arguments
        -----------------
        norm_report      : NormalizationPipelineReport | None
        feature_report   : FeaturePipelineReport | None
        """
        norm = kwargs.get("norm_report")
        feat = kwargs.get("feature_report")

        return PipelineMetrics(
            events_normalized=self._events_normalized(norm),
            events_failed=self._events_failed(norm),
            normalization_error_rate=self._norm_error_rate(norm),
            sources_processed=self._sources_processed(norm),
            normalization_duration_seconds=self._norm_duration(norm),
            event_processing_rate=self._event_rate(norm),
            feature_records_produced=self._feature_records(feat),
            feature_extraction_errors=self._feature_errors(feat),
            feature_generation_rate=self._feature_rate(feat),
            feature_extraction_duration_seconds=self._feature_duration(feat),
            pipeline_end_to_end_latency_seconds=self._end_to_end_latency(norm, feat),
        )

    # ── Private computation helpers ──────────────────────────────────────

    def _events_normalized(self, norm: Any) -> MetricValue:
        if norm is None:
            return MetricValue.insufficient("No normalization report available.")
        return MetricValue.computed(
            int(getattr(norm, "events_normalized", 0)),
            unit="count",
            description="Events successfully normalized.",
        )

    def _events_failed(self, norm: Any) -> MetricValue:
        if norm is None:
            return MetricValue.insufficient("No normalization report available.")
        return MetricValue.computed(
            int(getattr(norm, "events_failed", 0)),
            unit="count",
            description="Events that failed normalization.",
        )

    def _norm_error_rate(self, norm: Any) -> MetricValue:
        if norm is None:
            return MetricValue.insufficient("No normalization report available.")
        normalized = int(getattr(norm, "events_normalized", 0))
        failed = int(getattr(norm, "events_failed", 0))
        total = normalized + failed
        if total == 0:
            return MetricValue.insufficient("No events processed — cannot compute error rate.")
        rate = failed / total
        return MetricValue.computed(
            round(rate, 6),
            unit="ratio",
            description="Fraction of events that failed normalization.",
        )

    def _sources_processed(self, norm: Any) -> MetricValue:
        if norm is None:
            return MetricValue.insufficient("No normalization report available.")
        # Try multiple attribute names from different report versions
        sources = getattr(norm, "sources_processed", None)
        if sources is None:
            sources = getattr(norm, "source_count", None)
        if sources is None:
            sources_set = getattr(norm, "sources", None)
            if sources_set is not None:
                sources = len(sources_set)
        if sources is None:
            return MetricValue.insufficient("Source count not available in report.")
        return MetricValue.computed(
            int(sources),
            unit="count",
            description="Distinct telemetry sources processed.",
        )

    def _norm_duration(self, norm: Any) -> MetricValue:
        if norm is None:
            return MetricValue.insufficient("No normalization report available.")
        duration = getattr(norm, "duration_seconds", None)
        if duration is None:
            # Try computing from started_at / completed_at
            started = getattr(norm, "started_at", None)
            completed = getattr(norm, "completed_at", None)
            if started and completed:
                duration = (completed - started).total_seconds()
        if duration is None:
            return MetricValue.insufficient("Duration not available in normalization report.")
        return MetricValue.computed(
            round(float(duration), 3),
            unit="seconds",
            description="Wall-clock time for normalization run.",
        )

    def _event_rate(self, norm: Any) -> MetricValue:
        if norm is None:
            return MetricValue.insufficient("No normalization report available.")
        normalized = int(getattr(norm, "events_normalized", 0))
        duration = getattr(norm, "duration_seconds", None)
        if duration is None:
            started = getattr(norm, "started_at", None)
            completed = getattr(norm, "completed_at", None)
            if started and completed:
                duration = (completed - started).total_seconds()
        if duration is None or float(duration) <= 0:
            return MetricValue.insufficient("Cannot compute rate without valid duration.")
        rate = normalized / float(duration)
        return MetricValue.computed(
            round(rate, 2),
            unit="events/second",
            description="Events normalized per second.",
        )

    def _feature_records(self, feat: Any) -> MetricValue:
        if feat is None:
            return MetricValue.insufficient("No feature pipeline report available.")
        return MetricValue.computed(
            int(getattr(feat, "feature_records_written", 0)),
            unit="count",
            description="Feature records produced.",
        )

    def _feature_errors(self, feat: Any) -> MetricValue:
        if feat is None:
            return MetricValue.insufficient("No feature pipeline report available.")
        return MetricValue.computed(
            int(getattr(feat, "extraction_errors", 0)),
            unit="count",
            description="Feature extraction errors.",
        )

    def _feature_rate(self, feat: Any) -> MetricValue:
        if feat is None:
            return MetricValue.insufficient("No feature pipeline report available.")
        records = int(getattr(feat, "feature_records_written", 0))
        rate_val = getattr(feat, "records_per_second", None)
        if rate_val is not None:
            return MetricValue.computed(
                round(float(rate_val), 2),
                unit="records/second",
                description="Feature records produced per second.",
            )
        duration = getattr(feat, "duration_seconds", None)
        if duration is None or float(duration) <= 0:
            return MetricValue.insufficient("Cannot compute rate without valid duration.")
        return MetricValue.computed(
            round(records / float(duration), 2),
            unit="records/second",
            description="Feature records produced per second.",
        )

    def _feature_duration(self, feat: Any) -> MetricValue:
        if feat is None:
            return MetricValue.insufficient("No feature pipeline report available.")
        duration = getattr(feat, "duration_seconds", None)
        if duration is None:
            started = getattr(feat, "started_at", None)
            completed = getattr(feat, "completed_at", None)
            if started and completed:
                duration = (completed - started).total_seconds()
        if duration is None:
            return MetricValue.insufficient("Duration not available in feature report.")
        return MetricValue.computed(
            round(float(duration), 3),
            unit="seconds",
            description="Wall-clock time for feature extraction run.",
        )

    def _end_to_end_latency(self, norm: Any, feat: Any) -> MetricValue:
        """Sum of normalization + feature extraction durations."""
        norm_sec = None
        if norm is not None:
            d = getattr(norm, "duration_seconds", None)
            if d is None:
                s, c = getattr(norm, "started_at", None), getattr(norm, "completed_at", None)
                if s and c:
                    d = (c - s).total_seconds()
            if d is not None:
                norm_sec = float(d)

        feat_sec = None
        if feat is not None:
            d = getattr(feat, "duration_seconds", None)
            if d is None:
                s, c = getattr(feat, "started_at", None), getattr(feat, "completed_at", None)
                if s and c:
                    d = (c - s).total_seconds()
            if d is not None:
                feat_sec = float(d)

        if norm_sec is None and feat_sec is None:
            return MetricValue.insufficient("No timing data available for end-to-end latency.")

        total = (norm_sec or 0.0) + (feat_sec or 0.0)
        return MetricValue.computed(
            round(total, 3),
            unit="seconds",
            description="Estimated end-to-end pipeline latency (norm + feature extraction).",
        )
