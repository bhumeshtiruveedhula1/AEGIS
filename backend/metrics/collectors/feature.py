"""
backend.metrics.collectors.feature — Feature Metrics Collector
==============================================================
Module 2.3 — Metrics Collection & Evaluation Engine

Collects FeatureMetrics from:
  - FeaturePipelineReport  (Module 2.2 — batch summary)
  - List[FeatureRecord]    (Module 2.2 — individual records for novelty stats)

The collector performs incremental computation over feature records
to derive novelty statistics, avoiding full re-processing.

Available Metrics (fully computed when data is present)
-------------------------------------------------------
All 10 FeatureMetrics fields computed from real Module 2.2 output.
"""

from __future__ import annotations

import statistics
from typing import Any

from backend.features.models import FEATURE_DIMENSION, FEATURE_SCHEMA_VERSION
from backend.metrics.collectors import BaseCollector, register_collector
from backend.metrics.models import (
    FeatureMetrics,
    MetricDomain,
    MetricValue,
)


@register_collector
class FeatureMetricsCollector(BaseCollector):
    """Collects feature vector quality, novelty, and schema metrics."""

    @property
    def domain(self) -> MetricDomain:
        return MetricDomain.FEATURE

    @property
    def name(self) -> str:
        return "feature"

    def collect(self, **kwargs: Any) -> FeatureMetrics:
        """
        Compute FeatureMetrics from the feature pipeline report and records.

        Keyword Arguments
        -----------------
        feature_report  : FeaturePipelineReport | None
        feature_records : list[FeatureRecord] | None
        """
        feat_report = kwargs.get("feature_report")
        feat_records = kwargs.get("feature_records") or []

        # Pre-compute novelty statistics over all records once
        novelty_counts = self._novelty_counts(feat_records)
        baseline_available_flags = self._baseline_flags(feat_records)

        return FeatureMetrics(
            feature_schema_version=MetricValue.computed(
                FEATURE_SCHEMA_VERSION,
                description="Feature schema version used in the last extraction run.",
            ),
            feature_dimension=MetricValue.computed(
                FEATURE_DIMENSION,
                unit="count",
                description="Number of features in each feature vector.",
            ),
            total_feature_records=self._total_records(feat_report, feat_records),
            unique_entities_extracted=self._unique_entities(feat_report, feat_records),
            baseline_available_fraction=self._baseline_fraction(
                feat_report, baseline_available_flags
            ),
            cold_start_fraction=self._cold_start_fraction(
                feat_report, baseline_available_flags
            ),
            mean_novelty_count=self._mean_novelty(novelty_counts),
            max_novelty_count=self._max_novelty(novelty_counts),
            novelty_rate=self._novelty_rate(novelty_counts),
            extraction_error_rate=self._error_rate(feat_report, feat_records),
            extraction_warning_rate=self._warning_rate(feat_report, feat_records),
        )

    # ── Private helpers ──────────────────────────────────────────────────

    def _novelty_counts(self, records: list) -> list[int]:
        """Extract novelty_count() from each FeatureRecord."""
        counts = []
        for r in records:
            try:
                vec = getattr(r, "feature_vector", None)
                if vec is not None:
                    counts.append(vec.novelty_count())
            except Exception:  # noqa: BLE001
                pass
        return counts

    def _baseline_flags(self, records: list) -> list[bool]:
        """Extract baseline_available flag from each FeatureRecord."""
        flags = []
        for r in records:
            flag = getattr(r, "baseline_available", None)
            if flag is not None:
                flags.append(bool(flag))
        return flags

    def _total_records(self, report: Any, records: list) -> MetricValue:
        count = None
        if report is not None:
            count = getattr(report, "feature_records_written", None)
        if count is None:
            count = len(records)
        if count == 0 and report is None and not records:
            return MetricValue.insufficient("No feature records or report available.")
        return MetricValue.computed(
            int(count),
            unit="count",
            description="Total FeatureRecord objects produced.",
        )

    def _unique_entities(self, report: Any, records: list) -> MetricValue:
        if report is not None:
            count = getattr(report, "entities_extracted", None)
            if count is not None:
                return MetricValue.computed(
                    int(count),
                    unit="count",
                    description="Distinct entity dimensions with feature vectors.",
                )
        if records:
            entity_keys = set()
            for r in records:
                key = getattr(r, "entity_key", None)
                if key is not None:
                    entity_keys.add(str(key))
            return MetricValue.computed(
                len(entity_keys),
                unit="count",
                description="Distinct entity dimensions with feature vectors.",
            )
        return MetricValue.insufficient("No feature data available.")

    def _baseline_fraction(self, report: Any, flags: list[bool]) -> MetricValue:
        """Fraction of records where baseline was available during extraction."""
        if report is not None:
            avail = getattr(report, "baseline_available", None)
            if avail is not None:
                # report.baseline_available is a bool — single run flag
                # Use it as fallback; per-record is more accurate
                pass
        if flags:
            fraction = sum(1 for f in flags if f) / len(flags)
            return MetricValue.computed(
                round(fraction, 4),
                unit="ratio",
                description="Fraction of feature records with a baseline available.",
            )
        return MetricValue.insufficient("No feature records to compute baseline fraction.")

    def _cold_start_fraction(self, report: Any, flags: list[bool]) -> MetricValue:
        if flags:
            cold = sum(1 for f in flags if not f) / len(flags)
            return MetricValue.computed(
                round(cold, 4),
                unit="ratio",
                description="Fraction of feature records produced without a baseline.",
            )
        if report is not None:
            cold_start = getattr(report, "cold_start", None)
            if cold_start is not None:
                return MetricValue.computed(
                    1.0 if cold_start else 0.0,
                    unit="ratio",
                    description="Cold-start indicator (1.0 = no baseline was available).",
                )
        return MetricValue.insufficient("No feature data for cold-start fraction.")

    def _mean_novelty(self, counts: list[int]) -> MetricValue:
        if not counts:
            return MetricValue.insufficient("No feature records to compute novelty statistics.")
        return MetricValue.computed(
            round(statistics.mean(counts), 4),
            unit="count",
            description="Mean novelty flags fired per feature record.",
        )

    def _max_novelty(self, counts: list[int]) -> MetricValue:
        if not counts:
            return MetricValue.insufficient("No feature records to compute novelty statistics.")
        return MetricValue.computed(
            max(counts),
            unit="count",
            description="Maximum novelty flags in any single feature record.",
        )

    def _novelty_rate(self, counts: list[int]) -> MetricValue:
        if not counts:
            return MetricValue.insufficient("No feature records to compute novelty rate.")
        rate = sum(1 for c in counts if c > 0) / len(counts)
        return MetricValue.computed(
            round(rate, 4),
            unit="ratio",
            description="Fraction of feature records with at least one novelty flag.",
        )

    def _error_rate(self, report: Any, records: list) -> MetricValue:
        errors = None
        total = None
        if report is not None:
            errors = getattr(report, "extraction_errors", None)
            total = getattr(report, "feature_records_written", None)
        if errors is None:
            errors = 0
        if total is None:
            total = len(records)
        if total == 0:
            return MetricValue.insufficient("No feature records — cannot compute error rate.")
        return MetricValue.computed(
            round(int(errors) / int(total), 6),
            unit="ratio",
            description="Fraction of feature records with extraction errors.",
        )

    def _warning_rate(self, report: Any, records: list) -> MetricValue:
        warnings = None
        total = None
        if report is not None:
            warnings = getattr(report, "extraction_warnings", None)
            total = getattr(report, "feature_records_written", None)
        if warnings is None:
            # Compute from records
            if records:
                warnings = sum(
                    len(getattr(getattr(r, "feature_vector", None), "extraction_warnings", []) or [])
                    for r in records
                )
                total = len(records)
        if total is None:
            total = len(records)
        if total == 0:
            return MetricValue.insufficient("No feature records — cannot compute warning rate.")
        if warnings is None:
            return MetricValue.insufficient("Warning count not available.")
        return MetricValue.computed(
            round(int(warnings) / int(total), 6),
            unit="ratio",
            description="Fraction of feature records with extraction warnings.",
        )
