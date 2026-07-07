"""
backend.metrics.collectors.detection — Detection Metrics Collector
==================================================================
Module 2.3 — Metrics Collection & Evaluation Engine

All DetectionMetrics are UNAVAILABLE in this release.

The Behavioral Detection Core (Module 2.4+) is not yet implemented.
This collector marks every detection metric as UNAVAILABLE with an
informative reason string, so downstream consumers can reason correctly
about data availability.

When Module 2.4 is implemented, it will:
  1. Pass detection_results and label_data to MetricService.collect_all()
  2. This collector will compute real values from those inputs.
  3. No changes to the registry, service, or storage are required.

Design Note
-----------
This collector exists NOW to ensure:
  - Detection metrics appear in every MetricSnapshot
  - Their UNAVAILABLE status is explicit and auditable
  - The collector slot is reserved in the registry
  - Future integration requires only implementing the compute helpers
"""

from __future__ import annotations

from typing import Any

from backend.metrics.collectors import BaseCollector, register_collector
from backend.metrics.models import (
    DetectionMetrics,
    MetricDomain,
    MetricValue,
)

_REASON = "Requires Behavioral Detection Core (Module 2.4+), not yet implemented."


@register_collector
class DetectionMetricsCollector(BaseCollector):
    """Placeholder collector for detection quality metrics (Module 2.4+)."""

    @property
    def domain(self) -> MetricDomain:
        return MetricDomain.DETECTION

    @property
    def name(self) -> str:
        return "detection"

    def collect(self, **kwargs: Any) -> DetectionMetrics:
        """
        All detection metrics are UNAVAILABLE until Module 2.4 is integrated.

        Future Integration
        ------------------
        When Module 2.4 is ready, populate these kwargs in MetricService:
          detection_results : list[DetectionResult]
          label_data        : dict[str, bool]  # event_id → is_attack
          alert_records     : list[AlertRecord]
        """
        # Future: if kwargs.get("detection_results"):
        #     return self._compute_from_results(**kwargs)

        return DetectionMetrics(
            mean_time_to_detect_seconds=MetricValue.unavailable(_REASON),
            detection_rate=MetricValue.unavailable(_REASON),
            false_positive_rate=MetricValue.unavailable(_REASON),
            true_positive_count=MetricValue.unavailable(_REASON),
            false_positive_count=MetricValue.unavailable(_REASON),
            alerts_generated=MetricValue.unavailable(_REASON),
            anomaly_score_mean=MetricValue.unavailable(_REASON),
            anomaly_score_p95=MetricValue.unavailable(_REASON),
        )
