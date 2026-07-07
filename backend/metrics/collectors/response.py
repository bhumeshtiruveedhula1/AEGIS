"""
backend.metrics.collectors.response — Response Metrics Collector
================================================================
Module 2.3 — Metrics Collection & Evaluation Engine

All ResponseMetrics are UNAVAILABLE in this release.

Response Orchestration (Module 3.x) is not yet implemented.
This collector marks every response metric as UNAVAILABLE with an
informative reason string.

When Module 3.x is implemented, it will pass response_actions and
timing_data to MetricService.collect_all(), and this collector will
compute real MTTR, automation coverage, and audit coverage values.
"""

from __future__ import annotations

from typing import Any

from backend.metrics.collectors import BaseCollector, register_collector
from backend.metrics.models import (
    MetricDomain,
    MetricValue,
    ResponseMetrics,
)

_REASON = "Requires Response Orchestration (Module 3.x), not yet implemented."


@register_collector
class ResponseMetricsCollector(BaseCollector):
    """Placeholder collector for response and orchestration metrics (Module 3.x)."""

    @property
    def domain(self) -> MetricDomain:
        return MetricDomain.RESPONSE

    @property
    def name(self) -> str:
        return "response"

    def collect(self, **kwargs: Any) -> ResponseMetrics:
        """
        All response metrics are UNAVAILABLE until Module 3.x is integrated.

        Future Integration
        ------------------
        When Module 3.x is ready, populate these kwargs in MetricService:
          response_actions : list[ResponseAction]
          approval_records : list[ApprovalRecord]
        """
        return ResponseMetrics(
            mean_time_to_respond_seconds=MetricValue.unavailable(_REASON),
            automation_coverage=MetricValue.unavailable(_REASON),
            audit_coverage=MetricValue.unavailable(_REASON),
            actions_executed=MetricValue.unavailable(_REASON),
            actions_approved=MetricValue.unavailable(_REASON),
            actions_rejected=MetricValue.unavailable(_REASON),
        )
