"""
backend.metrics.collectors.baseline — Baseline Metrics Collector
================================================================
Module 2.3 — Metrics Collection & Evaluation Engine

Collects BaselineMetrics from:
  - BaselineProfile   (Module 2.1 output — entity baselines + metadata)
  - BaselineReader    (current active reader state)
  - BaselineManifest  (staleness — time since last build)

Available Metrics (fully computed when data is present)
-------------------------------------------------------
All 14 BaselineMetrics fields computed from real baseline data.
No fabrication — staleness is computed from manifest metadata.
"""

from __future__ import annotations

import statistics
from datetime import UTC, datetime
from typing import Any

from backend.metrics.collectors import BaseCollector, register_collector
from backend.metrics.models import (
    BaselineMetrics,
    MetricDomain,
    MetricValue,
)


@register_collector
class BaselineMetricsCollector(BaseCollector):
    """Collects baseline coverage, quality, and staleness metrics."""

    @property
    def domain(self) -> MetricDomain:
        return MetricDomain.BASELINE

    @property
    def name(self) -> str:
        return "baseline"

    def collect(self, **kwargs: Any) -> BaselineMetrics:
        """
        Compute BaselineMetrics from available baseline data.

        Keyword Arguments
        -----------------
        baseline_profile : BaselineProfile | None
        baseline_reader  : BaselineReader | None
        """
        profile = kwargs.get("baseline_profile")
        reader = kwargs.get("baseline_reader")

        return BaselineMetrics(
            entity_count=self._entity_count(profile),
            entity_type_breakdown=self._entity_type_breakdown(profile),
            baseline_coverage_ratio=self._coverage_ratio(profile),
            total_events_in_baseline=self._total_events(profile),
            mean_observations_per_entity=self._mean_observations(profile),
            min_observations_per_entity=self._min_observations(profile),
            max_observations_per_entity=self._max_observations(profile),
            mean_baseline_window_days=self._mean_window_days(profile),
            baseline_age_hours=self._baseline_age(profile),
            baseline_profile_id=self._profile_id(profile, reader),
            entities_with_network_baseline=self._count_with_sub(profile, "network"),
            entities_with_process_baseline=self._count_with_sub(profile, "process"),
            entities_with_auth_baseline=self._count_with_sub(profile, "auth"),
            entities_with_modbus_baseline=self._count_with_sub(profile, "modbus"),
        )

    # ── Private helpers ──────────────────────────────────────────────────

    def _entity_count(self, profile: Any) -> MetricValue:
        if profile is None:
            return MetricValue.insufficient("No baseline profile loaded.")
        count = getattr(profile, "entity_count", None)
        if count is None:
            entities = getattr(profile, "entities", {})
            count = len(entities)
        return MetricValue.computed(
            int(count),
            unit="count",
            description="Distinct entities in the behavioral baseline.",
        )

    def _entity_type_breakdown(self, profile: Any) -> MetricValue:
        if profile is None:
            return MetricValue.insufficient("No baseline profile loaded.")
        breakdown = getattr(profile, "entity_type_counts", None)
        if breakdown is None:
            # Compute from entities dict
            entities = getattr(profile, "entities", {})
            breakdown = {}
            for key in entities:
                etype = key.split("__", 1)[0] if "__" in key else "unknown"
                breakdown[etype] = breakdown.get(etype, 0) + 1
        return MetricValue.computed(
            dict(breakdown),
            unit="count",
            description="Entity count per entity dimension (user/host/source/user_host).",
        )

    def _coverage_ratio(self, profile: Any) -> MetricValue:
        """
        Baseline coverage is defined as entities_with_baseline / total_entities_observed.

        Without a separate 'observed entities' count, we report the entity count
        as a proxy. True coverage requires comparison with the normalization output.
        """
        if profile is None:
            return MetricValue.insufficient("No baseline profile loaded.")
        total_events = getattr(profile, "total_events_processed", None)
        entity_count = getattr(profile, "entity_count", None)
        if entity_count is None:
            entities = getattr(profile, "entities", {})
            entity_count = len(entities)
        if total_events is None or total_events == 0:
            return MetricValue.insufficient("Cannot compute coverage — total events unknown.")
        # Proxy: ratio of entities with a baseline to events (meaningful at scale)
        ratio = min(float(entity_count) / float(total_events), 1.0)
        return MetricValue.computed(
            round(ratio, 6),
            unit="ratio",
            description="Baseline entities / total events processed (coverage proxy).",
        )

    def _total_events(self, profile: Any) -> MetricValue:
        if profile is None:
            return MetricValue.insufficient("No baseline profile loaded.")
        total = getattr(profile, "total_events_processed", None)
        if total is None:
            return MetricValue.insufficient("total_events_processed not in profile.")
        return MetricValue.computed(
            int(total),
            unit="count",
            description="Total CanonicalEvents that built this baseline.",
        )

    def _observation_counts(self, profile: Any) -> list[int]:
        """Extract observation_count from all entity baselines."""
        if profile is None:
            return []
        entities = getattr(profile, "entities", {})
        counts = []
        for bl in entities.values():
            obs = getattr(bl, "observation_count", None)
            if obs is not None:
                counts.append(int(obs))
        return counts

    def _mean_observations(self, profile: Any) -> MetricValue:
        counts = self._observation_counts(profile)
        if not counts:
            return MetricValue.insufficient("No entity baselines in profile.")
        mean = statistics.mean(counts)
        return MetricValue.computed(
            round(mean, 2),
            unit="count",
            description="Mean observations per entity across all baselines.",
        )

    def _min_observations(self, profile: Any) -> MetricValue:
        counts = self._observation_counts(profile)
        if not counts:
            return MetricValue.insufficient("No entity baselines in profile.")
        return MetricValue.computed(
            min(counts),
            unit="count",
            description="Minimum observation count across all entity baselines.",
        )

    def _max_observations(self, profile: Any) -> MetricValue:
        counts = self._observation_counts(profile)
        if not counts:
            return MetricValue.insufficient("No entity baselines in profile.")
        return MetricValue.computed(
            max(counts),
            unit="count",
            description="Maximum observation count across all entity baselines.",
        )

    def _mean_window_days(self, profile: Any) -> MetricValue:
        if profile is None:
            return MetricValue.insufficient("No baseline profile loaded.")
        entities = getattr(profile, "entities", {})
        windows = []
        for bl in entities.values():
            window = getattr(bl, "observation_window_days", None)
            if callable(window):
                window = window()
            if window is not None:
                windows.append(float(window))
        if not windows:
            return MetricValue.insufficient("No observation windows computable.")
        return MetricValue.computed(
            round(statistics.mean(windows), 2),
            unit="days",
            description="Mean baseline observation window duration in days.",
        )

    def _baseline_age(self, profile: Any) -> MetricValue:
        if profile is None:
            return MetricValue.insufficient("No baseline profile loaded.")
        built_at = getattr(profile, "built_at", None)
        if built_at is None:
            return MetricValue.insufficient("Baseline built_at timestamp not available.")
        now = datetime.now(UTC)
        age_hours = (now - built_at).total_seconds() / 3600.0
        return MetricValue.computed(
            round(age_hours, 2),
            unit="hours",
            description="Hours since this baseline was built.",
        )

    def _profile_id(self, profile: Any, reader: Any) -> MetricValue:
        pid = None
        if reader is not None:
            pid = getattr(reader, "profile_id", None)
        if pid is None and profile is not None:
            pid = getattr(profile, "profile_id", None)
        if pid is None:
            return MetricValue.insufficient("No baseline profile ID available.")
        return MetricValue.computed(
            str(pid),
            description="Profile ID of the currently active baseline.",
        )

    def _count_with_sub(self, profile: Any, sub_name: str) -> MetricValue:
        if profile is None:
            return MetricValue.insufficient("No baseline profile loaded.")
        entities = getattr(profile, "entities", {})
        count = sum(
            1 for bl in entities.values()
            if getattr(bl, sub_name, None) is not None
        )
        return MetricValue.computed(
            count,
            unit="count",
            description=f"Entities with a {sub_name.capitalize()}Baseline.",
        )
