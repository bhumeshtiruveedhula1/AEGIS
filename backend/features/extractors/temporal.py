"""
backend.features.extractors.temporal — Temporal Feature Extractor
=================================================================
Module 2.2 — Behavioral Feature Engine

Computes 8 time-based behavioral features from the event timestamp
compared against the entity's baseline time pattern.

Features
--------
hour_of_day              : UTC hour (0.0–23.0)
day_of_week              : Weekday number (0.0=Mon, 6.0=Sun)
is_business_hours        : 1.0 if 08:00–18:00 Mon–Fri UTC
hour_baseline_frequency  : Normalised fraction of baseline events at this hour
hour_relative_frequency  : Current hour freq / peak hour freq (0.0–1.0)
day_baseline_frequency   : Normalised fraction of baseline events on this weekday
is_peak_hour             : 1.0 if event hour == most active baseline hour
time_since_last_seen_hrs : Hours since last_seen in baseline (0.0 = seen today)

Design notes
------------
- All frequencies are normalised (sum=1.0 across buckets) to be scale-free.
- Business hours: Monday–Friday, 08:00–18:00 UTC (infrastructure assumption).
- time_since_last_seen_hours is capped at 8760.0 (1 year) to prevent extreme values.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from backend.features.extractors import BaseExtractor, binary

if TYPE_CHECKING:
    from backend.baseline.models import EntityBaseline
    from backend.normalization.models import CanonicalEvent


_BUSINESS_HOUR_START = 8   # inclusive
_BUSINESS_HOUR_END   = 18  # exclusive
_MAX_HOURS_SINCE_SEEN = 8760.0  # 1 year cap


class TemporalExtractor(BaseExtractor):
    """Temporal behavior features derived from event timestamp."""

    @property
    def group_name(self) -> str:
        return "temporal"

    @property
    def feature_names(self) -> list[str]:
        return [
            "hour_of_day",
            "day_of_week",
            "is_business_hours",
            "hour_baseline_frequency",
            "hour_relative_frequency",
            "day_baseline_frequency",
            "is_peak_hour",
            "time_since_last_seen_hours",
        ]

    def extract(
        self,
        event: "CanonicalEvent",
        baseline: "EntityBaseline | None",
    ) -> dict[str, float]:
        ts: datetime = event.timestamp
        hour = float(ts.hour)
        dow = float(ts.weekday())  # Monday=0

        # Business hours: Mon–Fri, 08:00–18:00 UTC
        is_biz = binary(
            ts.weekday() < 5  # noqa: PLR2004
            and _BUSINESS_HOUR_START <= ts.hour < _BUSINESS_HOUR_END
        )

        # ── Baseline-derived temporal features ─────────────────────────────
        hour_baseline_freq = 0.0
        hour_relative_freq = 0.0
        day_baseline_freq = 0.0
        is_peak = 0.0
        time_since = 0.0

        if baseline is not None and baseline.time_pattern is not None:
            tp = baseline.time_pattern
            total = float(tp.total_events) if tp.total_events else 0.0

            # Hourly bucket normalisation
            hourly = tp.hourly_buckets  # list[int], length 24
            if total > 0 and hourly:
                hour_idx = int(ts.hour)
                hour_baseline_freq = hourly[hour_idx] / total if hour_idx < len(hourly) else 0.0
                peak_count = max(hourly) if hourly else 0
                hour_relative_freq = (
                    (hourly[hour_idx] / peak_count) if peak_count > 0 else 0.0
                )
                peak_hour = hourly.index(max(hourly))
                is_peak = binary(ts.hour == peak_hour)

            # Daily bucket normalisation
            daily = tp.daily_buckets  # list[int], length 7
            if total > 0 and daily:
                dow_idx = int(ts.weekday())
                day_baseline_freq = daily[dow_idx] / total if dow_idx < len(daily) else 0.0

            # Time since last seen — use the event's own timestamp, not wall-clock.
            # This makes the feature deterministic for historical replay:
            # the same event always produces the same time_since value
            # regardless of when the pipeline is executed.
            if baseline.last_seen is not None:
                event_utc = event.timestamp.astimezone(UTC)
                delta = event_utc - baseline.last_seen
                hours = delta.total_seconds() / 3600.0
                time_since = min(max(hours, 0.0), _MAX_HOURS_SINCE_SEEN)

        return {
            "hour_of_day": hour,
            "day_of_week": dow,
            "is_business_hours": is_biz,
            "hour_baseline_frequency": hour_baseline_freq,
            "hour_relative_frequency": hour_relative_freq,
            "day_baseline_frequency": day_baseline_freq,
            "is_peak_hour": is_peak,
            "time_since_last_seen_hours": time_since,
        }
