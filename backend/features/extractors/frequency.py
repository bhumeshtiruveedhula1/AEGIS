"""
backend.features.extractors.frequency — Frequency Feature Extractor
====================================================================
Module 2.2 — Behavioral Feature Engine

Computes 9 behavioral frequency features comparing current event
characteristics against entity baseline frequency distributions.

Features
--------
event_type_frequency       : Count of this event_type in baseline
event_type_frequency_rank  : Rank by frequency (0.0=most common, higher=rarer)
action_frequency           : Count of this action type in baseline
result_failure_rate_baseline: Baseline proportion of failure results
result_is_failure          : 1.0 if current event result == "failure"
source_frequency           : Count of this source in baseline
entity_observation_count   : Total events in baseline for this entity
baseline_window_days       : Duration of baseline window (last_seen - first_seen)
auth_unexpected_failure    : result_is_failure * (1 - result_failure_rate_baseline).
                             High when event is a failure but baseline shows almost no
                             failures — strong brute-force / credential-stuffing signal.

Design notes
------------
- "frequency" features use raw counts (not normalised) — let downstream
  models decide how to normalise across entities.
- result_failure_rate_baseline is capped to [0.0, 1.0].
- baseline_window_days is 0.0 if only one observation day.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from backend.features.extractors import BaseExtractor, binary, frequency_rank, safe_frequency

if TYPE_CHECKING:
    from backend.baseline.models import EntityBaseline
    from backend.normalization.models import CanonicalEvent


class FrequencyExtractor(BaseExtractor):
    """Event and action frequency features."""

    @property
    def group_name(self) -> str:
        return "frequency"

    @property
    def feature_names(self) -> list[str]:
        return [
            "event_type_frequency",
            "event_type_frequency_rank",
            "action_frequency",
            "result_failure_rate_baseline",
            "result_is_failure",
            "source_frequency",
            "entity_observation_count",
            "baseline_window_days",
            "auth_unexpected_failure",
        ]

    def extract(
        self,
        event: CanonicalEvent,
        baseline: EntityBaseline | None,
    ) -> dict[str, float]:
        result_is_fail = binary(event.result is not None and event.result.lower() == "failure")

        if baseline is None:
            # event_type_frequency_rank: use 100.0 (the unseen-value cap) rather
            # than 0.0 (rank 0 = most-common) so that cold-start events are treated
            # as "never seen" rather than "maximally familiar" by the Isolation Forest.
            # All other frequency features remain 0.0 (genuinely zero counts/rates).
            return {
                "event_type_frequency": 0.0,
                "event_type_frequency_rank": 100.0,
                "action_frequency": 0.0,
                "result_failure_rate_baseline": 0.0,
                "result_is_failure": result_is_fail,
                "source_frequency": 0.0,
                "entity_observation_count": 0.0,
                "baseline_window_days": 0.0,
                # Cold-start: no baseline failure rate → treat failure as unexpected
                "auth_unexpected_failure": result_is_fail,
            }

        # Event type frequency
        et_freq = safe_frequency(event.event_type, baseline.event_type_distribution)
        et_rank = frequency_rank(event.event_type, baseline.event_type_distribution)

        # Action frequency
        act_freq = safe_frequency(event.action, baseline.action_distribution)

        # Result failure rate
        result_dist = baseline.result_distribution or {}
        total_results = sum(result_dist.values()) or 1
        fail_count = result_dist.get("failure", 0)
        result_fail_rate = min(fail_count / total_results, 1.0)

        # Source frequency
        src_freq = safe_frequency(event.source, baseline.source_distribution)

        # Observation count
        obs_count = float(baseline.observation_count)

        # Window days
        window_days = 0.0
        if baseline.first_seen is not None and baseline.last_seen is not None:
            delta = baseline.last_seen - baseline.first_seen
            window_days = max(delta.total_seconds() / 86400.0, 0.0)

        return {
            "event_type_frequency": et_freq,
            "event_type_frequency_rank": et_rank,
            "action_frequency": act_freq,
            "result_failure_rate_baseline": result_fail_rate,
            "result_is_failure": result_is_fail,
            "source_frequency": src_freq,
            "entity_observation_count": obs_count,
            "baseline_window_days": window_days,
            # Composite: 1.0 when event is a failure BUT baseline shows almost no failures.
            # Captures brute-force / credential-stuffing where individual auth failures
            # are rare in baseline but current event is a failure.
            "auth_unexpected_failure": result_is_fail * max(0.0, 1.0 - result_fail_rate),
        }
