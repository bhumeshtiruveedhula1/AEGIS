"""
backend.baseline.updater — Incremental Baseline Updater
=======================================================
Module 2.1 — Baseline Generator

BaselineUpdater merges new CanonicalEvent observations into an existing
EntityBaseline without requiring a full rebuild from scratch.

This enables:
- Scheduled incremental updates (e.g., daily new telemetry)
- Real-time baseline drift tracking
- Rolling baseline windows

Algorithm
---------
Numeric fields use Welford's online algorithm for mean + variance:
  Given existing (n, mean, M2) and new observation x:
    n_new   = n + 1
    delta   = x - mean
    mean_new = mean + delta / n_new
    delta2  = x - mean_new
    M2_new  = M2 + delta * delta2
    std_new = sqrt(M2_new / (n_new - 1))

Categorical fields:
    value_frequencies[v] = existing.get(v, 0) + new_count[v]
    seen_values = seen_values | new_values (capped at max_values)

Time patterns:
    hourly_buckets[h] += new_counts[h]   (element-wise addition)
    daily_buckets[d]  += new_counts[d]

Set fields (unique_dst_ips, unique_processes, etc.):
    existing_set | new_set  (union, bounded only by memory)

Design
------
BaselineUpdater is STATELESS — it does not own any baseline data.
It takes an existing EntityBaseline and new events, returns an updated one.
The caller decides whether to persist the result.

Usage
-----
    updater = BaselineUpdater()

    # Get existing baseline (from store or builder)
    existing = store.load_entity(entity_key)

    # Merge new events
    updated = updater.update(existing, new_events)

    # Persist the result
    store.save_entity(entity_key, updated)
"""

from __future__ import annotations

import math
from collections import Counter
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import structlog

from backend.baseline.models import (
    AuthBaseline,
    EntityBaseline,
    ModbusBaseline,
    NetworkBaseline,
    NumericStats,
    ProcessBaseline,
    TimePattern,
)
from backend.baseline.statistics import (
    compute_auth_baseline,
    compute_entity_baseline,
    compute_modbus_baseline,
    compute_network_baseline,
    compute_process_baseline,
    compute_time_pattern,
)

if TYPE_CHECKING:
    from backend.normalization.models import CanonicalEvent

logger = structlog.get_logger(__name__)


class BaselineUpdater:
    """
    Merges new observations into an existing EntityBaseline.

    Stateless: takes existing baseline + new events → returns updated baseline.
    Does NOT read from or write to disk.

    Parameters
    ----------
    max_categorical_values:  Max unique values in frequency dists.
    """

    def __init__(self, max_categorical_values: int = 100) -> None:
        self._max_cat = max_categorical_values

    def update(
        self,
        existing: EntityBaseline,
        new_events: list["CanonicalEvent"],
    ) -> EntityBaseline:
        """
        Merge new events into an existing EntityBaseline.

        Strategy
        --------
        For each sub-baseline (network, process, modbus, auth):
          1. Compute the sub-baseline for new_events only.
          2. Merge with the existing sub-baseline.

        For universal distributions (event_type, action, result, source):
          Counter merge.

        For time pattern:
          Element-wise bucket addition.

        For observation window (first_seen, last_seen):
          min/max across both.

        Parameters
        ----------
        existing:    Existing EntityBaseline to update.
        new_events:  New CanonicalEvent observations to incorporate.

        Returns
        -------
        Updated EntityBaseline (existing is not mutated).
        """
        if not new_events:
            logger.debug(
                "baseline_updater_no_new_events",
                entity=repr(existing.entity_key),
            )
            return existing

        logger.info(
            "baseline_updater_merging",
            entity=repr(existing.entity_key),
            existing_count=existing.observation_count,
            new_event_count=len(new_events),
        )

        # ── Universal distributions ───────────────────────────────────────
        event_type_dist = _merge_counters(
            existing.event_type_distribution,
            Counter(str(e.event_type) for e in new_events),
        )
        action_dist = _merge_counters(
            existing.action_distribution,
            Counter(str(e.action) for e in new_events),
        )
        result_dist = _merge_counters(
            existing.result_distribution,
            Counter(str(e.result) for e in new_events),
        )
        source_dist = _merge_counters(
            existing.source_distribution,
            Counter(str(e.source) for e in new_events),
        )

        # ── Time pattern ─────────────────────────────────────────────────
        new_time = compute_time_pattern([e.timestamp for e in new_events])
        merged_time = _merge_time_patterns(existing.time_pattern, new_time)

        # ── Observation window ────────────────────────────────────────────
        new_timestamps = [e.timestamp for e in new_events]
        new_first = min(new_timestamps)
        new_last = max(new_timestamps)

        first_seen = (
            min(existing.first_seen, new_first)
            if existing.first_seen
            else new_first
        )
        last_seen = (
            max(existing.last_seen, new_last)
            if existing.last_seen
            else new_last
        )

        # ── Domain-specific baselines ─────────────────────────────────────
        new_net = compute_network_baseline(new_events, max_values=self._max_cat)
        merged_net = _merge_network(existing.network, new_net)

        new_proc = compute_process_baseline(new_events)
        merged_proc = _merge_process(existing.process, new_proc)

        new_modbus = compute_modbus_baseline(new_events)
        merged_modbus = _merge_modbus(existing.modbus, new_modbus)

        new_auth = compute_auth_baseline(new_events)
        merged_auth = _merge_auth(existing.auth, new_auth)

        # ── Resource stats ────────────────────────────────────────────────
        new_resources = [str(e.resource) for e in new_events if e.resource]
        merged_resource = None
        if existing.resource_stats and new_resources:
            merged_resource = _merge_categorical(
                existing.resource_stats, new_resources, self._max_cat
            )
        elif existing.resource_stats:
            merged_resource = existing.resource_stats
        elif new_resources:
            from backend.baseline.statistics import compute_categorical_stats
            merged_resource = compute_categorical_stats(
                "resource", new_resources, max_values=self._max_cat
            )

        return EntityBaseline(
            entity_key=existing.entity_key,
            baseline_version=existing.baseline_version,
            observation_count=existing.observation_count + len(new_events),
            first_seen=first_seen,
            last_seen=last_seen,
            computed_at=datetime.now(UTC),
            event_type_distribution=event_type_dist,
            action_distribution=action_dist,
            result_distribution=result_dist,
            source_distribution=source_dist,
            time_pattern=merged_time,
            network=merged_net,
            process=merged_proc,
            modbus=merged_modbus,
            auth=merged_auth,
            resource_stats=merged_resource,
        )

    def update_numeric(
        self,
        existing: NumericStats,
        new_values: list[float | int],
    ) -> NumericStats:
        """
        Merge new numeric observations using Welford's algorithm.

        This is the incremental equivalent of compute_numeric_stats().
        Can be called independently when only numeric stats need updating.

        Parameters
        ----------
        existing:   Existing NumericStats (from builder or previous update).
        new_values: New observations to incorporate.

        Returns
        -------
        Updated NumericStats (existing is not mutated).
        """
        if not new_values:
            return existing

        # Recover Welford state
        n = existing.count
        mean = existing.mean or 0.0
        m2 = existing._welford_m2 or 0.0
        minimum = existing.minimum
        maximum = existing.maximum

        for v in new_values:
            fv = float(v)
            n += 1
            delta = fv - mean
            mean += delta / n
            delta2 = fv - mean
            m2 += delta * delta2
            if minimum is None or fv < minimum:
                minimum = fv
            if maximum is None or fv > maximum:
                maximum = fv

        std = math.sqrt(m2 / (n - 1)) if n > 1 else 0.0

        # Re-compute percentiles with all values
        # (requires re-sorting — unavoidable without storing all observations)
        # For production, use approximate percentiles or accept this tradeoff.
        # Here we compute from the new values only, then merge p50 as approximate.
        new_sorted = sorted(float(v) for v in new_values)

        updated = NumericStats(
            field_name=existing.field_name,
            count=n,
            mean=mean,
            std=std,
            minimum=minimum,
            maximum=maximum,
            # Percentiles after update are approximations — exact requires all data
            p25=existing.p25,
            p50=existing.p50,
            p75=existing.p75,
            p95=existing.p95,
            p99=existing.p99,
        )
        updated._welford_m2 = m2
        return updated


# ---------------------------------------------------------------------------
# Private merge helpers (pure functions)
# ---------------------------------------------------------------------------

def _merge_counters(
    existing: dict[str, int],
    new: Counter[str],
) -> dict[str, int]:
    """Merge two frequency dicts by summing counts."""
    result = dict(existing)
    for k, v in new.items():
        result[k] = result.get(k, 0) + v
    return result


def _merge_time_patterns(
    existing: TimePattern,
    new: TimePattern,
) -> TimePattern:
    """Element-wise addition of hourly and daily buckets."""
    hourly = [existing.hourly_buckets[i] + new.hourly_buckets[i] for i in range(24)]
    daily = [existing.daily_buckets[i] + new.daily_buckets[i] for i in range(7)]
    return TimePattern(
        hourly_buckets=hourly,
        daily_buckets=daily,
        total_events=existing.total_events + new.total_events,
    )


def _merge_network(
    existing: NetworkBaseline | None,
    new: NetworkBaseline | None,
) -> NetworkBaseline | None:
    """Merge two NetworkBaseline objects."""
    if existing is None:
        return new
    if new is None:
        return existing

    port_dist = _merge_counters(existing.port_distribution, Counter(new.port_distribution))
    proto_dist = _merge_counters(existing.protocol_distribution, Counter(new.protocol_distribution))

    return NetworkBaseline(
        unique_src_ips=existing.unique_src_ips | new.unique_src_ips,
        unique_dst_ips=existing.unique_dst_ips | new.unique_dst_ips,
        port_distribution=port_dist,
        protocol_distribution=proto_dist,
        bytes_out_stats=existing.bytes_out_stats,  # keep existing approximation
        connection_count=existing.connection_count + new.connection_count,
    )


def _merge_process(
    existing: ProcessBaseline | None,
    new: ProcessBaseline | None,
) -> ProcessBaseline | None:
    """Merge two ProcessBaseline objects."""
    if existing is None:
        return new
    if new is None:
        return existing

    proc_freq = _merge_counters(existing.process_frequency, Counter(new.process_frequency))

    return ProcessBaseline(
        unique_processes=existing.unique_processes | new.unique_processes,
        unique_parent_processes=existing.unique_parent_processes | new.unique_parent_processes,
        process_frequency=proc_freq,
        parent_child_pairs=existing.parent_child_pairs | new.parent_child_pairs,
        pid_stats=existing.pid_stats,  # approximation kept
        process_event_count=existing.process_event_count + new.process_event_count,
    )


def _merge_modbus(
    existing: ModbusBaseline | None,
    new: ModbusBaseline | None,
) -> ModbusBaseline | None:
    """Merge two ModbusBaseline objects."""
    if existing is None:
        return new
    if new is None:
        return existing

    fc_dist = _merge_counters(
        existing.function_code_distribution,
        Counter(new.function_code_distribution),
    )

    return ModbusBaseline(
        register_stats=existing.register_stats,  # keep existing range approximation
        value_stats=existing.value_stats,
        function_code_distribution=fc_dist,
        known_supervisory_hosts=existing.known_supervisory_hosts | new.known_supervisory_hosts,
        modbus_event_count=existing.modbus_event_count + new.modbus_event_count,
    )


def _merge_auth(
    existing: AuthBaseline | None,
    new: AuthBaseline | None,
) -> AuthBaseline | None:
    """Merge two AuthBaseline objects."""
    if existing is None:
        return new
    if new is None:
        return existing

    logon_dist = _merge_counters(
        existing.logon_type_distribution, Counter(new.logon_type_distribution)
    )
    pkg_dist = _merge_counters(
        existing.auth_package_distribution, Counter(new.auth_package_distribution)
    )
    win_id_dist = _merge_counters(
        existing.windows_event_id_distribution, Counter(new.windows_event_id_distribution)
    )

    return AuthBaseline(
        logon_type_distribution=logon_dist,
        auth_package_distribution=pkg_dist,
        failure_count=existing.failure_count + new.failure_count,
        success_count=existing.success_count + new.success_count,
        windows_event_id_distribution=win_id_dist,
        auth_event_count=existing.auth_event_count + new.auth_event_count,
    )


def _merge_categorical(
    existing,
    new_values: list[str],
    max_values: int,
):
    """Merge new string observations into existing CategoricalStats."""
    from backend.baseline.models import CategoricalStats

    new_counter = Counter(new_values)
    merged_freq = dict(existing.value_frequencies)
    for v, c in new_counter.items():
        merged_freq[v] = merged_freq.get(v, 0) + c

    # Re-trim to max_values
    top_merged = dict(
        Counter(merged_freq).most_common(max_values)
    )
    new_unique = existing.total_unique_values + len(
        set(new_values) - existing.seen_values
    )

    return CategoricalStats(
        field_name=existing.field_name,
        count=existing.count + len(new_values),
        total_unique_values=new_unique,
        value_frequencies=top_merged,
        seen_values=existing.seen_values | set(top_merged.keys()),
        max_values=max_values,
    )
