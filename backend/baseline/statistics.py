"""
backend.baseline.statistics — Behavioral Statistics Computation
===============================================================
Module 2.1 — Baseline Generator

Pure computation functions that produce EntityBaseline from a list of
CanonicalEvent objects for one entity.

Design Principles
-----------------
- ALL functions are PURE: no I/O, no global state, no side effects.
- Every function takes data in, returns data out. Fully testable in isolation.
- None-aware: fields that are None in the canonical schema are skipped.
  Statistics are only computed when at least one non-None value exists.
- Welford's online algorithm is used for mean+variance computation.
  This enables the BaselineUpdater to apply incremental updates later.
- Statistics are computed in a single pass per field where possible.

Module Organisation
-------------------
  compute_entity_baseline()     — main entry point (assembles all sub-stats)
  compute_numeric_stats()       — NumericStats from a list of numbers
  compute_categorical_stats()   — CategoricalStats from a list of strings
  compute_time_pattern()        — TimePattern from a list of datetimes
  compute_network_baseline()    — NetworkBaseline from events
  compute_process_baseline()    — ProcessBaseline from events
  compute_modbus_baseline()     — ModbusBaseline from events
  compute_auth_baseline()       — AuthBaseline from events
  _welford_update()             — incremental mean/variance (one step)

Welford's Algorithm Reference
------------------------------
For running mean and variance without storing observations:
  n, mean, M2 = 0, 0.0, 0.0
  for each value x:
      n += 1
      delta = x - mean
      mean += delta / n
      delta2 = x - mean
      M2 += delta * delta2
  variance = M2 / (n - 1)  # sample variance
  std = sqrt(variance)
"""

from __future__ import annotations

import math
from collections import Counter
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from backend.baseline.models import (
    AuthBaseline,
    CategoricalStats,
    EntityBaseline,
    EntityKey,
    ModbusBaseline,
    NetworkBaseline,
    NumericStats,
    ProcessBaseline,
    TimePattern,
)

if TYPE_CHECKING:
    from backend.normalization.models import CanonicalEvent


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def compute_entity_baseline(
    entity_key: EntityKey,
    events: list["CanonicalEvent"],
    *,
    max_categorical_values: int = 100,
) -> EntityBaseline:
    """
    Compute a complete EntityBaseline from a list of CanonicalEvent objects.

    This is the single entry point for StatisticsComputer.
    All sub-baselines are computed by delegating to the appropriate
    pure functions below.

    Parameters
    ----------
    entity_key:              The entity this baseline describes.
    events:                  All CanonicalEvents for this entity.
    max_categorical_values:  Max unique values to store in CategoricalStats.

    Returns
    -------
    EntityBaseline with all applicable statistics populated.
    """
    if not events:
        return EntityBaseline(
            entity_key=entity_key,
            observation_count=0,
        )

    # ── Universal distributions ───────────────────────────────────────────
    event_type_dist = _count_field(events, "event_type")
    action_dist = _count_field(events, "action")
    result_dist = _count_field(events, "result")
    source_dist = _count_field(events, "source")

    # ── Temporal pattern ─────────────────────────────────────────────────
    timestamps = [e.timestamp for e in events]
    time_pattern = compute_time_pattern(timestamps)

    # ── Observation window ───────────────────────────────────────────────
    first_seen = min(timestamps)
    last_seen = max(timestamps)

    # ── Resource stats ────────────────────────────────────────────────────
    resource_values = [str(e.resource) for e in events if e.resource]
    resource_stats = (
        compute_categorical_stats("resource", resource_values, max_values=max_categorical_values)
        if resource_values
        else None
    )

    # ── Domain-specific baselines ─────────────────────────────────────────
    network = _maybe_compute_network(events, max_categorical_values)
    process = _maybe_compute_process(events)
    modbus = _maybe_compute_modbus(events)
    auth = _maybe_compute_auth(events)

    return EntityBaseline(
        entity_key=entity_key,
        observation_count=len(events),
        first_seen=first_seen,
        last_seen=last_seen,
        event_type_distribution=event_type_dist,
        action_distribution=action_dist,
        result_distribution=result_dist,
        source_distribution=source_dist,
        time_pattern=time_pattern,
        network=network,
        process=process,
        modbus=modbus,
        auth=auth,
        resource_stats=resource_stats,
    )


# ---------------------------------------------------------------------------
# NumericStats
# ---------------------------------------------------------------------------

def compute_numeric_stats(
    field_name: str,
    values: list[float | int],
) -> NumericStats:
    """
    Compute descriptive statistics for a list of numeric values.

    Uses a two-pass approach:
    - Pass 1: Welford's algorithm for mean and variance.
    - Pass 2: percentile computation (sort + index).

    Parameters
    ----------
    field_name:  Name of the CanonicalEvent field (for identification).
    values:      Non-None numeric observations. Must be non-empty.

    Returns
    -------
    NumericStats with count, mean, std, min, max, percentiles.

    Raises
    ------
    ValueError if values is empty (caller must ensure non-empty).
    """
    if not values:
        return NumericStats(field_name=field_name, count=0)

    n = 0
    mean = 0.0
    m2 = 0.0
    minimum = float(values[0])
    maximum = float(values[0])

    for v in values:
        fv = float(v)
        n += 1
        delta = fv - mean
        mean += delta / n
        delta2 = fv - mean
        m2 += delta * delta2
        if fv < minimum:
            minimum = fv
        if fv > maximum:
            maximum = fv

    # Sample variance (n-1 denominator — Bessel's correction)
    if n > 1:
        variance = m2 / (n - 1)
        std = math.sqrt(variance)
    else:
        std = 0.0

    # Percentiles via sorted copy
    sorted_vals = sorted(float(v) for v in values)
    p25 = _percentile(sorted_vals, 25)
    p50 = _percentile(sorted_vals, 50)
    p75 = _percentile(sorted_vals, 75)
    p95 = _percentile(sorted_vals, 95)
    p99 = _percentile(sorted_vals, 99)

    stats = NumericStats(
        field_name=field_name,
        count=n,
        mean=mean,
        std=std,
        minimum=minimum,
        maximum=maximum,
        p25=p25,
        p50=p50,
        p75=p75,
        p95=p95,
        p99=p99,
    )
    # Store Welford M2 state for incremental updates.
    # This is a proper Pydantic field — it persists through JSON round-trips.
    stats = stats.model_copy(update={"welford_m2": m2})
    return stats


# ---------------------------------------------------------------------------
# CategoricalStats
# ---------------------------------------------------------------------------

def compute_categorical_stats(
    field_name: str,
    values: list[str],
    *,
    max_values: int = 100,
) -> CategoricalStats:
    """
    Compute frequency distribution for a list of string values.

    Parameters
    ----------
    field_name:  Name of the field (for identification).
    values:      Non-None string observations.
    max_values:  Maximum unique values to retain in seen_values and frequencies.

    Returns
    -------
    CategoricalStats with top-max_values value_frequencies.
    """
    if not values:
        return CategoricalStats(field_name=field_name, count=0, max_values=max_values)

    counter = Counter(values)
    total_unique = len(counter)

    # Take top-N by frequency
    top_n = dict(counter.most_common(max_values))
    seen = set(top_n.keys())

    return CategoricalStats(
        field_name=field_name,
        count=len(values),
        total_unique_values=total_unique,
        value_frequencies=top_n,
        seen_values=seen,
        max_values=max_values,
    )


# ---------------------------------------------------------------------------
# TimePattern
# ---------------------------------------------------------------------------

def compute_time_pattern(timestamps: list[datetime]) -> TimePattern:
    """
    Compute hourly and daily activity distributions from timestamps.

    Parameters
    ----------
    timestamps:  List of UTC-aware datetime objects.

    Returns
    -------
    TimePattern with 24-bucket hourly and 7-bucket daily arrays.
    """
    hourly = [0] * 24
    daily = [0] * 7

    for ts in timestamps:
        # Ensure UTC
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        utc_ts = ts.astimezone(UTC)
        hourly[utc_ts.hour] += 1
        daily[utc_ts.weekday()] += 1  # 0=Monday, 6=Sunday

    return TimePattern(
        hourly_buckets=hourly,
        daily_buckets=daily,
        total_events=len(timestamps),
    )


# ---------------------------------------------------------------------------
# NetworkBaseline
# ---------------------------------------------------------------------------

def compute_network_baseline(
    events: list["CanonicalEvent"],
    *,
    max_values: int = 100,
) -> NetworkBaseline | None:
    """
    Compute network behavioral baseline from events.

    Returns None if no events have any network fields (src_ip, dst_ip, port).
    """
    network_events = [
        e for e in events
        if e.src_ip is not None or e.dst_ip is not None or e.port is not None
    ]
    if not network_events:
        return None

    src_ips = {e.src_ip for e in network_events if e.src_ip is not None}
    dst_ips = {e.dst_ip for e in network_events if e.dst_ip is not None}

    port_counter: Counter[str] = Counter(
        str(e.port) for e in network_events if e.port is not None
    )
    protocol_counter: Counter[str] = Counter(
        e.protocol for e in network_events if e.protocol is not None
    )

    bytes_values = [e.bytes_out for e in network_events if e.bytes_out is not None]
    bytes_stats = (
        compute_numeric_stats("bytes_out", bytes_values) if bytes_values else None
    )

    return NetworkBaseline(
        unique_src_ips=src_ips,
        unique_dst_ips=dst_ips,
        port_distribution=dict(port_counter.most_common(max_values)),
        protocol_distribution=dict(protocol_counter),
        bytes_out_stats=bytes_stats,
        connection_count=len(network_events),
    )


# ---------------------------------------------------------------------------
# ProcessBaseline
# ---------------------------------------------------------------------------

def compute_process_baseline(
    events: list["CanonicalEvent"],
) -> ProcessBaseline | None:
    """
    Compute process behavioral baseline from events.

    Returns None if no events have process fields.
    """
    process_events = [e for e in events if e.process is not None]
    if not process_events:
        return None

    processes = {e.process for e in process_events if e.process}
    parents = {e.parent_process for e in process_events if e.parent_process}
    proc_counter: Counter[str] = Counter(
        e.process for e in process_events if e.process
    )

    # Parent→child pairs as "parent__child" strings
    pairs: set[str] = set()
    for e in process_events:
        if e.parent_process and e.process:
            pairs.add(f"{e.parent_process}__{e.process}")

    pids = [e.pid for e in process_events if e.pid is not None]
    pid_stats = compute_numeric_stats("pid", pids) if pids else None

    return ProcessBaseline(
        unique_processes=processes,
        unique_parent_processes=parents,
        process_frequency=dict(proc_counter),
        parent_child_pairs=pairs,
        pid_stats=pid_stats,
        process_event_count=len(process_events),
    )


# ---------------------------------------------------------------------------
# ModbusBaseline
# ---------------------------------------------------------------------------

def compute_modbus_baseline(
    events: list["CanonicalEvent"],
) -> ModbusBaseline | None:
    """
    Compute Modbus/OT behavioral baseline from events.

    Returns None if no events have Modbus fields.
    """
    # Include any event with at least one Modbus-relevant field.
    # This covers: register read/write, FC-only commands (broadcasts,
    # coil commands), and value-only events without a specific register.
    modbus_events = [
        e for e in events
        if (
            e.modbus_register is not None
            or e.modbus_function_code is not None
            or e.modbus_value is not None
        )
    ]
    if not modbus_events:
        return None

    registers = [e.modbus_register for e in modbus_events if e.modbus_register is not None]
    values = [e.modbus_value for e in modbus_events if e.modbus_value is not None]
    fc_counter: Counter[str] = Counter(
        e.modbus_function_code
        for e in modbus_events
        if e.modbus_function_code is not None
    )
    supervisory_hosts = {
        e.supervisory_host for e in modbus_events if e.supervisory_host
    }

    return ModbusBaseline(
        register_stats=compute_numeric_stats("modbus_register", registers) if registers else None,
        value_stats=compute_numeric_stats("modbus_value", values) if values else None,
        function_code_distribution=dict(fc_counter),
        known_supervisory_hosts=supervisory_hosts,
        modbus_event_count=len(modbus_events),
    )


# ---------------------------------------------------------------------------
# AuthBaseline
# ---------------------------------------------------------------------------

def compute_auth_baseline(
    events: list["CanonicalEvent"],
) -> AuthBaseline | None:
    """
    Compute authentication behavioral baseline from events.

    Returns None if no events have authentication fields (logon_type,
    auth_package, or windows_event_id).
    """
    auth_events = [
        e for e in events
        if e.logon_type is not None or e.auth_package is not None or e.windows_event_id is not None
    ]
    if not auth_events:
        return None

    logon_counter: Counter[str] = Counter(
        e.logon_type for e in auth_events if e.logon_type
    )
    pkg_counter: Counter[str] = Counter(
        e.auth_package for e in auth_events if e.auth_package
    )
    win_id_counter: Counter[str] = Counter(
        str(e.windows_event_id)
        for e in auth_events
        if e.windows_event_id is not None
    )

    failure_count = sum(
        1 for e in auth_events if str(e.result).lower() == "failure"
    )
    success_count = sum(
        1 for e in auth_events if str(e.result).lower() == "success"
    )

    return AuthBaseline(
        logon_type_distribution=dict(logon_counter),
        auth_package_distribution=dict(pkg_counter),
        failure_count=failure_count,
        success_count=success_count,
        windows_event_id_distribution=dict(win_id_counter),
        auth_event_count=len(auth_events),
    )


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _count_field(events: list["CanonicalEvent"], field: str) -> dict[str, int]:
    """Count occurrences of each unique value for a string field."""
    counter: Counter[str] = Counter(
        str(getattr(e, field, "") or "")
        for e in events
        if getattr(e, field, None) is not None
    )
    return dict(counter)


def _maybe_compute_network(
    events: list["CanonicalEvent"],
    max_categorical_values: int,
) -> NetworkBaseline | None:
    """Compute NetworkBaseline only if network fields are present."""
    return compute_network_baseline(events, max_values=max_categorical_values)


def _maybe_compute_process(
    events: list["CanonicalEvent"],
) -> ProcessBaseline | None:
    """Compute ProcessBaseline only if process fields are present."""
    return compute_process_baseline(events)


def _maybe_compute_modbus(
    events: list["CanonicalEvent"],
) -> ModbusBaseline | None:
    """Compute ModbusBaseline only if modbus fields are present."""
    return compute_modbus_baseline(events)


def _maybe_compute_auth(
    events: list["CanonicalEvent"],
) -> AuthBaseline | None:
    """Compute AuthBaseline only if auth fields are present."""
    return compute_auth_baseline(events)


def _percentile(sorted_vals: list[float], pct: float) -> float:
    """
    Compute the p-th percentile of a pre-sorted list.

    Uses linear interpolation (same as numpy percentile with method='linear').

    Parameters
    ----------
    sorted_vals:  Pre-sorted list of floats.
    pct:          Percentile (0–100).
    """
    n = len(sorted_vals)
    if n == 0:
        return 0.0
    if n == 1:
        return sorted_vals[0]

    idx = (pct / 100.0) * (n - 1)
    lower = int(idx)
    upper = lower + 1

    if upper >= n:
        return sorted_vals[-1]

    frac = idx - lower
    return sorted_vals[lower] + frac * (sorted_vals[upper] - sorted_vals[lower])
