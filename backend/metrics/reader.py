"""
backend.metrics.reader — Metric Reader
=======================================
Module 2.3 — Metrics Collection & Evaluation Engine

Provides the public query interface for the metrics subsystem.

MetricReader wraps MetricStore and provides higher-level query operations:
  - Latest snapshot lookup
  - Historical trend queries (domain-level)
  - Run-over-run comparison (MetricRunComparison)
  - Specific metric value retrieval with dot-notation paths

This is the read-only interface. Writes always go through MetricService → MetricStore.

Design
------
- MetricReader is stateless — uses MetricStore for all data access.
- Path-based metric access: "pipeline.events_normalized.value"
- Trend queries produce lists of (timestamp, float) pairs.
- Comparison produces MetricRunComparison with deltas for every numeric metric.
"""

from __future__ import annotations

import math
from datetime import UTC, datetime
from typing import Any, Iterator

import structlog

from backend.metrics.exceptions import MetricQueryError
from backend.metrics.models import (
    METRICS_SCHEMA_VERSION,
    ManifestEntry,
    MetricAvailability,
    MetricDelta,
    MetricDomain,
    MetricHistoryManifest,
    MetricRecord,
    MetricRunComparison,
    MetricSnapshot,
    MetricValue,
)
from backend.metrics.store import MetricStore

logger = structlog.get_logger(__name__)

# Metrics where a LOWER value is better (improvements go downward)
_LOWER_IS_BETTER = {
    "normalization_error_rate",
    "events_failed",
    "feature_extraction_errors",
    "extraction_error_rate",
    "extraction_warning_rate",
    "false_positive_rate",
    "false_positive_count",
    "mean_time_to_detect_seconds",
    "mean_time_to_respond_seconds",
    "cold_start_fraction",
    "baseline_age_hours",
}


class MetricReader:
    """
    Read-only query interface for the metrics subsystem.

    Parameters
    ----------
    store : MetricStore instance. Defaults to a new MetricStore.
    """

    def __init__(self, store: MetricStore | None = None) -> None:
        self._store = store or MetricStore()

    # ── Latest snapshot ──────────────────────────────────────────────────

    def latest_snapshot(self) -> MetricSnapshot | None:
        """
        Return the most recent MetricSnapshot, or None if empty.
        """
        record = self._store.load_latest()
        return record.snapshot if record is not None else None

    def latest_record(self) -> MetricRecord | None:
        """Return the most recent MetricRecord including storage metadata."""
        return self._store.load_latest()

    # ── Specific metric lookup ───────────────────────────────────────────

    def get_metric(
        self,
        snapshot: MetricSnapshot,
        domain: MetricDomain,
        metric_name: str,
    ) -> MetricValue | None:
        """
        Retrieve a specific MetricValue from a snapshot.

        Parameters
        ----------
        snapshot    : The MetricSnapshot to query.
        domain      : Which domain the metric belongs to.
        metric_name : Field name within the domain model.

        Returns None if the domain or metric does not exist.
        """
        domain_obj = self._domain_obj(snapshot, domain)
        if domain_obj is None:
            return None
        val = getattr(domain_obj, metric_name, None)
        if isinstance(val, MetricValue):
            return val
        return None

    def get_value(
        self,
        snapshot: MetricSnapshot,
        domain: MetricDomain,
        metric_name: str,
        default: float = 0.0,
    ) -> float:
        """
        Get the numeric value of a metric, returning default if unavailable.

        Safe for arithmetic — never returns NaN or Inf.
        """
        mv = self.get_metric(snapshot, domain, metric_name)
        if mv is None:
            return default
        return mv.safe_float(default)

    # ── Historical trend ─────────────────────────────────────────────────

    def trend(
        self,
        domain: MetricDomain,
        metric_name: str,
        *,
        limit: int = 30,
        since: datetime | None = None,
    ) -> list[tuple[datetime, float]]:
        """
        Return a time series of (timestamp, value) for a specific metric.

        Only COMPUTED values are included. UNAVAILABLE / INSUFFICIENT_DATA
        entries produce no point in the series.

        Parameters
        ----------
        domain      : Which domain to query.
        metric_name : Field name within the domain model.
        limit       : Maximum data points to return (newest first).
        since       : Only include snapshots after this UTC datetime.

        Returns
        -------
        List of (collected_at, value) tuples, sorted ascending by time.
        """
        records = self._store.load_history(limit=limit * 2, since=since)
        points: list[tuple[datetime, float]] = []

        for record in records:
            mv = self.get_metric(record.snapshot, domain, metric_name)
            if mv is not None and mv.is_computed:
                f = mv.safe_float()
                if math.isfinite(f):
                    points.append((record.snapshot.collected_at, f))

        # Sort ascending, apply limit
        points.sort(key=lambda x: x[0])
        return points[-limit:]

    def trend_summary(
        self,
        domain: MetricDomain,
        metric_name: str,
        *,
        limit: int = 30,
    ) -> dict[str, Any]:
        """
        Return a statistical summary of a metric trend.

        Returns
        -------
        dict with keys: count, mean, min, max, latest, first
        """
        points = self.trend(domain, metric_name, limit=limit)
        if not points:
            return {
                "count": 0,
                "mean": None,
                "min": None,
                "max": None,
                "latest": None,
                "first": None,
            }
        values = [v for _, v in points]
        return {
            "count": len(points),
            "mean": round(sum(values) / len(values), 6),
            "min": min(values),
            "max": max(values),
            "latest": points[-1][1],
            "first": points[0][1],
        }

    # ── Run comparison ───────────────────────────────────────────────────

    def compare_snapshots(
        self,
        baseline_id: str,
        current_id: str,
    ) -> MetricRunComparison:
        """
        Compare two MetricSnapshots and return a MetricRunComparison.

        Parameters
        ----------
        baseline_id : snapshot_id of the reference (earlier) snapshot.
        current_id  : snapshot_id of the current (later) snapshot.

        Raises
        ------
        MetricQueryError if either snapshot cannot be found.
        """
        baseline_record = self._store.load_snapshot(baseline_id)
        if baseline_record is None:
            raise MetricQueryError(
                f"Baseline snapshot not found: {baseline_id}",
                context={"snapshot_id": baseline_id},
            )
        current_record = self._store.load_snapshot(current_id)
        if current_record is None:
            raise MetricQueryError(
                f"Current snapshot not found: {current_id}",
                context={"snapshot_id": current_id},
            )

        deltas = self._compute_deltas(baseline_record.snapshot, current_record.snapshot)

        return MetricRunComparison(
            baseline_snapshot_id=baseline_id,
            current_snapshot_id=current_id,
            deltas=deltas,
        )

    def compare_last_two(self) -> MetricRunComparison | None:
        """
        Compare the two most recent snapshots.

        Returns None if fewer than 2 snapshots exist.
        """
        records = self._store.load_history(limit=2)
        if len(records) < 2:
            return None
        # records is newest-first
        return self.compare_snapshots(
            baseline_id=records[1].snapshot.snapshot_id,
            current_id=records[0].snapshot.snapshot_id,
        )

    # ── Manifest access ──────────────────────────────────────────────────

    def manifest(self) -> MetricHistoryManifest:
        """Return the current metrics manifest."""
        return self._store.get_manifest()

    def snapshot_count(self) -> int:
        """Return the total number of stored snapshots."""
        return self._store.record_count()

    def list_snapshots(self, *, limit: int = 20) -> list[ManifestEntry]:
        """Return the N most recent manifest entries."""
        m = self._store.get_manifest()
        return m.entries[:limit]

    # ── Private helpers ──────────────────────────────────────────────────

    def _domain_obj(self, snapshot: MetricSnapshot, domain: MetricDomain) -> Any | None:
        """Return the domain model object from a snapshot."""
        domain_map = {
            MetricDomain.PIPELINE: snapshot.pipeline,
            MetricDomain.BASELINE: snapshot.baseline,
            MetricDomain.FEATURE: snapshot.feature,
            MetricDomain.DETECTION: snapshot.detection,
            MetricDomain.RESPONSE: snapshot.response,
            MetricDomain.PLATFORM_HEALTH: snapshot.health,
        }
        return domain_map.get(domain)

    def _compute_deltas(
        self,
        before: MetricSnapshot,
        after: MetricSnapshot,
    ) -> list[MetricDelta]:
        """Compute numeric deltas for all COMPUTED metric pairs."""
        deltas: list[MetricDelta] = []
        domain_pairs = [
            (MetricDomain.PIPELINE, before.pipeline, after.pipeline),
            (MetricDomain.BASELINE, before.baseline, after.baseline),
            (MetricDomain.FEATURE, before.feature, after.feature),
            (MetricDomain.DETECTION, before.detection, after.detection),
            (MetricDomain.RESPONSE, before.response, after.response),
            (MetricDomain.PLATFORM_HEALTH, before.health, after.health),
        ]

        for domain, before_obj, after_obj in domain_pairs:
            if before_obj is None or after_obj is None:
                continue
            for field_name in type(before_obj).model_fields:
                bv = getattr(before_obj, field_name, None)
                av = getattr(after_obj, field_name, None)
                if not (isinstance(bv, MetricValue) and isinstance(av, MetricValue)):
                    continue

                delta, delta_pct, improved = self._compute_single_delta(
                    bv, av, field_name
                )
                deltas.append(MetricDelta(
                    metric_name=field_name,
                    domain=domain,
                    before=bv,
                    after=av,
                    delta=delta,
                    delta_pct=delta_pct,
                    improved=improved,
                ))

        return deltas

    def _compute_single_delta(
        self,
        before: MetricValue,
        after: MetricValue,
        metric_name: str,
    ) -> tuple[float | None, float | None, bool | None]:
        """
        Compute delta, delta_pct, and improved for two MetricValues.

        Returns (delta, delta_pct, improved).
        """
        if not (before.is_computed and after.is_computed):
            return None, None, None

        b_val = before.safe_float()
        a_val = after.safe_float()

        if not (math.isfinite(b_val) and math.isfinite(a_val)):
            return None, None, None

        delta = round(a_val - b_val, 6)

        if b_val == 0:
            delta_pct = None
        else:
            delta_pct = round((delta / abs(b_val)) * 100.0, 2)

        # Determine if the change is an improvement
        lower_is_better = metric_name in _LOWER_IS_BETTER
        if delta == 0:
            improved = None  # no change
        elif lower_is_better:
            improved = delta < 0  # lower = better
        else:
            improved = delta > 0  # higher = better

        return delta, delta_pct, improved
