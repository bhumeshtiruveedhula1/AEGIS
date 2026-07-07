"""
backend.metrics.exceptions — Metrics Engine Exception Hierarchy
===============================================================
Module 2.3 — Metrics Collection & Evaluation Engine

All Metrics Engine failures derive from MetricsError.

Hierarchy
---------
  MetricsError
    MetricCollectionError   — failure during metric collection
    MetricStorageError      — I/O error during metric persistence
    MetricQueryError        — invalid or unsatisfiable query
    MetricVersionError      — schema version mismatch in stored metrics
    MetricRegistryError     — collector registry configuration error
"""

from __future__ import annotations


class MetricsError(Exception):
    """Root exception for all Metrics Engine failures."""

    def __init__(self, message: str, *, context: dict | None = None) -> None:
        super().__init__(message)
        self.context: dict = context or {}

    def __str__(self) -> str:
        base = super().__str__()
        if self.context:
            ctx = ", ".join(f"{k}={v!r}" for k, v in self.context.items())
            return f"{base} [{ctx}]"
        return base


class MetricCollectionError(MetricsError):
    """
    Raised when a metric collector fails to compute its metrics.

    Collectors are designed to be fault-tolerant; this exception is
    raised only for unrecoverable failures that prevent any metric
    from being produced.

    Context keys
    ------------
    collector   — name of the collector that failed
    domain      — metric domain (pipeline, baseline, feature, etc.)
    """


class MetricStorageError(MetricsError):
    """
    Raised when the MetricStore cannot persist or load metric records.

    Examples
    --------
    - Output directory cannot be created
    - Serialisation failure writing JSONL
    - Corrupt manifest file
    """


class MetricQueryError(MetricsError):
    """
    Raised when a MetricReader query cannot be satisfied.

    Examples
    --------
    - Requested run_id does not exist in history
    - Time range is invalid (end < start)
    - Requested metric domain has no history
    """


class MetricVersionError(MetricsError):
    """
    Raised when a stored MetricSnapshot has an incompatible schema version.

    Callers should re-collect metrics rather than consuming stale data.
    """


class MetricRegistryError(MetricsError):
    """
    Raised when the collector registry is misconfigured.

    Examples
    --------
    - Duplicate collector name registered
    - Collector class does not implement required interface
    """
