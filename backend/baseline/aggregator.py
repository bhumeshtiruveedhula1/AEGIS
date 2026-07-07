"""
backend.baseline.aggregator — Event Aggregator
===============================================
Module 2.1 — Baseline Generator

Groups CanonicalEvent objects by EntityKey across four dimensions:
  user       — per-service-account behavior
  host       — per-machine behavior
  source     — per-telemetry-source behavior
  user_host  — user-on-host combined fingerprint

The aggregator is a PURE grouping operation — no statistics are computed here.
It produces a mapping of EntityKey → list[CanonicalEvent] which is then
passed to the StatisticsComputer for per-entity baseline computation.

Design Principles
-----------------
- One pass over the event list for all four dimensions simultaneously.
- Memory-efficient: events are grouped into lists, not duplicated.
  Each event appears in 4 groups (one per dimension), but is not copied —
  only references are stored.
- Deterministic: same input → same output (no randomness).
- No I/O: this is a pure in-memory transformation.

Entity ID Rules
---------------
user:      event.user.lower().strip()
host:      event.host.lower().strip()
source:    event.source.lower().strip()
user_host: f"{user}::{host}" (double colon separator)

All IDs are lowercased and stripped before grouping.

Usage
-----
    aggregator = EventAggregator()
    groups = aggregator.aggregate(events)
    # groups: dict[EntityKey, list[CanonicalEvent]]

    # Restrict to specific dimensions:
    aggregator = EventAggregator(dimensions={"user", "host"})
"""

from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING

import structlog

from backend.baseline.models import ENTITY_TYPES, EntityKey

if TYPE_CHECKING:
    from backend.normalization.models import CanonicalEvent

logger = structlog.get_logger(__name__)

# All four entity dimensions supported
_ALL_DIMENSIONS = frozenset(ENTITY_TYPES)


class EventAggregator:
    """
    Groups CanonicalEvent objects by EntityKey across behavioral dimensions.

    Parameters
    ----------
    dimensions:  Set of entity types to compute. Defaults to all four.
                 Valid: {"user", "host", "source", "user_host"}

    Usage
    -----
        aggregator = EventAggregator()
        groups = aggregator.aggregate(events)

        for entity_key, entity_events in groups.items():
            baseline = compute_baseline(entity_key, entity_events)
    """

    def __init__(
        self,
        dimensions: set[str] | frozenset[str] | None = None,
    ) -> None:
        if dimensions is None:
            self._dimensions = _ALL_DIMENSIONS
        else:
            invalid = set(dimensions) - _ALL_DIMENSIONS
            if invalid:
                msg = f"Invalid entity dimensions: {invalid}. Valid: {_ALL_DIMENSIONS}"
                raise ValueError(msg)
            self._dimensions = frozenset(dimensions)

    @property
    def dimensions(self) -> frozenset[str]:
        """Entity dimensions this aggregator computes."""
        return self._dimensions

    def aggregate(
        self,
        events: list["CanonicalEvent"],
    ) -> dict[EntityKey, list["CanonicalEvent"]]:
        """
        Group events by EntityKey across all configured dimensions.

        Single pass — O(n) where n = len(events).
        Each event contributes to len(dimensions) groups.

        Parameters
        ----------
        events:  List of CanonicalEvent objects (in any order).

        Returns
        -------
        dict mapping EntityKey → list of events for that entity.
        Keys are sorted by entity_type, then entity_id for determinism.
        """
        if not events:
            logger.warning("baseline_aggregator_empty_input")
            return {}

        groups: dict[EntityKey, list["CanonicalEvent"]] = defaultdict(list)

        for event in events:
            for key in self._extract_keys(event):
                groups[key].append(event)

        result = dict(groups)

        logger.info(
            "baseline_aggregator_complete",
            input_events=len(events),
            total_entity_groups=len(result),
            groups_by_dimension={
                dim: sum(1 for k in result if k.entity_type == dim)
                for dim in self._dimensions
            },
        )

        return result

    def aggregate_stream(
        self,
        events_iter: "CanonicalEvent",  # type: ignore[assignment]  # actually iterable
    ) -> dict[EntityKey, list["CanonicalEvent"]]:
        """
        Aggregate from any iterable (generator-friendly).

        Materialises the iterable into a list first, then aggregates.
        For very large streams this trades memory for simplicity.
        The baseline builder uses this with stream() from the reader.

        Parameters
        ----------
        events_iter:  Any iterable of CanonicalEvent.
        """
        return self.aggregate(list(events_iter))

    def group_counts(
        self,
        groups: dict[EntityKey, list["CanonicalEvent"]],
    ) -> dict[str, int]:
        """
        Return counts of entity groups per dimension type.

        Useful for logging and the BuildReport.

        Parameters
        ----------
        groups:  Output of aggregate().

        Returns
        -------
        dict mapping entity_type → count of distinct entities.
        """
        counts: dict[str, int] = defaultdict(int)
        for key in groups:
            counts[key.entity_type] += 1
        return dict(counts)

    # ── Private helpers ──────────────────────────────────────────────────────

    def _extract_keys(self, event: "CanonicalEvent") -> list[EntityKey]:
        """
        Extract all EntityKey objects for one event across active dimensions.

        Rules
        -----
        - user:      event.user (lowercased)
        - host:      event.host (lowercased)
        - source:    event.source (lowercased)
        - user_host: f"{user}::{host}"

        Skips a dimension if the resulting entity_id would be empty.
        """
        keys: list[EntityKey] = []
        user = str(event.user).lower().strip() if event.user else ""
        host = str(event.host).lower().strip() if event.host else ""
        source = str(event.source).lower().strip() if event.source else ""

        if "user" in self._dimensions and user:
            keys.append(EntityKey(entity_type="user", entity_id=user))

        if "host" in self._dimensions and host:
            keys.append(EntityKey(entity_type="host", entity_id=host))

        if "source" in self._dimensions and source:
            keys.append(EntityKey(entity_type="source", entity_id=source))

        if "user_host" in self._dimensions and user and host:
            combined = f"{user}::{host}"
            keys.append(EntityKey(entity_type="user_host", entity_id=combined))

        return keys
