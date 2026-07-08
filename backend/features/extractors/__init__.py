"""
backend.features.extractors — Base Extractor ABC and Registry
=============================================================
Module 2.2 — Behavioral Feature Engine

Defines the BaseExtractor ABC that all feature extractors MUST implement,
plus the EXTRACTOR_REGISTRY and helper utilities used by the pipeline.

Architecture
------------
Each extractor is responsible for ONE feature group.
Extractors are pure — they take (event, baseline | None) and return
a dict[str, float]. No I/O. No global state. No side effects.

Adding a New Extractor
----------------------
1. Create backend/features/extractors/<group>.py
2. Subclass BaseExtractor, implement extract()
3. Register in EXTRACTOR_REGISTRY below
4. Add tests in tests/unit/features/test_<group>.py
"""

from __future__ import annotations

import math
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from backend.baseline.models import EntityBaseline
    from backend.normalization.models import CanonicalEvent


# ---------------------------------------------------------------------------
# Numeric helpers
# ---------------------------------------------------------------------------

def safe_z_score(value: float, mean: float | None, std: float | None) -> float:
    """
    Compute (value - mean) / std safely.

    Returns 0.0 when:
    - mean or std is None (baseline not computed)
    - std == 0 (no variance in baseline — every observation identical)
    - result would be NaN or Inf

    The 0.0 return value is intentional: a z-score of 0 means "equal to the
    mean", which is the most conservative encoding when variance is unknown.
    """
    if mean is None or std is None or std == 0.0:
        return 0.0
    z = (value - mean) / std
    if not math.isfinite(z):
        return 0.0
    return z


def safe_percentile_rank(value: float, p25: float | None, p50: float | None,
                          p75: float | None, p95: float | None) -> float:
    """
    Approximate where `value` falls in the baseline distribution.

    Returns a value in [0.0, 4.0]:
      0.0  — at or below p25
      1.0  — between p25 and p50
      2.0  — between p50 and p75
      3.0  — between p75 and p95
      4.0  — above p95

    Returns 0.0 when any percentile is None (baseline not available).
    """
    if any(p is None for p in (p25, p50, p75, p95)):
        return 0.0
    # Cast to float for comparison safety
    p25f, p50f, p75f, p95f = float(p25), float(p50), float(p75), float(p95)  # type: ignore[arg-type]
    if value <= p25f:
        return 0.0
    if value <= p50f:
        return 1.0
    if value <= p75f:
        return 2.0
    if value <= p95f:
        return 3.0
    return 4.0


def safe_frequency(
    value: str | int | None, distribution: dict | None, *, lower: bool = True
) -> float:
    """
    Return the count of `value` in a frequency distribution dict.

    Parameters
    ----------
    value        : The value to look up (str or int).
    distribution : Dict mapping value → count. None = cold-start.
    lower        : If True, lowercase string values before lookup.

    Returns 0.0 when distribution is None or value is None.
    """
    if value is None or distribution is None:
        return 0.0
    key = str(value).lower() if lower else str(value)
    return float(distribution.get(key, distribution.get(str(value), 0)))


def frequency_rank(value: str | None, distribution: dict | None) -> float:
    """
    Return the rank (0-indexed) of `value` by frequency in `distribution`.

    Rank 0 = most frequent. Returns 0.0 when value is None or not in distribution.
    Higher rank = rarer value. Comparison is case-insensitive.
    """
    if value is None or distribution is None:
        return 0.0
    lowered = value.lower()
    # Normalise all keys to lowercase for comparison
    lower_dist: dict[str, int] = {}
    for k, v in distribution.items():
        lower_dist[k.lower()] = lower_dist.get(k.lower(), 0) + v
    sorted_keys = sorted(lower_dist, key=lambda k: lower_dist[k], reverse=True)
    try:
        return float(sorted_keys.index(lowered))
    except ValueError:
        # Unseen value: return a rank beyond all seen values, capped at 100.0.
        # Without the cap, this value varies with baseline size — an entity with
        # 200 event types produces rank=200 while a small entity produces rank=5,
        # making the feature non-comparable across entities for the Isolation Forest.
        return min(float(len(sorted_keys)), 100.0)


def binary(condition: bool | None) -> float:
    """Convert a bool (or None) to 1.0 (True) or 0.0 (False / None)."""
    if condition is None:
        return 0.0
    return 1.0 if condition else 0.0


# ---------------------------------------------------------------------------
# BaseExtractor — ABC for all feature group extractors
# ---------------------------------------------------------------------------

class BaseExtractor(ABC):
    """
    Abstract base class for all behavioral feature extractors.

    Each concrete extractor owns one feature group (e.g., temporal,
    network, process) and computes all features in that group from:
      - A single CanonicalEvent
      - The EntityBaseline for the primary entity (may be None on cold-start)

    Contract
    --------
    - extract() MUST return exactly the keys declared in `feature_names`.
    - All returned values MUST be finite floats.
    - extract() MUST NOT raise exceptions — log and return defaults instead.
    - extract() MUST be deterministic — same inputs produce same outputs.
    - extract() MUST NOT perform I/O.
    - extract() MUST NOT mutate its inputs.
    """

    @property
    @abstractmethod
    def group_name(self) -> str:
        """Name of the feature group this extractor produces."""

    @property
    @abstractmethod
    def feature_names(self) -> list[str]:
        """Ordered list of feature names this extractor produces."""

    @abstractmethod
    def extract(
        self,
        event: "CanonicalEvent",
        baseline: "EntityBaseline | None",
    ) -> dict[str, float]:
        """
        Compute all features for this group.

        Parameters
        ----------
        event    : The CanonicalEvent to extract features from.
        baseline : The EntityBaseline for the primary entity, or None.

        Returns
        -------
        dict[str, float] — exactly the keys in self.feature_names.
        """

    def safe_extract(
        self,
        event: "CanonicalEvent",
        baseline: "EntityBaseline | None",
    ) -> tuple[dict[str, float], list[str]]:
        """
        Wrapper around extract() that catches all exceptions.

        Returns
        -------
        (features, warnings) — features default to 0.0 on failure.
        """
        import structlog
        logger = structlog.get_logger(self.__class__.__name__)

        try:
            result = self.extract(event, baseline)
            # Sanitise: ensure all values are finite floats
            cleaned: dict[str, float] = {}
            warnings: list[str] = []
            for name in self.feature_names:
                val = result.get(name, 0.0)
                if not math.isfinite(val):
                    cleaned[name] = 0.0
                    warnings.append(
                        f"{self.group_name}.{name} produced non-finite value {val!r}; "
                        f"defaulting to 0.0"
                    )
                else:
                    cleaned[name] = float(val)
            return cleaned, warnings

        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "extractor_failed",
                group=self.group_name,
                event_id=getattr(event, "event_id", "unknown"),
                error=str(exc),
            )
            defaults = {name: 0.0 for name in self.feature_names}
            warnings = [
                f"{self.group_name} extractor failed ({type(exc).__name__}: {exc}); "
                f"all features defaulted to 0.0"
            ]
            return defaults, warnings


# ---------------------------------------------------------------------------
# EXTRACTOR_REGISTRY — maps group name → extractor instance
# Populated lazily to avoid circular imports.
# ---------------------------------------------------------------------------

def _build_registry() -> dict[str, BaseExtractor]:
    """Build the extractor registry. Called once at first access."""
    from backend.features.extractors.temporal import TemporalExtractor
    from backend.features.extractors.frequency import FrequencyExtractor
    from backend.features.extractors.network import NetworkExtractor
    from backend.features.extractors.process import ProcessExtractor
    from backend.features.extractors.auth import AuthExtractor
    from backend.features.extractors.ot import OTExtractor
    from backend.features.extractors.baseline import BaselinePresenceExtractor
    from backend.features.extractors.entity_activity import EntityActivityExtractor

    instances = [
        TemporalExtractor(),
        FrequencyExtractor(),
        NetworkExtractor(),
        ProcessExtractor(),
        AuthExtractor(),
        OTExtractor(),
        BaselinePresenceExtractor(),
        EntityActivityExtractor(),
    ]
    return {e.group_name: e for e in instances}


_REGISTRY: dict[str, BaseExtractor] | None = None


def get_extractor_registry() -> dict[str, BaseExtractor]:
    """Return the singleton extractor registry, building it on first call."""
    global _REGISTRY  # noqa: PLW0603
    if _REGISTRY is None:
        _REGISTRY = _build_registry()
    return _REGISTRY


def get_all_extractors() -> list[BaseExtractor]:
    """Return all extractor instances in declaration order."""
    registry = get_extractor_registry()
    from backend.features.models import FEATURE_GROUPS
    return [registry[g] for g in FEATURE_GROUPS if g in registry]
