"""
backend.features.extractors.baseline — Baseline Presence Feature Extractor
===========================================================================
Module 2.2 — Behavioral Feature Engine

Computes 4 binary features indicating whether a baseline exists for
each entity dimension for the current event's actor.

Features
--------
has_user_baseline      : 1.0 if user-dimension baseline was available
has_host_baseline      : 1.0 if host-dimension baseline was available
has_source_baseline    : 1.0 if source-dimension baseline was available
has_user_host_baseline : 1.0 if user_host-dimension baseline was available

Design notes
------------
- These features let the Detection Core know which baselines are available.
- Downstream models can use these as conditioning features:
  "this novelty feature is only meaningful when has_user_baseline=1.0".
- These features require access to the BaselineReader to query all four
  entity dimensions, which is handled by the FeaturePipeline via
  the extraction context.
- The primary entity baseline (passed to extract()) may be the user
  baseline; this extractor receives the full availability map via
  a separate mechanism (context dict).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from backend.features.extractors import BaseExtractor, binary

if TYPE_CHECKING:
    from backend.baseline.models import EntityBaseline
    from backend.normalization.models import CanonicalEvent


class BaselinePresenceExtractor(BaseExtractor):
    """
    Binary flags indicating which entity-dimension baselines are available.

    This extractor differs from others: it uses the `_context` dict
    injected by FeaturePipeline rather than just the primary baseline.
    The context must contain:
        "has_user_baseline"      : bool
        "has_host_baseline"      : bool
        "has_source_baseline"    : bool
        "has_user_host_baseline" : bool
    """

    def __init__(self) -> None:
        self._context: dict[str, bool] = {}

    def set_context(self, context: dict[str, bool]) -> None:
        """
        Inject per-event availability flags from the pipeline.

        Called by FeaturePipeline before extract() for each event.
        """
        self._context = context

    @property
    def group_name(self) -> str:
        return "baseline_presence"

    @property
    def feature_names(self) -> list[str]:
        return [
            "has_user_baseline",
            "has_host_baseline",
            "has_source_baseline",
            "has_user_host_baseline",
        ]

    def extract(
        self,
        event: "CanonicalEvent",
        baseline: "EntityBaseline | None",
    ) -> dict[str, float]:
        return {
            "has_user_baseline": binary(
                self._context.get("has_user_baseline", False)
            ),
            "has_host_baseline": binary(
                self._context.get("has_host_baseline", False)
            ),
            "has_source_baseline": binary(
                self._context.get("has_source_baseline", False)
            ),
            "has_user_host_baseline": binary(
                self._context.get("has_user_host_baseline", False)
            ),
        }
