"""
backend.context.service — Attack Context Service
=================================================
Module 4.1 — Attack Context Generation

Single public orchestration layer. Only entry point into this module.

Usage
-----
    from backend.context.service import AttackContextService
    from backend.detection.models import DetectionAlert

    svc = AttackContextService()

    # Minimal — alert only
    ctx = svc.build_context(alert=alert)

    # Full — all module outputs
    ctx = svc.build_context(
        alert=alert,
        explanation=explanation,
        mapped=mapped_attack,
        graph=graph,
        chain=chain,
        events=canonical_events,
        feature_record=feature_record,
    )

    # Streaming
    for ctx in svc.build_contexts_stream(alert_iter, resolver):
        ...

    # Storage
    ctx = svc.load_context(context_id)
    ids = svc.list_context_ids()
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Callable, Iterable

import structlog

from backend.attack_graph.models import AttackGraph
from backend.chain_detection.models import AttackChain
from backend.context.builder import AttackContextBuilder
from backend.context.exceptions import ContextStorageError
from backend.context.models import AttackContext
from backend.context.storage import ContextStore
from backend.core.config import get_settings
from backend.detection.models import DetectionAlert
from backend.explainability.models import ExplanationResult
from backend.features.models import FeatureRecord
from backend.mitre.models import MappedAttack
from backend.normalization.models import CanonicalEvent

logger = structlog.get_logger(__name__)


class AttackContextService:
    """
    Orchestrates context assembly, persistence, and retrieval.

    Parameters
    ----------
    store_dir : Override storage root (default: settings.data_dir / "context").
    persist   : Auto-persist built contexts. Default True.
    """

    def __init__(
        self,
        *,
        store_dir: Path | None = None,
        persist: bool = True,
    ) -> None:
        settings = get_settings()
        resolved = store_dir or (settings.data_dir / "context")
        self._store = ContextStore(store_dir=resolved)
        self._builder = AttackContextBuilder()
        self._persist = persist
        logger.info(
            "attack_context_service_initialized",
            persist=persist,
            store_dir=str(resolved),
        )

    # ── Primary API ───────────────────────────────────────────────────────────

    def build_context(
        self,
        *,
        alert: DetectionAlert,
        explanation: ExplanationResult | None = None,
        mapped: MappedAttack | None = None,
        graph: AttackGraph | None = None,
        chain: AttackChain | None = None,
        events: list[CanonicalEvent] | None = None,
        feature_record: FeatureRecord | None = None,
        persist: bool | None = None,
    ) -> AttackContext:
        """
        Build and optionally persist a complete AttackContext.

        Parameters
        ----------
        alert        : Required. DetectionAlert anchors the context.
        explanation  : Optional SHAP ExplanationResult.
        mapped       : Optional MappedAttack from MITRE module.
        graph        : Optional AttackGraph from graph module.
        chain        : Optional AttackChain from chain detection.
        events       : Optional CanonicalEvents for evidence extraction.
        feature_record : Optional FeatureRecord for behavioral summary.
        persist      : Override instance-level persist flag.
        """
        ctx = self._builder.build(
            alert=alert,
            explanation=explanation,
            mapped=mapped,
            graph=graph,
            chain=chain,
            events=events,
            feature_record=feature_record,
        )

        should_persist = persist if persist is not None else self._persist
        if should_persist:
            self._store.save(ctx)

        return ctx

    def build_contexts_stream(
        self,
        alerts: Iterable[DetectionAlert],
        resolver: Callable[[DetectionAlert], dict],
        *,
        persist: bool | None = None,
    ) -> Iterable[AttackContext]:
        """
        Stream AttackContext objects — one per alert.

        Parameters
        ----------
        alerts   : Iterable of DetectionAlerts.
        resolver : Callable that receives a DetectionAlert and returns a dict with
                   optional keys: explanation, mapped, graph, chain, events, feature_record.
        """
        should_persist = persist if persist is not None else self._persist
        for alert in alerts:
            resolved = resolver(alert)
            ctx = self._builder.build(
                alert=alert,
                explanation=resolved.get("explanation"),
                mapped=resolved.get("mapped"),
                graph=resolved.get("graph"),
                chain=resolved.get("chain"),
                events=resolved.get("events"),
                feature_record=resolved.get("feature_record"),
            )
            if should_persist:
                self._store.save(ctx)
            yield ctx

    def build_batch(
        self,
        items: list[dict],
        *,
        persist: bool | None = None,
    ) -> list[AttackContext]:
        """
        Build multiple contexts from a list of input dicts.
        Each dict must contain 'alert' and optional other keys.
        """
        contexts: list[AttackContext] = []
        for item in items:
            ctx = self._builder.build(
                alert=item["alert"],
                explanation=item.get("explanation"),
                mapped=item.get("mapped"),
                graph=item.get("graph"),
                chain=item.get("chain"),
                events=item.get("events"),
                feature_record=item.get("feature_record"),
            )
            contexts.append(ctx)

        should_persist = persist if persist is not None else self._persist
        if should_persist:
            self._store.save_batch(contexts)

        return contexts

    # ── Query API ─────────────────────────────────────────────────────────────

    def load_context(self, context_id: str) -> AttackContext:
        return self._store.load(context_id)

    def load_for_date(self, date: datetime | None = None) -> list[AttackContext]:
        return self._store.load_for_date(date)

    def load_by_alert(self, alert_id: str) -> list[AttackContext]:
        return self._store.load_by_alert(alert_id)

    def list_context_ids(self) -> list[str]:
        return self._store.list_context_ids()

    def list_dates(self) -> list[str]:
        return self._store.list_dates()

    def get_status(self) -> dict:
        return {
            "persist": self._persist,
            "stored_contexts": len(self._store.list_context_ids()),
            "stored_dates": self._store.list_dates(),
        }

    # ── Filter helpers ────────────────────────────────────────────────────────

    @staticmethod
    def filter_high_confidence(
        contexts: list[AttackContext], threshold: float = 0.7
    ) -> list[AttackContext]:
        """Return contexts where chain confidence ≥ threshold."""
        return [
            c for c in contexts
            if c.chain is not None and c.chain.confidence >= threshold
        ]

    @staticmethod
    def filter_multi_tactic(contexts: list[AttackContext]) -> list[AttackContext]:
        """Return contexts with multi-tactic kill chains."""
        return [
            c for c in contexts
            if c.chain is not None and c.chain.is_multi_tactic
        ]

    @staticmethod
    def filter_ot_contexts(contexts: list[AttackContext]) -> list[AttackContext]:
        """Return contexts with OT/ICS indicators."""
        return [c for c in contexts if c.evidence.has_ot_indicators]

    @staticmethod
    def filter_complete(
        contexts: list[AttackContext], min_pct: float = 80.0
    ) -> list[AttackContext]:
        """Return contexts with completeness_pct ≥ min_pct."""
        return [c for c in contexts if c.completeness.completeness_pct >= min_pct]
