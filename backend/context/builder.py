"""
backend.context.builder — Attack Context Builder
=================================================
Module 4.1 — Attack Context Generation

AttackContextBuilder assembles an AttackContext from module outputs.
No business logic — only calls summarizers and timeline builder.
All logic lives in summarizer.py and timeline.py.
"""

from __future__ import annotations

import structlog

from backend.attack_graph.models import AttackGraph
from backend.chain_detection.models import AttackChain
from backend.context.exceptions import ContextBuildError, InsufficientInputError
from backend.context.models import AttackContext, ContextIdentity
from backend.context.summarizer import (
    BehavioralSummarizer,
    ChainSummarizer,
    CompletenessSummarizer,
    DetectionSummarizer,
    EvidenceSummarizer,
    GraphSummarizer,
    MitreSummarizer,
    ShapSummarizer,
    StatisticalSummarizer,
)
from backend.context.timeline import TimelineBuilder
from backend.detection.models import DetectionAlert
from backend.explainability.models import ExplanationResult
from backend.features.models import FeatureRecord
from backend.mitre.models import MappedAttack
from backend.normalization.models import CanonicalEvent

logger = structlog.get_logger(__name__)


class AttackContextBuilder:
    """
    Assembles an AttackContext from module outputs.

    Parameters
    ----------
    alert       : Required. DetectionAlert is the anchor.
    explanation : Optional SHAP explanation.
    mapped      : Optional MITRE mapped attack.
    graph       : Optional attack graph.
    chain       : Optional attack chain.
    events      : Optional list of CanonicalEvents for evidence extraction.
    feature_record : Optional FeatureRecord for behavioral summary.
    """

    def build(
        self,
        *,
        alert: DetectionAlert,
        explanation: ExplanationResult | None = None,
        mapped: MappedAttack | None = None,
        graph: AttackGraph | None = None,
        chain: AttackChain | None = None,
        events: list[CanonicalEvent] | None = None,
        feature_record: FeatureRecord | None = None,
    ) -> AttackContext:
        if alert is None:
            raise InsufficientInputError(
                "DetectionAlert is required to build AttackContext.",
                context={"reason": "alert is None"},
            )

        try:
            # Identity
            identity = self._build_identity(alert, chain, graph)

            # Per-domain summaries
            detection = DetectionSummarizer.build(alert)
            shap = ShapSummarizer.build(explanation) if explanation else ShapSummarizer.build_empty()
            mitre = MitreSummarizer.build(mapped) if mapped else MitreSummarizer.build_empty()
            graph_sum = GraphSummarizer.build(graph) if graph else GraphSummarizer.build_empty()
            chain_sum = ChainSummarizer.build(chain) if chain else ChainSummarizer.build_empty()
            behavioral = BehavioralSummarizer.build(alert, feature_record)
            statistical = StatisticalSummarizer.build(alert)
            evidence = EvidenceSummarizer.build(events or [])

            # Timeline (requires chain)
            timeline_builder = TimelineBuilder()
            timeline = timeline_builder.build(chain) if chain else timeline_builder.build_empty()

            # Completeness
            completeness = CompletenessSummarizer.build(
                has_detection=True,
                has_shap=explanation is not None,
                has_mitre=mapped is not None,
                has_graph=graph is not None,
                has_chain=chain is not None,
                has_timeline=len(timeline) > 0,
                has_evidence=bool(events),
                has_behavioral=True,
                has_statistical=True,
            )

            ctx = AttackContext(
                identity=identity,
                detection=detection,
                shap=shap,
                mitre=mitre,
                graph=graph_sum,
                chain=chain_sum,
                timeline=timeline,
                evidence=evidence,
                behavioral=behavioral,
                statistical=statistical,
                completeness=completeness,
            )

            logger.info(
                "attack_context_assembled",
                context_id=ctx.context_id,
                alert_id=alert.alert_id,
                completeness_pct=completeness.completeness_pct,
                timeline_steps=len(timeline),
            )
            return ctx

        except (InsufficientInputError, ContextBuildError):
            raise
        except Exception as exc:
            raise ContextBuildError(
                f"Failed to build AttackContext for alert {alert.alert_id}: {exc}",
                context={"alert_id": alert.alert_id, "cause": str(exc)},
            ) from exc

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _build_identity(
        alert: DetectionAlert,
        chain: AttackChain | None,
        graph: AttackGraph | None,
    ) -> ContextIdentity:
        # entity_key is an EntityKey model with entity_type and entity_id
        ek = alert.entity_key
        entity_type = ek.entity_type if hasattr(ek, "entity_type") else str(ek)
        entity_id = ek.entity_id if hasattr(ek, "entity_id") else str(ek)

        return ContextIdentity(
            alert_id=alert.alert_id,
            chain_id=chain.chain_id if chain else "",
            graph_id=graph.graph_id if graph else "",
            entity_type=entity_type,
            entity_id=entity_id,
            host=alert.event_host,
            user=alert.event_user,
            source=alert.event_source,
            event_id=alert.event_id,
        )
