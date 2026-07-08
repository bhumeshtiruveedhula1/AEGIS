"""
backend.mitre.mapper — MITRE ATT&CK Mapper
===========================================
Module 3.3 — MITRE ATT&CK Mapper

Translates DetectionAlert + ExplanationResult into MappedAttack.

Mapping Algorithm (deterministic)
-----------------------------------
1. Collect candidate techniques by iterating top SHAP contributors
   (from ExplanationResult) through the knowledge base feature map.
   Also include techniques from the alert's entity dimension context.

2. Aggregate evidence per technique_id:
   - matched_features: feature names that map to this technique
   - shap_contributors: feature names sorted by |SHAP| descending
   - shap_total: sum of |SHAP values| for matched features
   - feature_match_count: number of matched features

3. Compute confidence (deterministic):
   confidence = (
       0.40 × alert.anomaly_score
     + 0.40 × min(shap_total / MAX_SHAP_TOTAL, 1.0)
     + 0.20 × min(feature_match_count / MAX_FEATURE_MATCH, 1.0)
   )
   clipped to [0.0, 1.0], rounded to 4 d.p.

4. Filter by min_confidence threshold (default 0.10).
   If no techniques remain → MappedAttack with empty techniques list.

5. Return MappedAttack (sorted by confidence descending by model_validator).

Statelessness
-------------
MitreMapper holds no mutable state after construction.
explain_alert / explain_batch / explain_stream are safe for concurrent use.

MAX_SHAP_TOTAL calibration
--------------------------
Empirically calibrated: IsolationForest TreeSHAP values for our 56-feature
space rarely exceed 3.0 total |SHAP|. MAX_SHAP_TOTAL = 3.0 provides a
stable normalisation anchor without over-compressing high-SHAP events.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable, Iterator

import structlog

from backend.detection.models import DetectionAlert
from backend.explainability.models import ExplanationResult, FeatureContribution
from backend.mitre.exceptions import MappingError
from backend.mitre.knowledge_base import MitreKnowledgeBase, get_knowledge_base
from backend.mitre.models import AttackTechnique, MappedAttack, TechniqueMapping

logger = structlog.get_logger(__name__)

# Confidence weight constants
_W_ANOMALY: float = 0.40
_W_SHAP: float = 0.40
_W_FEATURE_BREADTH: float = 0.20

# Normalisation anchors
_MAX_SHAP_TOTAL: float = 3.0    # max expected |SHAP| sum for 56 features
_MAX_FEATURE_MATCH: int = 10    # max expected matched features per technique

# Default confidence threshold below which techniques are discarded
DEFAULT_MIN_CONFIDENCE: float = 0.10

# Maximum techniques to include per MappedAttack (prevents noise)
MAX_TECHNIQUES_PER_ALERT: int = 8


class MitreMapper:
    """
    Stateless MITRE ATT&CK mapper.

    Parameters
    ----------
    knowledge_base    : MitreKnowledgeBase instance (default: module singleton).
    min_confidence    : Minimum confidence to include a technique.
    max_techniques    : Maximum techniques to include per MappedAttack.
    """

    def __init__(
        self,
        knowledge_base: MitreKnowledgeBase | None = None,
        *,
        min_confidence: float = DEFAULT_MIN_CONFIDENCE,
        max_techniques: int = MAX_TECHNIQUES_PER_ALERT,
    ) -> None:
        self._kb: MitreKnowledgeBase = knowledge_base or get_knowledge_base()
        self._min_confidence: float = min_confidence
        self._max_techniques: int = max_techniques
        logger.debug(
            "mitre_mapper_initialized",
            techniques_in_kb=self._kb.technique_count,
            min_confidence=min_confidence,
        )

    # ── Public API ────────────────────────────────────────────────────────────

    def map_alert(
        self,
        alert: DetectionAlert,
        explanation: ExplanationResult | None = None,
    ) -> MappedAttack:
        """
        Map one DetectionAlert (+ optional ExplanationResult) to ATT&CK techniques.

        Parameters
        ----------
        alert       : The DetectionAlert to map.
        explanation : ExplanationResult from Module 3.2 (optional but recommended).
                      When present, SHAP contributors drive technique ranking.

        Returns
        -------
        MappedAttack with 0..N TechniqueMapping objects sorted by confidence.
        Never raises on unknown features — simply returns empty techniques list.
        """
        try:
            return self._do_map(alert, explanation)
        except Exception as exc:
            raise MappingError(
                f"Failed to map alert {alert.alert_id}: {exc}",
                context={"alert_id": alert.alert_id, "cause": str(exc)},
            ) from exc

    def map_batch(
        self,
        alerts: list[DetectionAlert],
        explanations: list[ExplanationResult] | None = None,
    ) -> list[MappedAttack]:
        """
        Map multiple alerts. Parallel lists — index i of alerts matches explanations[i].

        Parameters
        ----------
        alerts       : List of DetectionAlert objects.
        explanations : Optional parallel list of ExplanationResult objects.
                       Pass None to map without SHAP evidence.

        Returns
        -------
        list[MappedAttack] in input order. Per-alert failures are logged and skipped.
        """
        if not alerts:
            return []

        expl_map: dict[str, ExplanationResult] = {}
        if explanations:
            for e in explanations:
                expl_map[e.alert_id] = e

        results: list[MappedAttack] = []
        errors = 0
        for alert in alerts:
            expl = expl_map.get(alert.alert_id)
            try:
                results.append(self.map_alert(alert, expl))
            except Exception as exc:  # noqa: BLE001
                errors += 1
                logger.warning(
                    "batch_map_error",
                    alert_id=alert.alert_id,
                    error=str(exc),
                )

        logger.info(
            "batch_mapping_complete",
            input=len(alerts),
            mapped=len(results),
            errors=errors,
        )
        return results

    def map_stream(
        self,
        pairs: Iterable[tuple[DetectionAlert, ExplanationResult | None]],
    ) -> Iterator[MappedAttack]:
        """
        Streaming mapping over (alert, explanation_or_None) pairs.
        Errors on individual pairs are logged and skipped.

        Yields
        ------
        MappedAttack objects in arrival order.
        """
        emitted = 0
        for alert, expl in pairs:
            try:
                yield self.map_alert(alert, expl)
                emitted += 1
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "stream_map_error",
                    alert_id=alert.alert_id,
                    error=str(exc),
                )
        logger.info("stream_mapping_complete", emitted=emitted)

    # ── Core mapping logic ────────────────────────────────────────────────────

    def _do_map(
        self,
        alert: DetectionAlert,
        explanation: ExplanationResult | None,
    ) -> MappedAttack:
        """Inner mapping — may raise on computation errors."""

        # --- Step 1: gather SHAP contributions (sorted by |SHAP| desc)
        shap_contributions: list[FeatureContribution] = []
        top_features: list[str] = []

        if explanation and explanation.feature_contributions:
            shap_contributions = list(explanation.feature_contributions)  # already ranked
            top_features = explanation.top_features

        # Fallback: use raw_feature_values keys from alert if no explanation
        feature_pool: list[str] = (
            top_features
            or list((alert.raw_feature_values or {}).keys())
        )

        # --- Step 2: accumulate evidence per technique_id
        # Structure: technique_id → evidence accumulator dict
        accumulators: dict[str, dict] = defaultdict(lambda: {
            "matched_features": [],
            "shap_contributors": [],
            "shap_total": 0.0,
        })

        # Primary signal: SHAP contributions via knowledge base
        if shap_contributions:
            for contrib in shap_contributions:
                fname = contrib.feature_name
                tech_ids = self._kb.technique_ids_for_feature(fname)
                if not tech_ids:
                    continue
                for tid in tech_ids:
                    acc = accumulators[tid]
                    if fname not in acc["matched_features"]:
                        acc["matched_features"].append(fname)
                    if fname not in acc["shap_contributors"]:
                        acc["shap_contributors"].append(fname)
                    acc["shap_total"] += contrib.abs_shap_value
        else:
            # Fallback: use feature pool without SHAP weighting
            for fname in feature_pool:
                for tid in self._kb.technique_ids_for_feature(fname):
                    acc = accumulators[tid]
                    if fname not in acc["matched_features"]:
                        acc["matched_features"].append(fname)

        if not accumulators:
            logger.debug(
                "no_techniques_found",
                alert_id=alert.alert_id,
                feature_count=len(feature_pool),
            )
            return self._build_mapped_attack(alert, explanation, [])

        # --- Step 3: compute confidence and build TechniqueMapping objects
        technique_mappings: list[TechniqueMapping] = []

        for tid, acc in accumulators.items():
            technique = self._kb.get_technique(tid)
            if technique is None:
                continue

            confidence = self._compute_confidence(
                anomaly_score=alert.anomaly_score,
                shap_total=acc["shap_total"],
                feature_match_count=len(acc["matched_features"]),
            )

            if confidence < self._min_confidence:
                continue

            evidence = self._build_evidence(
                technique=technique,
                matched_features=acc["matched_features"],
                shap_total=acc["shap_total"],
                anomaly_score=alert.anomaly_score,
            )

            technique_mappings.append(
                TechniqueMapping(
                    technique=technique,
                    confidence=confidence,
                    evidence=evidence,
                    matched_features=acc["matched_features"],
                    shap_contributors=acc["shap_contributors"][:5],
                    shap_total_contribution=round(acc["shap_total"], 6),
                )
            )

        # --- Step 4: sort by confidence, cap at max_techniques
        technique_mappings.sort(key=lambda t: t.confidence, reverse=True)
        technique_mappings = technique_mappings[: self._max_techniques]

        logger.info(
            "alert_mapped",
            alert_id=alert.alert_id,
            techniques=len(technique_mappings),
            primary=(
                technique_mappings[0].technique.technique_id
                if technique_mappings else None
            ),
        )

        return self._build_mapped_attack(alert, explanation, technique_mappings)

    def _compute_confidence(
        self,
        anomaly_score: float,
        shap_total: float,
        feature_match_count: int,
    ) -> float:
        """
        Deterministic confidence score in [0.0, 1.0].

        Formula
        -------
        confidence = (
            0.40 × anomaly_score
          + 0.40 × clamp(shap_total / MAX_SHAP_TOTAL, 0, 1)
          + 0.20 × clamp(feature_match_count / MAX_FEATURE_MATCH, 0, 1)
        )
        """
        shap_component = min(shap_total / _MAX_SHAP_TOTAL, 1.0)
        breadth_component = min(feature_match_count / _MAX_FEATURE_MATCH, 1.0)

        raw = (
            _W_ANOMALY * anomaly_score
            + _W_SHAP * shap_component
            + _W_FEATURE_BREADTH * breadth_component
        )
        return round(min(max(raw, 0.0), 1.0), 4)

    def _build_evidence(
        self,
        technique: AttackTechnique,
        matched_features: list[str],
        shap_total: float,
        anomaly_score: float,
    ) -> list[str]:
        """Build human-readable evidence strings for this mapping."""
        ev: list[str] = []
        ev.append(
            f"Isolation Forest anomaly score {anomaly_score:.3f} "
            f"above detection threshold."
        )
        ev.append(
            f"{len(matched_features)} behavioral feature(s) match "
            f"{technique.technique_id} ({technique.name})."
        )
        if matched_features:
            ev.append(
                f"Key features: {', '.join(matched_features[:3])}."
            )
        if shap_total > 0:
            ev.append(
                f"Cumulative SHAP contribution to technique: {shap_total:.4f}."
            )
        ev.append(
            f"Tactic: {technique.tactic.name} ({technique.tactic.tactic_id})."
        )
        return ev

    @staticmethod
    def _build_mapped_attack(
        alert: DetectionAlert,
        explanation: ExplanationResult | None,
        techniques: list[TechniqueMapping],
    ) -> MappedAttack:
        return MappedAttack(
            alert_id=alert.alert_id,
            explanation_id=explanation.explanation_id if explanation else "",
            model_id=alert.model_id,
            entity_type=alert.entity_key.entity_type,
            entity_id=alert.entity_key.entity_id,
            event_id=alert.event_id,
            anomaly_score=alert.anomaly_score,
            techniques=techniques,
            top_shap_features=(explanation.top_features if explanation else []),
        )
