"""
backend.chain_detection.evaluator — Chain Evaluator
====================================================
Module 3.5 — Attack Chain Detection Engine

ChainEvaluator computes a deterministic confidence score and quality metrics
for each discovered AttackChain.

Confidence Formula (weights sum to 1.0)
-----------------------------------------
  W_STEP   = 0.40  — average per-step technique confidence from the graph
  W_TACTIC = 0.25  — fraction of the kill-chain covered by distinct tactics
  W_TIME   = 0.20  — temporal consistency: steps are chronologically ordered
  W_OBS    = 0.15  — normalised total observation count

Kill-chain reference: 14 core ATT&CK tactics (Enterprise v15).
MAX_OBSERVATIONS: 20 — normalisation cap for observation_strength.
"""

from __future__ import annotations

from backend.chain_detection.exceptions import EvaluationError
from backend.chain_detection.models import (
    AttackChain,
    ChainEvaluation,
    ChainNode,
)

# Weights
_W_STEP: float = 0.40
_W_TACTIC: float = 0.25
_W_TIME: float = 0.20
_W_OBS: float = 0.15
assert abs(_W_STEP + _W_TACTIC + _W_TIME + _W_OBS - 1.0) < 1e-9

# Kill-chain reference size (14 Enterprise ATT&CK v15 tactics)
_FULL_KILL_CHAIN_SIZE: int = 14
# Observation strength normalisation cap
_MAX_OBSERVATIONS: int = 20


class ChainEvaluator:
    """
    Stateless evaluator for AttackChain quality.
    All methods are pure functions with no side effects.
    """

    def evaluate(self, chain: AttackChain) -> ChainEvaluation:
        """
        Compute and return a ChainEvaluation for the given AttackChain.
        Raises EvaluationError if the chain has no nodes.
        """
        if not chain.nodes:
            raise EvaluationError(
                f"Cannot evaluate chain {chain.chain_id} with no nodes.",
                context={"chain_id": chain.chain_id},
            )

        try:
            avg_step = self._avg_step_confidence(chain.nodes)
            tactic_ratio = self._tactic_coverage_ratio(chain.nodes)
            time_score = self._temporal_consistency_score(chain.nodes)
            obs_strength = self._observation_strength(chain.nodes)

            raw = (
                _W_STEP * avg_step
                + _W_TACTIC * tactic_ratio
                + _W_TIME * time_score
                + _W_OBS * obs_strength
            )
            confidence = round(min(max(raw, 0.0), 1.0), 4)

            distinct_tactics = len({n.tactic_id for n in chain.nodes})

            return ChainEvaluation(
                confidence=confidence,
                avg_step_confidence=round(avg_step, 4),
                tactic_coverage_ratio=round(tactic_ratio, 4),
                temporal_consistency_score=round(time_score, 4),
                observation_strength=round(obs_strength, 4),
                is_multi_tactic=distinct_tactics > 1,
                is_temporally_ordered=time_score == 1.0,
                chain_length=len(chain.nodes),
                tactic_count=distinct_tactics,
            )
        except Exception as exc:
            raise EvaluationError(
                f"Evaluation failed for chain {chain.chain_id}: {exc}",
                context={"chain_id": chain.chain_id, "cause": str(exc)},
            ) from exc

    def evaluate_batch(self, chains: list[AttackChain]) -> list[ChainEvaluation]:
        """Evaluate a list of chains. Errors on individual chains are re-raised."""
        return [self.evaluate(c) for c in chains]

    # ── Component calculations ────────────────────────────────────────────────

    @staticmethod
    def _avg_step_confidence(nodes: list[ChainNode]) -> float:
        if not nodes:
            return 0.0
        return sum(n.confidence for n in nodes) / len(nodes)

    @staticmethod
    def _tactic_coverage_ratio(nodes: list[ChainNode]) -> float:
        distinct_tactics = len({n.tactic_id for n in nodes})
        return min(distinct_tactics / _FULL_KILL_CHAIN_SIZE, 1.0)

    @staticmethod
    def _temporal_consistency_score(nodes: list[ChainNode]) -> float:
        """
        1.0 if nodes are strictly non-decreasing in first_seen.
        Partial credit: fraction of consecutive pairs that are ordered.
        """
        if len(nodes) < 2:
            return 1.0
        ordered = sum(
            1 for a, b in zip(nodes, nodes[1:])
            if a.first_seen <= b.first_seen
        )
        return ordered / (len(nodes) - 1)

    @staticmethod
    def _observation_strength(nodes: list[ChainNode]) -> float:
        total = sum(n.observation_count for n in nodes)
        return min(total / _MAX_OBSERVATIONS, 1.0)
