"""
backend.chain_detection.models — Attack Chain Data Models
==========================================================
Module 3.5 — Attack Chain Detection Engine

Pure data models — no detection logic.

An AttackChain represents a discovered sequence of ATT&CK techniques
observed in the Attack Graph that form a coherent attack progression.

Chain Anatomy
-------------
AttackChain
  ├── chain_id           — unique identifier
  ├── graph_id           — source AttackGraph
  ├── entity_id          — the entity the chain targets
  ├── nodes: [ChainNode] — technique observations in temporal order
  ├── links: [ChainLink] — directed relationships between ChainNodes
  ├── evidence: ChainEvidence
  └── evaluation: ChainEvaluation

Schema Version: 1.0.0
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import ConfigDict, Field, field_validator

from backend.shared.models import CyberShieldBaseModel
from backend.shared.utils.id_utils import generate_id

CHAIN_SCHEMA_VERSION = "1.0.0"


# ---------------------------------------------------------------------------
# ChainNode — one step in the chain (wraps a TECHNIQUE graph node)
# ---------------------------------------------------------------------------

class ChainNode(CyberShieldBaseModel):
    """
    A single technique observation forming one step in an attack chain.
    Maps 1:1 to a TECHNIQUE GraphNode in the attack graph.
    """

    model_config = ConfigDict(protected_namespaces=())

    chain_node_id: str = Field(..., description="Mirrors GraphNode.node_id for the technique")
    technique_id: str = Field(..., description="ATT&CK technique ID, e.g. T1110")
    technique_name: str
    tactic_id: str = Field(..., description="ATT&CK tactic ID, e.g. TA0006")
    tactic_name: str
    entity_id: str
    entity_type: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    observation_count: int = Field(default=1, ge=1)
    first_seen: datetime
    last_seen: datetime
    matched_features: list[str] = Field(default_factory=list)
    step_index: int = Field(default=0, ge=0, description="Zero-based position in chain")

    def to_summary(self) -> dict[str, Any]:
        return {
            "step": self.step_index,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic_name": self.tactic_name,
            "confidence": self.confidence,
            "first_seen": self.first_seen.isoformat(),
        }


# ---------------------------------------------------------------------------
# ChainLink — directed relationship between two ChainNodes
# ---------------------------------------------------------------------------

class ChainLink(CyberShieldBaseModel):
    """Directed relationship between two chain steps."""

    model_config = ConfigDict(protected_namespaces=())

    source_node_id: str
    target_node_id: str
    link_type: str = Field(..., description="Edge type from the graph: precedes / related_to")
    temporal_gap_seconds: float = Field(
        default=0.0, ge=0.0,
        description="Time between source.first_seen and target.first_seen"
    )

    @property
    def link_key(self) -> tuple[str, str]:
        return (self.source_node_id, self.target_node_id)


# ---------------------------------------------------------------------------
# ChainEvidence — supporting evidence for the chain
# ---------------------------------------------------------------------------

class ChainEvidence(CyberShieldBaseModel):
    """Aggregated supporting evidence for an AttackChain."""

    model_config = ConfigDict(protected_namespaces=())

    alert_ids: list[str] = Field(default_factory=list)
    mapping_ids: list[str] = Field(default_factory=list)
    tactic_sequence: list[str] = Field(
        default_factory=list,
        description="Ordered tactic names in the chain"
    )
    technique_ids: list[str] = Field(default_factory=list)
    matched_features: list[str] = Field(
        default_factory=list,
        description="Union of all matched features across chain steps"
    )
    total_observations: int = Field(default=0, ge=0)


# ---------------------------------------------------------------------------
# ChainEvaluation — deterministic confidence and quality metrics
# ---------------------------------------------------------------------------

class ChainEvaluation(CyberShieldBaseModel):
    """
    Deterministic quality evaluation of an AttackChain.

    Confidence formula:
        0.40 × avg_step_confidence
      + 0.25 × tactic_coverage_ratio
      + 0.20 × temporal_consistency_score
      + 0.15 × observation_strength
    All components ∈ [0, 1]. Result clipped to [0, 1], rounded to 4 dp.
    """

    model_config = ConfigDict(protected_namespaces=())

    confidence: float = Field(..., ge=0.0, le=1.0)
    avg_step_confidence: float = Field(..., ge=0.0, le=1.0)
    tactic_coverage_ratio: float = Field(
        ..., ge=0.0, le=1.0,
        description="Distinct tactics / total ATT&CK tactics expected in a full kill-chain (14)"
    )
    temporal_consistency_score: float = Field(
        ..., ge=0.0, le=1.0,
        description="1.0 if all steps are temporally ordered, 0.0 if disordered"
    )
    observation_strength: float = Field(
        ..., ge=0.0, le=1.0,
        description="Normalised total observation count across chain steps"
    )
    is_multi_tactic: bool = Field(default=False)
    is_temporally_ordered: bool = Field(default=True)
    chain_length: int = Field(default=0, ge=0)
    tactic_count: int = Field(default=0, ge=0)


# ---------------------------------------------------------------------------
# AttackChain — the primary output of this module
# ---------------------------------------------------------------------------

class AttackChain(CyberShieldBaseModel):
    """
    A discovered attack chain — an ordered sequence of ATT&CK technique
    observations forming a coherent attack progression for a specific entity.
    """

    model_config = ConfigDict(protected_namespaces=())

    chain_id: str = Field(default_factory=lambda: f"chain-{generate_id()}")
    schema_version: str = Field(default=CHAIN_SCHEMA_VERSION)
    graph_id: str = Field(..., description="Source AttackGraph.graph_id")
    entity_id: str
    entity_type: str
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    nodes: list[ChainNode] = Field(default_factory=list)
    links: list[ChainLink] = Field(default_factory=list)
    evidence: ChainEvidence = Field(default_factory=ChainEvidence)
    evaluation: ChainEvaluation = Field(
        default_factory=lambda: ChainEvaluation(
            confidence=0.0, avg_step_confidence=0.0,
            tactic_coverage_ratio=0.0, temporal_consistency_score=0.0,
            observation_strength=0.0,
        )
    )

    @field_validator("nodes")
    @classmethod
    def nodes_sorted_by_step(cls, v: list[ChainNode]) -> list[ChainNode]:
        return sorted(v, key=lambda n: n.step_index)

    @property
    def length(self) -> int:
        return len(self.nodes)

    @property
    def tactic_sequence(self) -> list[str]:
        seen: list[str] = []
        for node in self.nodes:
            if not seen or seen[-1] != node.tactic_name:
                seen.append(node.tactic_name)
        return seen

    @property
    def technique_ids(self) -> list[str]:
        return [n.technique_id for n in self.nodes]

    def to_summary(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "graph_id": self.graph_id,
            "entity_id": self.entity_id,
            "length": self.length,
            "confidence": self.evaluation.confidence,
            "tactic_sequence": self.tactic_sequence,
            "technique_ids": self.technique_ids,
            "is_multi_tactic": self.evaluation.is_multi_tactic,
            "discovered_at": self.discovered_at.isoformat(),
        }


# ---------------------------------------------------------------------------
# ChainStatistics — aggregate metrics for a detection run
# ---------------------------------------------------------------------------

class ChainStatistics(CyberShieldBaseModel):
    model_config = ConfigDict(protected_namespaces=())

    total_chains: int = Field(default=0, ge=0)
    multi_tactic_chains: int = Field(default=0, ge=0)
    avg_chain_length: float = Field(default=0.0, ge=0.0)
    avg_confidence: float = Field(default=0.0, ge=0.0)
    max_confidence: float = Field(default=0.0, ge=0.0)
    entities_affected: int = Field(default=0, ge=0)
    tactics_observed: list[str] = Field(default_factory=list)
    top_techniques: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# ChainReport — batch output for one detection run
# ---------------------------------------------------------------------------

class ChainReport(CyberShieldBaseModel):
    """Full report of all chains discovered in one detection run."""

    model_config = ConfigDict(protected_namespaces=())

    report_id: str = Field(default_factory=lambda: f"crpt-{generate_id()}")
    schema_version: str = Field(default=CHAIN_SCHEMA_VERSION)
    graph_id: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    chains: list[AttackChain] = Field(default_factory=list)
    statistics: ChainStatistics = Field(default_factory=ChainStatistics)

    def model_post_init(self, __context: Any) -> None:
        if self.chains:
            self.statistics = self._compute_stats()

    def _compute_stats(self) -> ChainStatistics:
        from collections import Counter
        if not self.chains:
            return ChainStatistics()
        confs = [c.evaluation.confidence for c in self.chains]
        lengths = [c.length for c in self.chains]
        multi = sum(1 for c in self.chains if c.evaluation.is_multi_tactic)
        entities = len({c.entity_id for c in self.chains})
        tactic_set: set[str] = set()
        tec_counter: Counter[str] = Counter()
        for ch in self.chains:
            tactic_set.update(ch.tactic_sequence)
            for nid in ch.technique_ids:
                tec_counter[nid] += 1
        return ChainStatistics(
            total_chains=len(self.chains),
            multi_tactic_chains=multi,
            avg_chain_length=round(sum(lengths) / len(lengths), 4),
            avg_confidence=round(sum(confs) / len(confs), 4),
            max_confidence=round(max(confs), 4),
            entities_affected=entities,
            tactics_observed=sorted(tactic_set),
            top_techniques=[t for t, _ in tec_counter.most_common(10)],
        )

    def to_summary(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "graph_id": self.graph_id,
            "total_chains": self.statistics.total_chains,
            "multi_tactic_chains": self.statistics.multi_tactic_chains,
            "avg_confidence": self.statistics.avg_confidence,
            "entities_affected": self.statistics.entities_affected,
        }
