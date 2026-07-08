"""
backend.context.models — Attack Context Data Models
====================================================
Module 4.1 — Attack Context Generation

Pure immutable Pydantic models. Zero business logic.

Hierarchy
---------
AttackContext                   ← single input to Phase 5 LLM Reasoning Agent
  ├── ContextIdentity           ← who / what / where
  ├── DetectionSummary          ← anomaly score, confidence, timing
  ├── ShapSummary               ← top features, contributions
  ├── MitreSummary              ← techniques, tactics, confidence
  ├── GraphSummary              ← graph shape, connectivity
  ├── ChainSummary              ← ordered kill-chain
  ├── list[TimelineEvent]       ← deterministic chronology
  ├── SupportingEvidence        ← hosts, users, IPs, processes, OT
  ├── BehavioralSummary         ├ novelty deltas from Feature Engine
  ├── StatisticalSummary        ← anomaly metrics from Metrics Engine
  └── ContextCompleteness       ← deterministic quality metadata

Schema version: 1.0.0
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import ConfigDict, Field

from backend.shared.models import CyberShieldBaseModel
from backend.shared.utils.id_utils import generate_id

CONTEXT_SCHEMA_VERSION = "1.0.0"


# ─────────────────────────────────────────────────────────────────────────────
# Sub-models
# ─────────────────────────────────────────────────────────────────────────────

class ContextIdentity(CyberShieldBaseModel):
    """Who and what triggered this context."""
    alert_id: str
    chain_id: str = Field(default="")
    graph_id: str = Field(default="")
    entity_type: str
    entity_id: str
    host: str = Field(default="")
    user: str = Field(default="")
    source: str = Field(default="")
    event_id: str = Field(default="")


class FeatureSummaryItem(CyberShieldBaseModel):
    """One SHAP-explained feature."""
    feature_name: str
    raw_value: float
    shap_value: float
    direction: str        # "positive" | "negative"
    contribution_pct: float


class ShapSummary(CyberShieldBaseModel):
    """Pre-computed SHAP explainability output — never recomputed here."""
    explanation_id: str = Field(default="")
    total_abs_shap: float = Field(default=0.0)
    expected_value: float = Field(default=0.0)
    top_features: list[FeatureSummaryItem] = Field(default_factory=list)
    positive_contributors: list[str] = Field(default_factory=list)
    negative_contributors: list[str] = Field(default_factory=list)
    feature_count: int = Field(default=0)


class DetectionSummary(CyberShieldBaseModel):
    """Detection layer output — no recomputation."""
    model_config = ConfigDict(protected_namespaces=())
    model_id: str
    anomaly_score: float
    threshold_used: float = Field(default=0.0)
    raw_if_score: float = Field(default=0.0)
    feature_dimension: int = Field(default=0)
    novelty_count: int = Field(default=0)
    baseline_available: bool = Field(default=True)
    detection_timestamp: datetime


class TechniqueSummary(CyberShieldBaseModel):
    """One MITRE ATT&CK technique."""
    technique_id: str
    technique_name: str
    tactic_id: str
    tactic_name: str
    confidence: float


class MitreSummary(CyberShieldBaseModel):
    """MITRE mapping output — no remapping."""
    mapping_id: str = Field(default="")
    primary_technique: TechniqueSummary | None = Field(default=None)
    supporting_techniques: list[TechniqueSummary] = Field(default_factory=list)
    all_technique_ids: list[str] = Field(default_factory=list)
    all_tactic_ids: list[str] = Field(default_factory=list)
    technique_count: int = Field(default=0)
    tactic_count: int = Field(default=0)
    mapping_confidence: float = Field(default=0.0)


class GraphSummary(CyberShieldBaseModel):
    """Attack graph shape — extracted, not rebuilt."""
    graph_id: str
    node_count: int = Field(default=0)
    edge_count: int = Field(default=0)
    technique_count: int = Field(default=0)
    tactic_count: int = Field(default=0)
    alert_count: int = Field(default=0)
    entity_count: int = Field(default=0)
    is_dag: bool = Field(default=True)
    tactic_distribution: dict[str, int] = Field(default_factory=dict)
    technique_distribution: dict[str, int] = Field(default_factory=dict)


class ChainSummary(CyberShieldBaseModel):
    """Attack chain output — ordered technique/tactic sequence."""
    chain_id: str
    chain_length: int
    confidence: float
    tactic_sequence: list[str] = Field(default_factory=list)
    technique_sequence: list[str] = Field(default_factory=list)
    tactic_count: int = Field(default=0)
    is_multi_tactic: bool = Field(default=False)
    is_temporally_ordered: bool = Field(default=False)
    observation_strength: float = Field(default=0.0)
    matched_alert_ids: list[str] = Field(default_factory=list)
    matched_features: list[str] = Field(default_factory=list)
    total_observations: int = Field(default=0)
    first_event_time: datetime | None = Field(default=None)
    last_event_time: datetime | None = Field(default=None)
    duration_seconds: float = Field(default=0.0)


class TimelineEvent(CyberShieldBaseModel):
    """One deterministic step in the attack timeline."""
    step_index: int
    timestamp: datetime
    technique_id: str
    tactic_name: str
    action: str
    host: str
    user: str
    source: str
    result: str
    confidence: float
    observation_count: int


class SupportingEvidence(CyberShieldBaseModel):
    """Evidence extracted from existing CanonicalEvents — never synthesised."""
    affected_hosts: list[str] = Field(default_factory=list)
    affected_users: list[str] = Field(default_factory=list)
    processes: list[str] = Field(default_factory=list)
    command_lines: list[str] = Field(default_factory=list)
    src_ips: list[str] = Field(default_factory=list)
    dst_ips: list[str] = Field(default_factory=list)
    ports: list[int] = Field(default_factory=list)
    protocols: list[str] = Field(default_factory=list)
    logon_types: list[str] = Field(default_factory=list)
    auth_packages: list[str] = Field(default_factory=list)
    file_paths: list[str] = Field(default_factory=list)
    # OT/ICS
    modbus_registers: list[int] = Field(default_factory=list)
    modbus_values: list[int] = Field(default_factory=list)
    supervisory_hosts: list[str] = Field(default_factory=list)
    has_ot_indicators: bool = Field(default=False)
    has_auth_indicators: bool = Field(default=False)
    has_network_indicators: bool = Field(default=False)
    has_process_indicators: bool = Field(default=False)


class NoveltyItem(CyberShieldBaseModel):
    """One novel observation vs baseline."""
    feature_name: str
    observed_value: float
    baseline_mean: float
    deviation_magnitude: float


class BehavioralSummary(CyberShieldBaseModel):
    """Behavioral novelty from Feature Engine — never recomputed."""
    entity_key: str
    baseline_available: bool = Field(default=False)
    novel_features: list[str] = Field(default_factory=list)
    novelty_count: int = Field(default=0)
    feature_dimension: int = Field(default=0)
    raw_feature_snapshot: dict[str, float] = Field(default_factory=dict)


class StatisticalSummary(CyberShieldBaseModel):
    """Metrics Engine output — reused, never recalculated."""
    anomaly_score: float
    feature_count: int = Field(default=0)
    baseline_coverage: float = Field(default=0.0)
    entity_observations: int = Field(default=0)


class MissingComponent(CyberShieldBaseModel):
    """One item absent from the context package."""
    component: str
    reason: str


class ContextCompleteness(CyberShieldBaseModel):
    """
    Deterministic completeness metadata.
    Reports exactly what is present and what is missing.
    Never infers, guesses, or predicts.
    """
    completeness_pct: float = Field(default=0.0, ge=0.0, le=100.0)
    has_detection: bool = Field(default=False)
    has_shap: bool = Field(default=False)
    has_mitre: bool = Field(default=False)
    has_graph: bool = Field(default=False)
    has_chain: bool = Field(default=False)
    has_timeline: bool = Field(default=False)
    has_evidence: bool = Field(default=False)
    has_behavioral: bool = Field(default=False)
    has_statistical: bool = Field(default=False)
    missing: list[MissingComponent] = Field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# Root context object
# ─────────────────────────────────────────────────────────────────────────────

class AttackContext(CyberShieldBaseModel):
    """
    Immutable intelligence package assembled for Phase 5 LLM Reasoning Agent.

    Every field is populated deterministically from existing module outputs.
    Nothing is inferred, predicted, or generated here.
    """

    model_config = ConfigDict(protected_namespaces=())

    context_id: str = Field(default_factory=lambda: f"ctx-{generate_id()}")
    schema_version: str = Field(default=CONTEXT_SCHEMA_VERSION)
    assembled_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    # Identity
    identity: ContextIdentity

    # Detection layer
    detection: DetectionSummary

    # Explainability layer
    shap: ShapSummary = Field(default_factory=ShapSummary)

    # MITRE layer
    mitre: MitreSummary = Field(default_factory=MitreSummary)

    # Graph layer
    graph: GraphSummary | None = Field(default=None)

    # Chain layer
    chain: ChainSummary | None = Field(default=None)

    # Timeline
    timeline: list[TimelineEvent] = Field(default_factory=list)

    # Evidence
    evidence: SupportingEvidence = Field(default_factory=SupportingEvidence)

    # Behavioral
    behavioral: BehavioralSummary | None = Field(default=None)

    # Statistical
    statistical: StatisticalSummary | None = Field(default=None)

    # Completeness
    completeness: ContextCompleteness = Field(default_factory=ContextCompleteness)

    # Passthrough metadata
    extra: dict[str, Any] = Field(default_factory=dict)

    def to_summary(self) -> dict[str, Any]:
        return {
            "context_id": self.context_id,
            "alert_id": self.identity.alert_id,
            "entity_id": self.identity.entity_id,
            "anomaly_score": self.detection.anomaly_score,
            "chain_confidence": self.chain.confidence if self.chain else None,
            "completeness_pct": self.completeness.completeness_pct,
            "technique_count": self.mitre.technique_count,
            "timeline_steps": len(self.timeline),
            "assembled_at": self.assembled_at.isoformat(),
        }
