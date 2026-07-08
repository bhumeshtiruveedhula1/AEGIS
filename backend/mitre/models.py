"""
backend.mitre.models — MITRE ATT&CK Data Models
=================================================
Module 3.3 — MITRE ATT&CK Mapper

Pure data models — no business logic.

Hierarchy
---------
AttackTactic           — one ATT&CK tactic (e.g. TA0006 Credential Access)
AttackTechnique        — one ATT&CK technique (e.g. T1110 Brute Force)
TechniqueMapping       — evidence linking one technique to one alert
MappedAttack           — complete mapping result for one alert (1..N techniques)
MappingReport          — aggregate over a batch of MappedAttacks
MappingStatistics      — summary stats for a MappingReport
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import ConfigDict, Field, model_validator

from backend.shared.models import CyberShieldBaseModel
from backend.shared.utils.id_utils import generate_id

MITRE_SCHEMA_VERSION = "1.0.0"
MITRE_KNOWLEDGE_VERSION = "ATT&CK-v15"


# ---------------------------------------------------------------------------
# AttackTactic
# ---------------------------------------------------------------------------

class AttackTactic(CyberShieldBaseModel):
    """One MITRE ATT&CK tactic."""

    model_config = ConfigDict(protected_namespaces=(), populate_by_name=True)

    tactic_id: str = Field(..., description="ATT&CK tactic ID, e.g. TA0006")
    name: str = Field(..., description="Tactic name, e.g. 'Credential Access'")
    short_name: str = Field(..., description="Slug, e.g. 'credential-access'")
    description: str = Field(default="", description="Brief tactic description")

    def __str__(self) -> str:
        return f"{self.tactic_id} {self.name}"


# ---------------------------------------------------------------------------
# AttackTechnique
# ---------------------------------------------------------------------------

class AttackTechnique(CyberShieldBaseModel):
    """One MITRE ATT&CK technique or sub-technique."""

    model_config = ConfigDict(protected_namespaces=(), populate_by_name=True)

    technique_id: str = Field(..., description="ATT&CK technique ID, e.g. T1110 or T1110.001")
    name: str = Field(..., description="Technique name, e.g. 'Brute Force'")
    tactic: AttackTactic = Field(..., description="Parent tactic")
    description: str = Field(default="", description="Brief technique description")
    is_subtechnique: bool = Field(default=False)
    url: str = Field(
        default="",
        description="ATT&CK reference URL (static, no runtime fetch)",
    )

    @model_validator(mode="after")
    def _set_subtechnique_flag(self) -> "AttackTechnique":
        self.is_subtechnique = "." in self.technique_id
        return self

    def __str__(self) -> str:
        return f"{self.technique_id} {self.name}"


# ---------------------------------------------------------------------------
# TechniqueMapping — one technique linked to one alert with evidence
# ---------------------------------------------------------------------------

class TechniqueMapping(CyberShieldBaseModel):
    """
    Evidence-backed association between an ATT&CK technique and one alert.

    Confidence scoring
    ------------------
    confidence is deterministic, computed by MitreMapper from:
      - alert.anomaly_score            (weight 0.40)
      - shap evidence strength          (weight 0.40)  — normalized top-contributor signal
      - feature_match_count / total     (weight 0.20)  — breadth of evidence
    Result: float in [0.0, 1.0] rounded to 4 d.p.
    """

    model_config = ConfigDict(protected_namespaces=(), populate_by_name=True)

    technique: AttackTechnique = Field(...)
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence [0,1]")
    evidence: list[str] = Field(
        default_factory=list,
        description="Human-readable evidence strings",
    )
    matched_features: list[str] = Field(
        default_factory=list,
        description="Feature names from ALL_FEATURE_NAMES that triggered this mapping",
    )
    shap_contributors: list[str] = Field(
        default_factory=list,
        description="Top SHAP feature names from ExplanationResult that support this mapping",
    )
    shap_total_contribution: float = Field(
        default=0.0,
        ge=0.0,
        description="Sum of |SHAP values| for matched features",
    )

    def to_summary(self) -> dict[str, Any]:
        return {
            "technique_id": self.technique.technique_id,
            "technique_name": self.technique.name,
            "tactic": self.technique.tactic.name,
            "confidence": self.confidence,
            "evidence_count": len(self.evidence),
            "matched_features": self.matched_features[:5],
            "shap_contributors": self.shap_contributors[:3],
        }


# ---------------------------------------------------------------------------
# MappedAttack — complete mapping result for one DetectionAlert
# ---------------------------------------------------------------------------

class MappedAttack(CyberShieldBaseModel):
    """
    Complete MITRE ATT&CK mapping for one DetectionAlert + ExplanationResult pair.

    Contains all candidate technique mappings sorted by confidence descending.
    The primary_technique is always the highest-confidence mapping.
    """

    model_config = ConfigDict(protected_namespaces=(), populate_by_name=True)

    mapping_id: str = Field(
        default_factory=lambda: f"map-{generate_id()}",
        description="Unique mapping identifier",
    )
    alert_id: str = Field(..., description="Source DetectionAlert.alert_id")
    explanation_id: str = Field(
        default="",
        description="Source ExplanationResult.explanation_id (empty if no explanation)",
    )
    model_id: str = Field(..., description="Detection model version")
    entity_type: str = Field(...)
    entity_id: str = Field(...)
    event_id: str = Field(...)
    anomaly_score: float = Field(..., ge=0.0, le=1.0)
    mapped_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    techniques: list[TechniqueMapping] = Field(
        default_factory=list,
        description="Candidate techniques, sorted by confidence descending",
    )
    top_shap_features: list[str] = Field(
        default_factory=list,
        description="Top SHAP feature names from ExplanationResult",
    )
    schema_version: str = Field(default=MITRE_SCHEMA_VERSION)
    knowledge_version: str = Field(default=MITRE_KNOWLEDGE_VERSION)

    @model_validator(mode="after")
    def _sort_techniques(self) -> "MappedAttack":
        self.techniques = sorted(
            self.techniques, key=lambda t: t.confidence, reverse=True
        )
        return self

    @property
    def primary_technique(self) -> TechniqueMapping | None:
        return self.techniques[0] if self.techniques else None

    @property
    def primary_tactic(self) -> str:
        t = self.primary_technique
        return t.technique.tactic.name if t else "Unknown"

    @property
    def mapped_tactics(self) -> list[str]:
        """Unique tactic names across all technique mappings."""
        seen: set[str] = set()
        result: list[str] = []
        for tm in self.techniques:
            tac = tm.technique.tactic.name
            if tac not in seen:
                seen.add(tac)
                result.append(tac)
        return result

    def to_summary(self) -> dict[str, Any]:
        pt = self.primary_technique
        return {
            "mapping_id": self.mapping_id,
            "alert_id": self.alert_id,
            "entity_id": self.entity_id,
            "anomaly_score": self.anomaly_score,
            "primary_technique": pt.technique.technique_id if pt else None,
            "primary_tactic": self.primary_tactic,
            "technique_count": len(self.techniques),
            "top_confidence": pt.confidence if pt else 0.0,
            "mapped_at": self.mapped_at.isoformat(),
        }


# ---------------------------------------------------------------------------
# MappingStatistics
# ---------------------------------------------------------------------------

class MappingStatistics(CyberShieldBaseModel):
    """Aggregate statistics for a MappingReport."""

    model_config = ConfigDict(protected_namespaces=(), populate_by_name=True)

    total_alerts: int = Field(default=0, ge=0)
    total_mapped: int = Field(default=0, ge=0)
    total_unmapped: int = Field(default=0, ge=0)
    avg_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    avg_techniques_per_alert: float = Field(default=0.0, ge=0.0)
    tactic_distribution: dict[str, int] = Field(
        default_factory=dict,
        description="Count of alerts per tactic (primary technique only)",
    )
    technique_distribution: dict[str, int] = Field(
        default_factory=dict,
        description="Count of alerts per technique ID",
    )
    mapping_rate: float = Field(default=0.0, ge=0.0, le=1.0)


# ---------------------------------------------------------------------------
# MappingReport — batch aggregate
# ---------------------------------------------------------------------------

class MappingReport(CyberShieldBaseModel):
    """Aggregate mapping result for a detection batch."""

    model_config = ConfigDict(protected_namespaces=(), populate_by_name=True)

    report_id: str = Field(
        default_factory=lambda: f"mrpt-{generate_id()}",
    )
    run_id: str = Field(..., description="DetectionResult.run_id this covers")
    model_id: str = Field(...)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    mappings: list[MappedAttack] = Field(default_factory=list)
    statistics: MappingStatistics = Field(default_factory=MappingStatistics)
    schema_version: str = Field(default=MITRE_SCHEMA_VERSION)
    errors: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def _compute_statistics(self) -> "MappingReport":
        if not self.mappings:
            self.statistics = MappingStatistics(
                total_alerts=0,
                total_mapped=0,
                total_unmapped=self.errors,
                mapping_rate=0.0,
            )
            return self

        total = len(self.mappings)
        mapped = sum(1 for m in self.mappings if m.techniques)
        unmapped = total - mapped + self.errors

        confidences = [
            m.primary_technique.confidence
            for m in self.mappings
            if m.primary_technique
        ]
        avg_conf = round(sum(confidences) / len(confidences), 4) if confidences else 0.0

        avg_tech = round(
            sum(len(m.techniques) for m in self.mappings) / total, 2
        )

        from collections import Counter
        tac_ctr: Counter[str] = Counter()
        tec_ctr: Counter[str] = Counter()
        for m in self.mappings:
            if m.primary_technique:
                tac_ctr[m.primary_tactic] += 1
                tec_ctr[m.primary_technique.technique.technique_id] += 1

        self.statistics = MappingStatistics(
            total_alerts=total,
            total_mapped=mapped,
            total_unmapped=unmapped,
            avg_confidence=avg_conf,
            avg_techniques_per_alert=avg_tech,
            tactic_distribution=dict(tac_ctr),
            technique_distribution=dict(tec_ctr),
            mapping_rate=round(mapped / total, 4) if total else 0.0,
        )
        return self

    def to_summary(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "run_id": self.run_id,
            "total_alerts": self.statistics.total_alerts,
            "total_mapped": self.statistics.total_mapped,
            "mapping_rate": self.statistics.mapping_rate,
            "avg_confidence": self.statistics.avg_confidence,
            "top_tactics": list(self.statistics.tactic_distribution.keys())[:5],
            "generated_at": self.generated_at.isoformat(),
        }
