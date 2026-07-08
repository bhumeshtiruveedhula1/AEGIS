"""
backend.explainability.models — Explainability Data Models
==========================================================
Module 3.2 — SHAP Explainability Layer

Pydantic models for structured SHAP explanation output.

Model Hierarchy
---------------
FeatureContribution       — one feature's SHAP contribution to a single alert
ExplanationResult         — SHAP explanation for one DetectionAlert
ExplainabilityReport      — aggregate over a DetectionResult (batch)

Design Principles
-----------------
- All SHAP values are stored raw (float) AND as a normalised rank [0, 1]
  so that downstream consumers (MITRE mapper, dashboard) can use
  whichever representation suits them without re-computing.
- feature_contributions is ordered by |shap_value| descending so the
  most important feature is always at index 0.
- ExplanationResult embeds the full alert_id + model_id from DetectionAlert
  so it can be correlated without re-loading the original alert.
- raw_feature_values mirrors DetectionAlert.raw_feature_values — copied
  at explanation time to ensure the explanation is self-contained.
"""

from __future__ import annotations

import math
from datetime import UTC, datetime
from typing import Any

from pydantic import ConfigDict, Field, field_validator, model_validator

from backend.shared.models import CyberShieldBaseModel
from backend.shared.utils.id_utils import generate_id

# ---------------------------------------------------------------------------
# Schema version — bump when adding/removing fields
# ---------------------------------------------------------------------------
EXPLAINABILITY_SCHEMA_VERSION = "1.0.0"


# ---------------------------------------------------------------------------
# FeatureContribution
# ---------------------------------------------------------------------------

class FeatureContribution(CyberShieldBaseModel):
    """
    SHAP contribution of one feature to a single anomaly score.

    Fields
    ------
    feature_name    : Canonical name from ALL_FEATURE_NAMES.
    raw_value       : Actual value of the feature for this event.
    shap_value      : Raw SHAP value (positive = pushes toward anomaly).
    abs_shap_value  : |shap_value| for sorting/ranking.
    contribution_rank : 1-based rank by |shap_value| (1 = most important).
    contribution_pct  : Percentage of total |SHAP| sum this feature accounts for.
    direction       : "anomaly" if shap_value > 0 else "normal".
    """

    model_config = ConfigDict(
        protected_namespaces=(),
        populate_by_name=True,
    )

    feature_name: str = Field(..., description="Canonical feature name")
    raw_value: float = Field(..., description="Actual feature value for this event")
    shap_value: float = Field(..., description="SHAP value (signed contribution)")
    abs_shap_value: float = Field(..., ge=0.0, description="|SHAP value|")
    contribution_rank: int = Field(..., ge=1, description="1-based importance rank")
    contribution_pct: float = Field(
        ..., ge=0.0, le=100.0, description="Percentage of total |SHAP| sum"
    )
    direction: str = Field(
        ..., pattern="^(anomaly|normal)$", description="'anomaly' or 'normal'"
    )

    @classmethod
    def build(
        cls,
        feature_name: str,
        raw_value: float,
        shap_value: float,
        rank: int,
        total_abs_shap: float,
    ) -> "FeatureContribution":
        """
        Factory method that computes derived fields from raw SHAP value.

        Parameters
        ----------
        feature_name   : Canonical feature name.
        raw_value      : Actual value of the feature at scoring time.
        shap_value     : Raw SHAP output (float, signed).
        rank           : 1-based rank by |shap_value| within this explanation.
        total_abs_shap : Sum of |shap_value| for all features (for pct calc).
        """
        abs_val = abs(shap_value) if math.isfinite(shap_value) else 0.0
        pct = (abs_val / total_abs_shap * 100.0) if total_abs_shap > 0 else 0.0
        return cls(
            feature_name=feature_name,
            raw_value=raw_value if math.isfinite(raw_value) else 0.0,
            shap_value=shap_value if math.isfinite(shap_value) else 0.0,
            abs_shap_value=round(abs_val, 8),
            contribution_rank=rank,
            contribution_pct=round(min(pct, 100.0), 4),
            direction="anomaly" if shap_value > 0 else "normal",
        )


# ---------------------------------------------------------------------------
# ExplanationResult — SHAP explanation for one DetectionAlert
# ---------------------------------------------------------------------------

class ExplanationResult(CyberShieldBaseModel):
    """
    SHAP explanation for a single anomalous event.

    Produced by SHAPExplainer.explain_alert().
    Consumed by ExplainabilityReport, MITRE mapper, and dashboard.

    Fields
    ------
    explanation_id       : Unique explanation identifier ("expl-<uuid>")
    alert_id             : DetectionAlert.alert_id this explains
    model_id             : Model version that produced the original alert
    entity_type          : EntityKey.entity_type
    entity_id            : EntityKey.entity_id
    event_id             : Originating event_id
    anomaly_score        : Copied from DetectionAlert for self-containedness
    expected_value       : SHAP expected_value (base rate for this model)
    total_abs_shap       : Sum of |SHAP values| across all features
    explained_at         : UTC timestamp of explanation generation
    feature_contributions: Ordered list (rank 1 = most important)
    top_features         : Top N feature names by |SHAP| (default N=5)
    raw_feature_values   : Full feature snapshot copied from DetectionAlert
    schema_version       : Explainability schema version
    explainer_type       : Always "TreeSHAP" for Isolation Forest
    """

    model_config = ConfigDict(
        protected_namespaces=(),
        populate_by_name=True,
    )

    explanation_id: str = Field(
        default_factory=lambda: f"expl-{generate_id()}",
        description="Unique explanation identifier",
    )
    alert_id: str = Field(..., description="ID of the explained DetectionAlert")
    model_id: str = Field(..., description="Model version that produced the alert")
    entity_type: str = Field(..., description="Entity dimension (e.g. user_host)")
    entity_id: str = Field(..., description="Entity identifier")
    event_id: str = Field(..., description="Originating event ID")
    anomaly_score: float = Field(..., ge=0.0, le=1.0, description="Original anomaly score")
    expected_value: float = Field(..., description="SHAP base rate / expected value")
    total_abs_shap: float = Field(..., ge=0.0, description="Sum of |SHAP values|")
    explained_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp of explanation generation",
    )
    feature_contributions: list[FeatureContribution] = Field(
        default_factory=list,
        description="All feature contributions, ordered by |SHAP| descending",
    )
    top_features: list[str] = Field(
        default_factory=list,
        description="Top N feature names by absolute SHAP contribution",
    )
    raw_feature_values: dict[str, float] = Field(
        default_factory=dict,
        description="Full feature snapshot at scoring time",
    )
    schema_version: str = Field(
        default=EXPLAINABILITY_SCHEMA_VERSION,
        description="Schema version for forward compatibility",
    )
    explainer_type: str = Field(
        default="TreeSHAP",
        description="SHAP explainer algorithm used",
    )

    @field_validator("feature_contributions")
    @classmethod
    def validate_contributions_ordered(
        cls, v: list[FeatureContribution]
    ) -> list[FeatureContribution]:
        """Ensure contributions are sorted by rank ascending (rank 1 first)."""
        return sorted(v, key=lambda c: c.contribution_rank)

    def top_n_contributions(self, n: int = 5) -> list[FeatureContribution]:
        """Return the top N FeatureContribution objects by importance rank."""
        return self.feature_contributions[:n]

    def to_summary(self) -> dict[str, Any]:
        """Compact dict for logging and downstream consumers."""
        return {
            "explanation_id": self.explanation_id,
            "alert_id": self.alert_id,
            "model_id": self.model_id,
            "entity_id": self.entity_id,
            "anomaly_score": self.anomaly_score,
            "top_features": self.top_features,
            "expected_value": self.expected_value,
            "total_abs_shap": round(self.total_abs_shap, 6),
            "explained_at": self.explained_at.isoformat(),
        }


# ---------------------------------------------------------------------------
# ExplainabilityReport — aggregate for one DetectionResult (batch)
# ---------------------------------------------------------------------------

class ExplainabilityReport(CyberShieldBaseModel):
    """
    Aggregate explanation for an entire DetectionResult batch.

    Produced by ExplainabilityService.explain_detection_result().
    Provides batch-level analytics over individual ExplanationResults.

    Fields
    ------
    report_id            : Unique report identifier ("rpt-<uuid>")
    run_id               : DetectionResult.run_id this report covers
    model_id             : Model version used
    generated_at         : UTC timestamp
    alerts_explained     : Total alerts explained in this batch
    explanations         : All ExplanationResult objects
    top_global_features  : Features most frequently in top-5 across all alerts
    avg_total_abs_shap   : Mean total_abs_shap across all explanations
    schema_version       : Explainability schema version
    """

    model_config = ConfigDict(
        protected_namespaces=(),
        populate_by_name=True,
    )

    report_id: str = Field(
        default_factory=lambda: f"rpt-{generate_id()}",
        description="Unique report identifier",
    )
    run_id: str = Field(..., description="DetectionResult.run_id this covers")
    model_id: str = Field(..., description="Model version used")
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC generation timestamp",
    )
    alerts_explained: int = Field(default=0, ge=0)
    explanations: list[ExplanationResult] = Field(default_factory=list)
    top_global_features: list[str] = Field(
        default_factory=list,
        description="Features most frequently appearing in top-5 across all alerts",
    )
    avg_total_abs_shap: float = Field(
        default=0.0,
        ge=0.0,
        description="Mean total_abs_shap across all explanations",
    )
    schema_version: str = Field(default=EXPLAINABILITY_SCHEMA_VERSION)
    errors: int = Field(default=0, ge=0, description="Alerts that failed explanation")

    @model_validator(mode="after")
    def compute_aggregates(self) -> "ExplainabilityReport":
        """
        Auto-compute top_global_features and avg_total_abs_shap
        from the explanations list when set.
        """
        if not self.explanations:
            return self
        # avg_total_abs_shap
        self.avg_total_abs_shap = round(
            sum(e.total_abs_shap for e in self.explanations) / len(self.explanations),
            6,
        )
        # top_global_features: rank by frequency in top-5 of each explanation
        from collections import Counter
        counter: Counter[str] = Counter()
        for expl in self.explanations:
            for feat in expl.top_features[:5]:
                counter[feat] += 1
        # Return sorted by frequency descending, top 10
        self.top_global_features = [f for f, _ in counter.most_common(10)]
        self.alerts_explained = len(self.explanations)
        return self

    def to_summary(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "run_id": self.run_id,
            "model_id": self.model_id,
            "alerts_explained": self.alerts_explained,
            "errors": self.errors,
            "top_global_features": self.top_global_features[:5],
            "avg_total_abs_shap": self.avg_total_abs_shap,
            "generated_at": self.generated_at.isoformat(),
        }
