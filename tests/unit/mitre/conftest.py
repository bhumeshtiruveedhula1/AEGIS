"""tests/unit/mitre/conftest.py — Shared MITRE test fixtures."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from backend.baseline.models import EntityKey
from backend.detection.models import DetectionAlert
from backend.explainability.models import (
    ExplanationResult,
    FeatureContribution,
)
from backend.features.models import ALL_FEATURE_NAMES, FEATURE_DIMENSION
from backend.mitre.knowledge_base import MitreKnowledgeBase
from backend.mitre.mapper import MitreMapper

MODEL_ID = "iforest-test-001"
ENTITY_KEY = EntityKey(entity_type="user_host", entity_id="alice::workstation-01")


def make_alert(
    alert_id: str = "alert-001",
    model_id: str = MODEL_ID,
    anomaly_score: float = 0.82,
    raw_feature_values: dict | None = None,
) -> DetectionAlert:
    if raw_feature_values is None:
        # Populate with values that trigger auth/process features
        raw_feature_values = {
            "auth_failure_rate_baseline": 1.0,
            "result_failure_rate_baseline": 1.0,
            "logon_type_is_novel": 1.0,
            "process_is_novel": 1.0,
        }
    return DetectionAlert(
        alert_id=alert_id,
        model_id=model_id,
        entity_key=ENTITY_KEY,
        event_id=f"evt-{alert_id}",
        event_type="AuthFailure",
        event_source="dc01",
        event_timestamp=datetime(2024, 6, 10, 23, 0, tzinfo=UTC),
        event_host="workstation-01",
        event_user="alice",
        anomaly_score=anomaly_score,
        raw_if_score=-0.7,
        threshold_used=0.5,
        feature_dimension=FEATURE_DIMENSION,
        raw_feature_values=raw_feature_values,
        novelty_count=3,
        baseline_available=True,
    )


def make_explanation(
    alert_id: str = "alert-001",
    model_id: str = MODEL_ID,
    top_features: list[str] | None = None,
) -> ExplanationResult:
    if top_features is None:
        top_features = [
            "auth_failure_rate_baseline",
            "result_failure_rate_baseline",
            "logon_type_is_novel",
            "process_is_novel",
            "dst_ip_is_novel",
        ]
    # Build minimal contributions for top features
    all_names = list(ALL_FEATURE_NAMES)
    contribs = []
    for i, name in enumerate(all_names):
        abs_val = 0.3 - i * 0.004 if name in top_features else 0.001
        abs_val = max(abs_val, 0.0)
        shap_val = abs_val if name in top_features else -abs_val
        contribs.append(
            FeatureContribution(
                feature_name=name,
                raw_value=1.0 if name in top_features else 0.0,
                shap_value=shap_val,
                abs_shap_value=abs_val,
                contribution_rank=i + 1,
                contribution_pct=round(abs_val / 2.0 * 100, 4),
                direction="anomaly" if shap_val > 0 else "normal",
            )
        )

    return ExplanationResult(
        explanation_id=f"expl-{alert_id}",
        alert_id=alert_id,
        model_id=model_id,
        entity_type=ENTITY_KEY.entity_type,
        entity_id=ENTITY_KEY.entity_id,
        event_id=f"evt-{alert_id}",
        anomaly_score=0.82,
        expected_value=-0.05,
        total_abs_shap=1.5,
        feature_contributions=contribs,
        top_features=top_features,
    )


@pytest.fixture()
def kb() -> MitreKnowledgeBase:
    return MitreKnowledgeBase()


@pytest.fixture()
def mapper() -> MitreMapper:
    return MitreMapper(min_confidence=0.10)


@pytest.fixture()
def sample_alert() -> DetectionAlert:
    return make_alert()


@pytest.fixture()
def sample_explanation() -> ExplanationResult:
    return make_explanation()
