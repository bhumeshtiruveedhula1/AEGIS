"""
tests/unit/explainability/conftest.py — Shared Explainability Fixtures
=======================================================================
Builds minimal trained _DetectionPipeline and SHAPExplainer for use
across all explainability test modules.

Note on test isolation: SHAPExplainer initialization is expensive
(builds TreeExplainer from IsolationForest). We scope it to 'module'
to run once per test file, not once per test function.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from backend.baseline.models import EntityKey
from backend.detection.models import DetectionAlert
from backend.detection.preprocessor import FeaturePreprocessor
from backend.detection.trainer import IsolationForestTrainer, _DetectionPipeline
from backend.explainability.explainer import SHAPExplainer
from backend.features.models import ALL_FEATURE_NAMES, FEATURE_DIMENSION, FeatureRecord, FeatureVector

# ---------------------------------------------------------------------------
# FeatureRecord factory (matches detection conftest pattern)
# ---------------------------------------------------------------------------

def make_feature_record(
    entity_type: str = "user_host",
    entity_id: str = "alice::workstation-01",
    event_id: str | None = None,
    anomaly_hint: float = 0.0,
) -> FeatureRecord:
    import uuid
    eid = event_id or str(uuid.uuid4())
    entity_key = EntityKey(entity_type=entity_type, entity_id=entity_id)
    values = {name: min(anomaly_hint, 1.0) for name in ALL_FEATURE_NAMES}
    fv = FeatureVector(entity_key=entity_key, values=values)
    return FeatureRecord(
        event_id=eid,
        event_type="ProcessCreate",
        event_source="domain_controller",
        event_timestamp=datetime(2024, 1, 15, 10, 30, tzinfo=UTC),
        event_host="workstation-01",
        event_user="alice",
        entity_key=entity_key,
        baseline_available=True,
        feature_vector=fv,
    )


def make_normal_records(n: int = 80, entity_type: str = "user_host") -> list[FeatureRecord]:
    return [
        make_feature_record(
            entity_type=entity_type,
            entity_id=f"user_{i}::host_{i % 5}",
            anomaly_hint=0.0,
        )
        for i in range(n)
    ]


def make_alert(
    record: FeatureRecord,
    model_id: str,
    anomaly_score: float = 0.75,
) -> DetectionAlert:
    return DetectionAlert(
        model_id=model_id,
        entity_key=record.entity_key,
        event_id=record.event_id,
        event_type=record.event_type,
        event_source=record.event_source,
        event_timestamp=record.event_timestamp,
        event_host=record.event_host,
        event_user=record.event_user,
        anomaly_score=anomaly_score,
        raw_if_score=-0.6,
        threshold_used=0.5,
        feature_dimension=FEATURE_DIMENSION,
        raw_feature_values=dict(record.feature_vector.values),
        novelty_count=2,
        baseline_available=True,
    )


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def trained_pipeline_and_id() -> tuple[_DetectionPipeline, str]:
    """Build one real pipeline for all tests in this module. Scope=module for speed."""
    records = make_normal_records(80)
    trainer = IsolationForestTrainer(
        n_estimators=10, contamination=0.05, random_state=42
    )
    pipeline, metadata, _ = trainer.train(records)
    return pipeline, metadata.model_id


@pytest.fixture(scope="module")
def shap_explainer(trained_pipeline_and_id: tuple) -> SHAPExplainer:
    pipeline, model_id = trained_pipeline_and_id
    return SHAPExplainer(pipeline=pipeline, model_id=model_id, top_n=5)


@pytest.fixture()
def normal_record() -> FeatureRecord:
    return make_feature_record(anomaly_hint=0.0)


@pytest.fixture()
def anomalous_record() -> FeatureRecord:
    return make_feature_record(
        entity_id="attacker::evil-host", anomaly_hint=1.0
    )


@pytest.fixture()
def sample_alert(
    normal_record: FeatureRecord,
    trained_pipeline_and_id: tuple,
) -> DetectionAlert:
    _, model_id = trained_pipeline_and_id
    return make_alert(normal_record, model_id=model_id)
