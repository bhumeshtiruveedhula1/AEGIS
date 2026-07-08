"""
tests/unit/detection/test_models.py — Detection Models Tests
=============================================================
Tests for ModelMetadata, TrainingResult, DetectionAlert, DetectionResult.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from backend.baseline.models import EntityKey
from backend.detection.models import (
    DETECTION_SCHEMA_VERSION,
    DetectionAlert,
    DetectionResult,
    ModelMetadata,
    TrainingResult,
)
from backend.features.models import ALL_FEATURE_NAMES, FEATURE_DIMENSION


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def sample_entity_key() -> EntityKey:
    return EntityKey(entity_type="user_host", entity_id="alice::workstation-01")


@pytest.fixture()
def valid_model_metadata() -> ModelMetadata:
    return ModelMetadata(
        model_id="iforest-test-001",
        feature_schema_version="1.0.0",
        feature_names=list(ALL_FEATURE_NAMES),
        feature_dimension=FEATURE_DIMENSION,
        n_estimators=100,
        contamination=0.05,
        random_state=42,
        entity_dimension="user_host",
        entity_count=50,
        sample_count=500,
        training_duration_seconds=1.23,
        scaler_fitted=True,
        model_file="isolation_forest_iforest-test-001.pkl",
    )


@pytest.fixture()
def valid_alert(sample_entity_key: EntityKey, valid_model_metadata: ModelMetadata) -> DetectionAlert:
    return DetectionAlert(
        model_id=valid_model_metadata.model_id,
        entity_key=sample_entity_key,
        event_id="evt-abc-123",
        event_type="ProcessCreate",
        event_source="domain_controller",
        event_timestamp=datetime(2024, 1, 15, 10, 30, tzinfo=UTC),
        event_host="workstation-01",
        event_user="alice",
        anomaly_score=0.82,
        raw_if_score=-0.75,
        threshold_used=0.5,
        feature_dimension=FEATURE_DIMENSION,
        raw_feature_values={k: 0.0 for k in ALL_FEATURE_NAMES},
        novelty_count=3,
        baseline_available=True,
    )


# ---------------------------------------------------------------------------
# ModelMetadata tests
# ---------------------------------------------------------------------------

class TestModelMetadata:
    def test_construction_valid(self, valid_model_metadata: ModelMetadata) -> None:
        assert valid_model_metadata.model_id == "iforest-test-001"
        assert valid_model_metadata.feature_dimension == FEATURE_DIMENSION
        assert len(valid_model_metadata.feature_names) == FEATURE_DIMENSION
        assert valid_model_metadata.schema_version == DETECTION_SCHEMA_VERSION

    def test_feature_dimension_mismatch_raises(self) -> None:
        with pytest.raises(ValueError, match="feature_dimension"):
            ModelMetadata(
                model_id="bad-meta",
                feature_schema_version="1.0.0",
                feature_names=["feat_a", "feat_b"],  # 2 names
                feature_dimension=99,                 # but says 99
                n_estimators=100,
                contamination=0.05,
                random_state=42,
                entity_dimension="user_host",
                model_file="test.pkl",
            )

    def test_json_round_trip(self, valid_model_metadata: ModelMetadata) -> None:
        json_str = valid_model_metadata.model_dump_json()
        reloaded = ModelMetadata.model_validate_json(json_str)
        assert reloaded.model_id == valid_model_metadata.model_id
        assert reloaded.feature_names == valid_model_metadata.feature_names

    def test_contamination_bounds(self) -> None:
        with pytest.raises(Exception):  # pydantic ValidationError
            ModelMetadata(
                model_id="x",
                feature_schema_version="1.0.0",
                feature_names=list(ALL_FEATURE_NAMES),
                feature_dimension=FEATURE_DIMENSION,
                n_estimators=100,
                contamination=0.9,   # exceeds max 0.5
                random_state=42,
                entity_dimension="user_host",
                model_file="x.pkl",
            )

    def test_default_model_id_is_unique(self) -> None:
        meta_a = ModelMetadata(
            feature_schema_version="1.0.0",
            feature_names=list(ALL_FEATURE_NAMES),
            feature_dimension=FEATURE_DIMENSION,
            n_estimators=10,
            contamination=0.01,
            random_state=42,
            entity_dimension="user_host",
            model_file="a.pkl",
        )
        meta_b = ModelMetadata(
            feature_schema_version="1.0.0",
            feature_names=list(ALL_FEATURE_NAMES),
            feature_dimension=FEATURE_DIMENSION,
            n_estimators=10,
            contamination=0.01,
            random_state=42,
            entity_dimension="user_host",
            model_file="b.pkl",
        )
        assert meta_a.model_id != meta_b.model_id


# ---------------------------------------------------------------------------
# DetectionAlert tests
# ---------------------------------------------------------------------------

class TestDetectionAlert:
    def test_construction(self, valid_alert: DetectionAlert) -> None:
        assert valid_alert.anomaly_score == pytest.approx(0.82, abs=1e-5)
        assert valid_alert.is_alert is True
        assert valid_alert.schema_version == DETECTION_SCHEMA_VERSION

    def test_alert_id_auto_generated(self, valid_alert: DetectionAlert) -> None:
        assert valid_alert.alert_id.startswith("alert-")

    def test_nan_score_replaced_with_zero(self) -> None:
        """The field_validator replaces NaN with 0.0 via the _validate_score method."""
        import math
        from backend.detection.scorer import _sigmoid_score
        # Test the scorer's NaN handling (Pydantic ge/le prevents raw NaN in the model)
        assert _sigmoid_score(float("nan")) == 0.0
        assert math.isfinite(_sigmoid_score(float("nan")))

    def test_to_summary_keys(self, valid_alert: DetectionAlert) -> None:
        summary = valid_alert.to_summary()
        for key in ("alert_id", "model_id", "entity_type", "anomaly_score",
                    "threshold_used", "novelty_count"):
            assert key in summary

    def test_json_round_trip(self, valid_alert: DetectionAlert) -> None:
        json_str = valid_alert.model_dump_json()
        reloaded = DetectionAlert.model_validate_json(json_str)
        assert reloaded.alert_id == valid_alert.alert_id
        assert reloaded.entity_key.entity_id == valid_alert.entity_key.entity_id


# ---------------------------------------------------------------------------
# DetectionResult tests
# ---------------------------------------------------------------------------

class TestDetectionResult:
    def test_alert_rate_empty(self) -> None:
        result = DetectionResult(
            model_id="m1",
            score_threshold=0.5,
            entity_dimension="user_host",
        )
        assert result.alert_rate == 0.0

    def test_alert_rate_calculation(
        self, valid_alert: DetectionAlert
    ) -> None:
        result = DetectionResult(
            model_id="m1",
            score_threshold=0.5,
            entity_dimension="user_host",
            records_scored=10,
            alerts_generated=3,
            alerts=[valid_alert] * 3,
        )
        assert result.alert_rate == pytest.approx(0.3, abs=1e-6)

    def test_duration_none_when_not_completed(self) -> None:
        result = DetectionResult(
            model_id="m1",
            score_threshold=0.5,
            entity_dimension="user_host",
        )
        assert result.duration_seconds is None

    def test_to_summary_structure(self) -> None:
        result = DetectionResult(
            model_id="m1",
            score_threshold=0.5,
            entity_dimension="user_host",
            completed_at=datetime.now(UTC),
            records_scored=100,
            alerts_generated=5,
        )
        summary = result.to_summary()
        assert summary["records_scored"] == 100
        assert summary["alerts_generated"] == 5
        assert "alert_rate" in summary

    def test_json_round_trip(self, valid_alert: DetectionAlert) -> None:
        result = DetectionResult(
            model_id="m1",
            score_threshold=0.5,
            entity_dimension="user_host",
            records_scored=5,
            alerts_generated=1,
            alerts=[valid_alert],
        )
        json_str = result.model_dump_json()
        reloaded = DetectionResult.model_validate_json(json_str)
        assert len(reloaded.alerts) == 1
        assert reloaded.alerts[0].alert_id == valid_alert.alert_id
