"""
tests/unit/detection/test_trainer.py — IsolationForestTrainer Tests
====================================================================
"""

from __future__ import annotations

from pathlib import Path

import pytest

from backend.detection.models import ModelMetadata, TrainingResult
from backend.detection.trainer import IsolationForestTrainer, _DetectionPipeline
from backend.features.models import FEATURE_DIMENSION

from tests.unit.detection.conftest import make_normal_records, make_anomalous_record


class TestIsolationForestTrainer:
    def test_train_returns_triple(self) -> None:
        trainer = IsolationForestTrainer(
            contamination=0.05,
            n_estimators=10,
            random_state=42,
        )
        records = make_normal_records(50)
        pipeline, metadata, result = trainer.train(records)
        assert isinstance(pipeline, _DetectionPipeline)
        assert isinstance(metadata, ModelMetadata)
        assert isinstance(result, TrainingResult)

    def test_metadata_feature_dimension_correct(self) -> None:
        trainer = IsolationForestTrainer(n_estimators=10, random_state=42)
        records = make_normal_records(40)
        _, metadata, _ = trainer.train(records)
        assert metadata.feature_dimension == FEATURE_DIMENSION
        assert len(metadata.feature_names) == FEATURE_DIMENSION

    def test_training_result_sample_count(self) -> None:
        trainer = IsolationForestTrainer(n_estimators=10, random_state=42)
        records = make_normal_records(60)
        _, _, result = trainer.train(records)
        assert result.sample_count == 60

    def test_custom_model_id(self) -> None:
        trainer = IsolationForestTrainer(n_estimators=10, random_state=42)
        records = make_normal_records(30)
        _, metadata, result = trainer.train(records, model_id="custom-id-001")
        assert metadata.model_id == "custom-id-001"
        assert result.model_id == "custom-id-001"

    def test_entity_dim_filter(self) -> None:
        trainer = IsolationForestTrainer(
            n_estimators=10, random_state=42, entity_dim="user_host"
        )
        uh = make_normal_records(30, entity_type="user_host")
        user = make_normal_records(20, entity_type="user")
        _, _, result = trainer.train(uh + user)
        assert result.sample_count == 30  # only user_host filtered

    def test_empty_entity_dim_raises(self) -> None:
        trainer = IsolationForestTrainer(n_estimators=10, random_state=42)
        records = make_normal_records(20, entity_type="user")  # no user_host
        with pytest.raises(ValueError, match="No FeatureRecord"):
            trainer.train(records)

    def test_reproducibility(self) -> None:
        """Two trainers with same seed produce same decision_function output."""
        records = make_normal_records(60)
        anomaly = make_anomalous_record()

        trainer_a = IsolationForestTrainer(
            n_estimators=20, contamination=0.05, random_state=99
        )
        trainer_b = IsolationForestTrainer(
            n_estimators=20, contamination=0.05, random_state=99
        )

        pipeline_a, _, _ = trainer_a.train(records)
        pipeline_b, _, _ = trainer_b.train(records)

        X_a = pipeline_a.preprocessor.transform_single(anomaly)
        X_b = pipeline_b.preprocessor.transform_single(anomaly)

        score_a = pipeline_a.isolation_forest.decision_function(X_a)[0]
        score_b = pipeline_b.isolation_forest.decision_function(X_b)[0]

        assert abs(score_a - score_b) < 1e-10

    def test_pipeline_preprocessor_is_fitted(self) -> None:
        trainer = IsolationForestTrainer(n_estimators=10, random_state=42)
        records = make_normal_records(40)
        pipeline, _, _ = trainer.train(records)
        assert pipeline.preprocessor.is_fitted is True

    def test_n_estimators_passed_to_if(self) -> None:
        trainer = IsolationForestTrainer(n_estimators=7, random_state=42)
        records = make_normal_records(40)
        pipeline, _, _ = trainer.train(records)
        assert pipeline.isolation_forest.n_estimators == 7

    def test_training_duration_positive(self) -> None:
        trainer = IsolationForestTrainer(n_estimators=10, random_state=42)
        records = make_normal_records(40)
        _, _, result = trainer.train(records)
        assert result.training_duration_seconds >= 0.0

    def test_retrain_combines_records(self) -> None:
        trainer = IsolationForestTrainer(n_estimators=10, random_state=42)
        existing = make_normal_records(40)
        new = make_normal_records(20)
        _, _, result = trainer.retrain(existing, new)
        assert result.sample_count == 60

    def test_notes_stored_in_metadata(self) -> None:
        trainer = IsolationForestTrainer(n_estimators=10, random_state=42)
        records = make_normal_records(30)
        _, metadata, _ = trainer.train(records, notes="initial training")
        assert metadata.notes == "initial training"

    def test_entity_count_in_result(self) -> None:
        trainer = IsolationForestTrainer(n_estimators=10, random_state=42)
        # 10 unique entity IDs
        records = [
            make_normal_records(5, entity_type="user_host")[i % 5]
            for i in range(10)
        ]
        # override entity_ids manually
        from tests.unit.detection.conftest import make_feature_record
        records_unique = [
            make_feature_record(entity_id=f"u{i}::h{i}")
            for i in range(10)
        ]
        _, _, result = trainer.train(records_unique)
        assert result.entity_count == 10
