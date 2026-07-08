"""
tests/unit/detection/test_service.py — DetectionService Tests
=============================================================
Integration-style unit tests for the complete detection service.
Uses temp directories for filesystem isolation; no real model files on disk.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from backend.core.config import Settings
from backend.detection.exceptions import ModelNotTrainedError
from backend.detection.models import DetectionAlert, DetectionResult, TrainingResult
from backend.detection.service import DetectionService
from tests.unit.detection.conftest import (
    make_feature_record,
    make_normal_records,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def detection_settings(tmp_path: Path) -> Settings:
    """Settings pointing to temp directories."""
    return Settings(
        app_env="development",
        log_level="DEBUG",
        log_format="console",
        secret_key="test-secret-key-do-not-use",
        api_key="test-api-key",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'test.db'}",
        data_dir=tmp_path / "data",
        models_dir=tmp_path / "models",
        reports_dir=tmp_path / "reports",
        isolation_forest_contamination=0.05,
        isolation_forest_n_estimators=10,
        isolation_forest_random_state=42,
        anomaly_score_threshold=0.5,
    )


@pytest.fixture()
def service(detection_settings: Settings, tmp_path: Path) -> DetectionService:
    """A DetectionService backed by temp directories, no auto-load."""
    with (
        patch("backend.detection.service.get_settings", return_value=detection_settings),
        patch("backend.detection.storage.get_settings", return_value=detection_settings),
        patch("backend.detection.trainer.get_settings", return_value=detection_settings),
        patch("backend.detection.scorer.get_settings", return_value=detection_settings),
    ):
        svc = DetectionService(
            features_dir=tmp_path / "data" / "features",
            models_dir=tmp_path / "models",
            threshold=0.5,
            entity_dim="user_host",
            auto_load=False,
        )
    return svc


@pytest.fixture()
def trained_service(service: DetectionService) -> DetectionService:
    """A DetectionService that has been trained on 80 normal records."""
    records = make_normal_records(80)
    service.train_from_features(feature_records=records)
    return service


# ---------------------------------------------------------------------------
# Tests — Initialisation
# ---------------------------------------------------------------------------


class TestDetectionServiceInit:
    def test_not_loaded_on_auto_load_false(self, service: DetectionService) -> None:
        assert service.is_model_loaded is False

    def test_current_model_id_none_before_training(self, service: DetectionService) -> None:
        assert service.current_model_id is None

    def test_score_event_before_training_raises(self, service: DetectionService) -> None:
        rec = make_feature_record()
        with pytest.raises(ModelNotTrainedError):
            service.score_event(rec)

    def test_score_batch_before_training_raises(self, service: DetectionService) -> None:
        with pytest.raises(ModelNotTrainedError):
            service.score_batch_from_features(feature_records=[make_feature_record()])

    def test_stream_before_training_raises(self, service: DetectionService) -> None:
        with pytest.raises(ModelNotTrainedError):
            list(service.score_stream(iter([make_feature_record()])))


# ---------------------------------------------------------------------------
# Tests — Training
# ---------------------------------------------------------------------------


class TestDetectionServiceTraining:
    def test_train_returns_training_result(self, service: DetectionService) -> None:
        records = make_normal_records(60)
        result = service.train_from_features(feature_records=records)
        assert isinstance(result, TrainingResult)
        assert result.sample_count == 60

    def test_model_loaded_after_training(self, service: DetectionService) -> None:
        records = make_normal_records(50)
        service.train_from_features(feature_records=records)
        assert service.is_model_loaded is True

    def test_model_id_set_after_training(self, service: DetectionService) -> None:
        records = make_normal_records(50)
        result = service.train_from_features(feature_records=records)
        assert service.current_model_id == result.model_id

    def test_model_paths_set_in_result(self, service: DetectionService) -> None:
        records = make_normal_records(50)
        result = service.train_from_features(feature_records=records)
        assert result.model_path != ""
        assert result.metadata_path != ""
        assert Path(result.model_path).exists()
        assert Path(result.metadata_path).exists()

    def test_incremental_retrain_increases_model_count(
        self, service: DetectionService, tmp_path: Path
    ) -> None:
        initial = make_normal_records(50)
        service.train_from_features(feature_records=initial)

        new_records = make_normal_records(20)
        result = service.retrain_incremental(new_records, existing_records=initial)
        assert result.sample_count == 50 + 20

    def test_retrain_uses_passed_existing_records(self, service: DetectionService) -> None:
        records = make_normal_records(50)
        service.train_from_features(feature_records=records)
        new = make_normal_records(10)
        result = service.retrain_incremental(new, existing_records=records)
        assert result.sample_count == 60

    def test_get_status_after_training(self, trained_service: DetectionService) -> None:
        status = trained_service.get_status()
        assert status["model_loaded"] is True
        assert "model_id" in status
        assert "sample_count" in status

    def test_get_status_before_training(self, service: DetectionService) -> None:
        status = service.get_status()
        assert status["model_loaded"] is False
        assert "model_id" not in status


# ---------------------------------------------------------------------------
# Tests — Inference
# ---------------------------------------------------------------------------


class TestDetectionServiceInference:
    def test_score_event_returns_none_or_alert(self, trained_service: DetectionService) -> None:
        rec = make_feature_record(anomaly_hint=0.0)
        result = trained_service.score_event(rec)
        assert result is None or isinstance(result, DetectionAlert)

    def test_score_event_alert_has_model_id(self, trained_service: DetectionService) -> None:
        records = make_normal_records(50)
        for rec in records:
            alert = trained_service.score_event(rec)
            if alert is not None:
                assert alert.model_id == trained_service.current_model_id
                break

    def test_score_batch_returns_detection_result(self, trained_service: DetectionService) -> None:
        records = make_normal_records(20)
        result = trained_service.score_batch_from_features(feature_records=records)
        assert isinstance(result, DetectionResult)
        assert result.records_scored == 20
        assert result.model_id == trained_service.current_model_id

    def test_score_stream_yields_alerts(self, trained_service: DetectionService) -> None:
        records = make_normal_records(30)
        alerts = list(trained_service.score_stream(iter(records)))
        for a in alerts:
            assert isinstance(a, DetectionAlert)

    def test_reload_model_after_training(self, trained_service: DetectionService) -> None:
        original_id = trained_service.current_model_id
        meta = trained_service.reload_model()
        assert meta.model_id == original_id

    def test_list_available_models_after_two_trains(self, service: DetectionService) -> None:
        service.train_from_features(feature_records=make_normal_records(40))
        service.train_from_features(feature_records=make_normal_records(40))
        models = service.list_available_models()
        assert len(models) == 2


# ---------------------------------------------------------------------------
# Tests — JSONL loading
# ---------------------------------------------------------------------------


class TestDetectionServiceFeatureLoading:
    def test_load_from_jsonl_files(self, service: DetectionService, tmp_path: Path) -> None:
        features_dir = tmp_path / "data" / "features"
        features_dir.mkdir(parents=True, exist_ok=True)

        # Write 50 feature records to a JSONL file
        records = make_normal_records(50)
        jsonl_path = features_dir / "features_test.jsonl"
        with jsonl_path.open("w", encoding="utf-8") as fh:
            for rec in records:
                fh.write(rec.model_dump_json() + "\n")

        # Point service at this directory
        service._features_dir = features_dir
        loaded = service._load_all_feature_records()
        assert len(loaded) == 50

    def test_missing_features_dir_returns_empty(
        self, service: DetectionService, tmp_path: Path
    ) -> None:
        service._features_dir = tmp_path / "nonexistent"
        loaded = service._load_all_feature_records()
        assert loaded == []

    def test_corrupt_jsonl_line_skipped(self, service: DetectionService, tmp_path: Path) -> None:
        features_dir = tmp_path / "data" / "features"
        features_dir.mkdir(parents=True, exist_ok=True)

        records = make_normal_records(10)
        jsonl_path = features_dir / "features_mixed.jsonl"
        with jsonl_path.open("w", encoding="utf-8") as fh:
            for rec in records:
                fh.write(rec.model_dump_json() + "\n")
            fh.write("{not valid json\n")  # corrupt line

        service._features_dir = features_dir
        loaded = service._load_all_feature_records()
        assert len(loaded) == 10  # corrupt line skipped
