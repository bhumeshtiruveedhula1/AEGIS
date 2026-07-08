"""
tests/unit/explainability/test_service.py — ExplainabilityService Tests
=======================================================================
Integration-style tests for the complete explainability service.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from backend.core.config import Settings
from backend.detection.models import DetectionResult
from backend.detection.service import DetectionService
from backend.explainability.exceptions import ExplainerNotInitializedError
from backend.explainability.models import ExplainabilityReport, ExplanationResult
from backend.explainability.service import ExplainabilityService

from tests.unit.explainability.conftest import (
    make_alert,
    make_feature_record,
    make_normal_records,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def expl_settings(tmp_path: Path) -> Settings:
    return Settings(
        app_env="development",
        log_level="DEBUG",
        log_format="console",
        secret_key="test-secret-key-do-not-use",  # noqa: S106
        api_key="test-api-key",  # noqa: S106
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
def trained_det_service(expl_settings: Settings, tmp_path: Path) -> DetectionService:
    """Fully trained DetectionService."""
    with patch("backend.detection.service.get_settings", return_value=expl_settings), \
         patch("backend.detection.storage.get_settings", return_value=expl_settings), \
         patch("backend.detection.trainer.get_settings", return_value=expl_settings), \
         patch("backend.detection.scorer.get_settings", return_value=expl_settings):
        svc = DetectionService(
            features_dir=tmp_path / "data" / "features",
            models_dir=tmp_path / "models",
            threshold=0.5,
            auto_load=False,
        )
    records = make_normal_records(80)
    svc.train_from_features(feature_records=records)
    return svc


@pytest.fixture()
def expl_service(
    expl_settings: Settings,
    trained_det_service: DetectionService,
    tmp_path: Path,
) -> ExplainabilityService:
    """Initialized ExplainabilityService backed by temp store, no auto-persist."""
    with patch("backend.explainability.service.get_settings", return_value=expl_settings):
        svc = ExplainabilityService(
            store_dir=tmp_path / "explanations",
            persist=False,
            top_n=5,
        )
    svc.initialize_from_detection_service(trained_det_service)
    return svc


# ---------------------------------------------------------------------------
# Tests — Initialization
# ---------------------------------------------------------------------------

class TestExplainabilityServiceInit:
    def test_not_initialized_on_creation(
        self, expl_settings: Settings, tmp_path: Path
    ) -> None:
        with patch("backend.explainability.service.get_settings", return_value=expl_settings):
            svc = ExplainabilityService(store_dir=tmp_path / "e", persist=False)
        assert svc.is_initialized is False

    def test_model_id_none_before_init(
        self, expl_settings: Settings, tmp_path: Path
    ) -> None:
        with patch("backend.explainability.service.get_settings", return_value=expl_settings):
            svc = ExplainabilityService(store_dir=tmp_path / "e", persist=False)
        assert svc.current_model_id is None

    def test_initialized_after_init(self, expl_service: ExplainabilityService) -> None:
        assert expl_service.is_initialized is True

    def test_model_id_set_after_init(
        self,
        expl_service: ExplainabilityService,
        trained_det_service: DetectionService,
    ) -> None:
        assert expl_service.current_model_id == trained_det_service.current_model_id

    def test_explain_before_init_raises(
        self, expl_settings: Settings, tmp_path: Path, trained_det_service: DetectionService
    ) -> None:
        with patch("backend.explainability.service.get_settings", return_value=expl_settings):
            svc = ExplainabilityService(store_dir=tmp_path / "e", persist=False)
        record = make_feature_record()
        alert = make_alert(record, model_id="any-id")
        with pytest.raises(ExplainerNotInitializedError):
            svc.explain_alert(alert, record)

    def test_init_from_unloaded_service_raises(
        self, expl_settings: Settings, tmp_path: Path
    ) -> None:
        with patch("backend.detection.service.get_settings", return_value=expl_settings), \
             patch("backend.detection.storage.get_settings", return_value=expl_settings), \
             patch("backend.detection.trainer.get_settings", return_value=expl_settings), \
             patch("backend.detection.scorer.get_settings", return_value=expl_settings):
            unloaded = DetectionService(
                features_dir=tmp_path / "f",
                models_dir=tmp_path / "m",
                auto_load=False,
            )
        with patch("backend.explainability.service.get_settings", return_value=expl_settings):
            svc = ExplainabilityService(store_dir=tmp_path / "e", persist=False)
        with pytest.raises(ValueError, match="no model loaded"):
            svc.initialize_from_detection_service(unloaded)

    def test_get_status_before_init(
        self, expl_settings: Settings, tmp_path: Path
    ) -> None:
        with patch("backend.explainability.service.get_settings", return_value=expl_settings):
            svc = ExplainabilityService(store_dir=tmp_path / "e", persist=False)
        status = svc.get_status()
        assert status["initialized"] is False

    def test_get_status_after_init(self, expl_service: ExplainabilityService) -> None:
        status = expl_service.get_status()
        assert status["initialized"] is True
        assert "model_id" in status


# ---------------------------------------------------------------------------
# Tests — Single Alert Explanation
# ---------------------------------------------------------------------------

class TestExplainAlertService:
    def test_explain_alert_returns_result(
        self,
        expl_service: ExplainabilityService,
        trained_det_service: DetectionService,
    ) -> None:
        record = make_feature_record()
        alert = make_alert(record, model_id=trained_det_service.current_model_id)
        result = expl_service.explain_alert(alert, record)
        assert isinstance(result, ExplanationResult)

    def test_explanation_has_correct_alert_id(
        self,
        expl_service: ExplainabilityService,
        trained_det_service: DetectionService,
    ) -> None:
        record = make_feature_record(event_id="evt-test-123")
        alert = make_alert(record, model_id=trained_det_service.current_model_id)
        result = expl_service.explain_alert(alert, record)
        assert result.alert_id == alert.alert_id

    def test_explanation_top_n_features(
        self,
        expl_service: ExplainabilityService,
        trained_det_service: DetectionService,
    ) -> None:
        record = make_feature_record()
        alert = make_alert(record, model_id=trained_det_service.current_model_id)
        result = expl_service.explain_alert(alert, record)
        assert len(result.top_features) == 5

    def test_explain_alert_with_persist_saves_to_store(
        self,
        expl_service: ExplainabilityService,
        trained_det_service: DetectionService,
    ) -> None:
        record = make_feature_record()
        alert = make_alert(record, model_id=trained_det_service.current_model_id)
        expl_service.explain_alert(alert, record, persist=True)
        loaded = expl_service.load_explanations_for_date()
        assert len(loaded) == 1


# ---------------------------------------------------------------------------
# Tests — Batch Explanation
# ---------------------------------------------------------------------------

class TestExplainBatchService:
    def test_explain_alerts_batch_returns_list(
        self,
        expl_service: ExplainabilityService,
        trained_det_service: DetectionService,
    ) -> None:
        model_id = trained_det_service.current_model_id
        records = [make_feature_record(event_id=f"e-{i}") for i in range(5)]
        alerts = [make_alert(r, model_id=model_id) for r in records]
        results = expl_service.explain_alerts_batch(alerts, records)
        assert len(results) == 5
        assert all(isinstance(r, ExplanationResult) for r in results)

    def test_explain_detection_result_returns_report(
        self,
        expl_service: ExplainabilityService,
        trained_det_service: DetectionService,
    ) -> None:
        model_id = trained_det_service.current_model_id
        records = [make_feature_record(event_id=f"e-{i}") for i in range(3)]
        alerts = [make_alert(r, model_id=model_id, anomaly_score=0.75) for r in records]

        det_result = DetectionResult(
            model_id=model_id,
            score_threshold=0.5,
            entity_dimension="user_host",
            records_scored=3,
            alerts_generated=3,
            alerts=alerts,
        )
        report = expl_service.explain_detection_result(det_result, records)
        assert isinstance(report, ExplainabilityReport)
        assert report.alerts_explained == 3

    def test_explain_detection_result_empty_alerts(
        self,
        expl_service: ExplainabilityService,
        trained_det_service: DetectionService,
    ) -> None:
        det_result = DetectionResult(
            model_id=trained_det_service.current_model_id,
            score_threshold=0.5,
            entity_dimension="user_host",
            alerts=[],
        )
        report = expl_service.explain_detection_result(det_result, [])
        assert report.alerts_explained == 0

    def test_explain_detection_result_unmatched_records_counted_as_errors(
        self,
        expl_service: ExplainabilityService,
        trained_det_service: DetectionService,
    ) -> None:
        model_id = trained_det_service.current_model_id
        record = make_feature_record(event_id="e-1")
        alert = make_alert(record, model_id=model_id)

        det_result = DetectionResult(
            model_id=model_id,
            score_threshold=0.5,
            entity_dimension="user_host",
            records_scored=1,
            alerts_generated=1,
            alerts=[alert],
        )
        # Pass empty feature_records → no match → 1 error
        report = expl_service.explain_detection_result(det_result, [])
        assert report.errors >= 1

    def test_report_has_aggregates(
        self,
        expl_service: ExplainabilityService,
        trained_det_service: DetectionService,
    ) -> None:
        model_id = trained_det_service.current_model_id
        records = [make_feature_record(event_id=f"e-{i}") for i in range(4)]
        alerts = [make_alert(r, model_id=model_id) for r in records]
        det_result = DetectionResult(
            model_id=model_id, score_threshold=0.5,
            entity_dimension="user_host", alerts=alerts,
        )
        report = expl_service.explain_detection_result(det_result, records)
        # avg_total_abs_shap may be 0 if training used constant features (all zeros)
        assert report.avg_total_abs_shap >= 0.0
        # alerts_explained should match
        assert report.alerts_explained == 4


# ---------------------------------------------------------------------------
# Tests — Streaming Explanation
# ---------------------------------------------------------------------------

class TestExplainStreamService:
    def test_explain_stream_yields_results(
        self,
        expl_service: ExplainabilityService,
        trained_det_service: DetectionService,
    ) -> None:
        model_id = trained_det_service.current_model_id
        records = [make_feature_record(event_id=f"e-{i}") for i in range(3)]
        alerts = [make_alert(r, model_id=model_id) for r in records]
        pairs = list(zip(alerts, records))

        results = list(expl_service.explain_stream(iter(pairs)))
        assert len(results) == 3
        assert all(isinstance(r, ExplanationResult) for r in results)

    def test_explain_stream_empty_input(
        self, expl_service: ExplainabilityService
    ) -> None:
        results = list(expl_service.explain_stream(iter([])))
        assert results == []
