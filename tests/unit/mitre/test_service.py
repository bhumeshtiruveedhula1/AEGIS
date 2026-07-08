"""tests/unit/mitre/test_service.py — MitreService Integration Tests."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from backend.core.config import Settings
from backend.detection.models import DetectionResult
from backend.mitre.models import MappedAttack, MappingReport
from backend.mitre.service import MitreService

from tests.unit.mitre.conftest import make_alert, make_explanation, MODEL_ID


@pytest.fixture()
def mitre_settings(tmp_path: Path) -> Settings:
    return Settings(
        app_env="development",
        log_level="DEBUG",
        log_format="console",
        secret_key="test-secret-mitre-do-not-use",  # noqa: S106
        api_key="test-api-key-mitre",  # noqa: S106
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
def svc(mitre_settings: Settings, tmp_path: Path) -> MitreService:
    with patch("backend.mitre.service.get_settings", return_value=mitre_settings):
        return MitreService(
            store_dir=tmp_path / "mitre",
            persist=False,
            min_confidence=0.10,
        )


class TestMitreServiceInit:
    def test_get_status(self, svc: MitreService) -> None:
        status = svc.get_status()
        assert "kb_techniques" in status
        assert "kb_version" in status
        assert status["kb_techniques"] > 0

    def test_status_persist_flag(self, svc: MitreService) -> None:
        assert svc.get_status()["persist"] is False


class TestMitreServiceMapAlert:
    def test_returns_mapped_attack(self, svc: MitreService) -> None:
        alert = make_alert()
        result = svc.map_alert(alert)
        assert isinstance(result, MappedAttack)

    def test_returns_mapped_attack_with_explanation(self, svc: MitreService) -> None:
        alert = make_alert()
        expl = make_explanation(alert_id=alert.alert_id)
        result = svc.map_alert(alert, expl)
        assert isinstance(result, MappedAttack)
        assert len(result.techniques) > 0

    def test_alert_id_in_result(self, svc: MitreService) -> None:
        alert = make_alert("test-alert-007")
        result = svc.map_alert(alert)
        assert result.alert_id == "test-alert-007"

    def test_persist_saves_mapping(
        self, mitre_settings: Settings, tmp_path: Path
    ) -> None:
        with patch("backend.mitre.service.get_settings", return_value=mitre_settings):
            svc_persist = MitreService(
                store_dir=tmp_path / "mitre2",
                persist=True,
            )
        alert = make_alert()
        svc_persist.map_alert(alert, persist=True)
        loaded = svc_persist.load_mappings_for_date()
        assert len(loaded) == 1

    def test_no_persist_when_flag_false(self, svc: MitreService) -> None:
        alert = make_alert()
        svc.map_alert(alert, persist=False)
        loaded = svc.load_mappings_for_date()
        assert len(loaded) == 0


class TestMitreServiceBatch:
    def test_map_alerts_batch_returns_list(self, svc: MitreService) -> None:
        alerts = [make_alert(f"a-{i}") for i in range(5)]
        results = svc.map_alerts_batch(alerts)
        assert len(results) == 5

    def test_map_alerts_batch_with_explanations(self, svc: MitreService) -> None:
        alerts = [make_alert(f"a-{i}") for i in range(3)]
        expls = [make_explanation(alert_id=a.alert_id) for a in alerts]
        results = svc.map_alerts_batch(alerts, expls)
        assert len(results) == 3

    def test_map_detection_result_returns_report(self, svc: MitreService) -> None:
        alerts = [make_alert(f"a-{i}") for i in range(4)]
        det_result = DetectionResult(
            model_id=MODEL_ID,
            score_threshold=0.5,
            entity_dimension="user_host",
            records_scored=4,
            alerts_generated=4,
            alerts=alerts,
        )
        report = svc.map_detection_result(det_result)
        assert isinstance(report, MappingReport)
        assert report.statistics.total_alerts == 4

    def test_map_detection_result_with_explanations(self, svc: MitreService) -> None:
        alerts = [make_alert(f"a-{i}") for i in range(3)]
        expls = [make_explanation(alert_id=a.alert_id) for a in alerts]
        det_result = DetectionResult(
            model_id=MODEL_ID, score_threshold=0.5,
            entity_dimension="user_host", alerts=alerts,
        )
        report = svc.map_detection_result(det_result, expls)
        assert report.statistics.total_alerts == 3

    def test_map_detection_result_empty_alerts(self, svc: MitreService) -> None:
        det_result = DetectionResult(
            model_id=MODEL_ID, score_threshold=0.5,
            entity_dimension="user_host", alerts=[],
        )
        report = svc.map_detection_result(det_result)
        assert report.statistics.total_alerts == 0
        assert report.statistics.mapping_rate == 0.0

    def test_report_statistics_populated(self, svc: MitreService) -> None:
        alerts = [make_alert(f"a-{i}") for i in range(5)]
        expls = [make_explanation(alert_id=a.alert_id) for a in alerts]
        det_result = DetectionResult(
            model_id=MODEL_ID, score_threshold=0.5,
            entity_dimension="user_host", alerts=alerts,
        )
        report = svc.map_detection_result(det_result, expls)
        assert report.statistics.total_alerts == 5
        assert 0.0 <= report.statistics.mapping_rate <= 1.0


class TestMitreServiceStream:
    def test_stream_yields_results(self, svc: MitreService) -> None:
        alerts = [make_alert(f"a-{i}") for i in range(3)]
        pairs = [(a, make_explanation(alert_id=a.alert_id)) for a in alerts]
        results = list(svc.map_stream(iter(pairs)))
        assert len(results) == 3
        assert all(isinstance(r, MappedAttack) for r in results)

    def test_stream_empty(self, svc: MitreService) -> None:
        assert list(svc.map_stream(iter([]))) == []

    def test_stream_without_explanations(self, svc: MitreService) -> None:
        alerts = [make_alert(f"a-{i}") for i in range(2)]
        pairs = [(a, None) for a in alerts]
        results = list(svc.map_stream(iter(pairs)))
        assert len(results) == 2


class TestMitreServiceStorage:
    def test_list_reports_empty(self, svc: MitreService) -> None:
        assert svc.list_reports() == []

    def test_load_report_after_persist(
        self, mitre_settings: Settings, tmp_path: Path
    ) -> None:
        with patch("backend.mitre.service.get_settings", return_value=mitre_settings):
            svc_p = MitreService(store_dir=tmp_path / "mitre3", persist=True)
        alerts = [make_alert(f"a-{i}") for i in range(2)]
        det_result = DetectionResult(
            model_id=MODEL_ID, score_threshold=0.5,
            entity_dimension="user_host", alerts=alerts,
        )
        report = svc_p.map_detection_result(det_result)
        loaded = svc_p.load_report(report.report_id)
        assert loaded.report_id == report.report_id
