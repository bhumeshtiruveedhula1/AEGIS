"""tests/unit/chain_detection/test_service.py — AttackChainService Integration Tests."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from backend.chain_detection.models import AttackChain, ChainReport
from backend.chain_detection.service import AttackChainService
from backend.core.config import Settings

from tests.unit.chain_detection.conftest import (
    make_chain,
    make_empty_snapshot,
    make_linear_snapshot,
    make_multi_entity_snapshot,
    make_single_step_snapshot,
)


@pytest.fixture()
def cd_settings(tmp_path: Path) -> Settings:
    return Settings(
        app_env="development",
        log_level="DEBUG",
        log_format="console",
        secret_key="test-secret-cd",  # noqa: S106
        api_key="test-api-cd",  # noqa: S106
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
def svc(cd_settings: Settings, tmp_path: Path) -> AttackChainService:
    with patch("backend.chain_detection.service.get_settings", return_value=cd_settings):
        return AttackChainService(
            store_dir=tmp_path / "cd",
            persist=False,
        )


@pytest.fixture()
def svc_persist(cd_settings: Settings, tmp_path: Path) -> AttackChainService:
    with patch("backend.chain_detection.service.get_settings", return_value=cd_settings):
        return AttackChainService(
            store_dir=tmp_path / "cd_persist",
            persist=True,
        )


class TestServiceInit:
    def test_get_status(self, svc: AttackChainService) -> None:
        s = svc.get_status()
        assert "persist" in s
        assert "min_chain_length" in s
        assert s["persist"] is False


class TestDetectFromSnapshot:
    def test_returns_chain_report(
        self, svc: AttackChainService, linear_snapshot
    ) -> None:
        report = svc.detect_from_snapshot(linear_snapshot)
        assert isinstance(report, ChainReport)

    def test_report_graph_id_matches(
        self, svc: AttackChainService, linear_snapshot
    ) -> None:
        report = svc.detect_from_snapshot(linear_snapshot)
        assert report.graph_id == linear_snapshot.graph_id

    def test_empty_snapshot_returns_empty_report(
        self, svc: AttackChainService, empty_snapshot
    ) -> None:
        report = svc.detect_from_snapshot(empty_snapshot)
        assert report.statistics.total_chains == 0

    def test_single_step_no_chains(
        self, svc: AttackChainService, single_step_snapshot
    ) -> None:
        report = svc.detect_from_snapshot(single_step_snapshot)
        assert report.statistics.total_chains == 0

    def test_linear_snapshot_detects_chains(
        self, svc: AttackChainService, linear_snapshot
    ) -> None:
        report = svc.detect_from_snapshot(linear_snapshot)
        assert report.statistics.total_chains >= 1

    def test_multi_entity_snapshot(
        self, svc: AttackChainService, multi_entity_snapshot
    ) -> None:
        report = svc.detect_from_snapshot(multi_entity_snapshot)
        assert report.statistics.entities_affected >= 2

    def test_report_has_statistics(
        self, svc: AttackChainService, linear_snapshot
    ) -> None:
        report = svc.detect_from_snapshot(linear_snapshot)
        assert report.statistics is not None


class TestPersistence:
    def test_persist_saves_report(
        self, svc_persist: AttackChainService, linear_snapshot
    ) -> None:
        report = svc_persist.detect_from_snapshot(linear_snapshot)
        ids = svc_persist.list_reports()
        assert report.report_id in ids

    def test_no_persist_no_files(
        self, svc: AttackChainService, linear_snapshot
    ) -> None:
        svc.detect_from_snapshot(linear_snapshot)
        assert svc.list_reports() == []

    def test_load_report_after_persist(
        self, svc_persist: AttackChainService, linear_snapshot
    ) -> None:
        report = svc_persist.detect_from_snapshot(linear_snapshot)
        loaded = svc_persist.load_report(report.report_id)
        assert loaded.report_id == report.report_id

    def test_load_chains_for_date_after_persist(
        self, svc_persist: AttackChainService, linear_snapshot
    ) -> None:
        report = svc_persist.detect_from_snapshot(linear_snapshot)
        if report.statistics.total_chains > 0:
            chains = svc_persist.load_chains_for_date()
            assert len(chains) > 0


class TestStreamDetection:
    def test_stream_yields_reports(
        self, svc: AttackChainService
    ) -> None:
        snapshots = [make_linear_snapshot(), make_multi_entity_snapshot()]
        reports = list(svc.detect_from_snapshots_stream(iter(snapshots)))
        assert len(reports) == 2
        for r in reports:
            assert isinstance(r, ChainReport)

    def test_empty_stream(self, svc: AttackChainService) -> None:
        reports = list(svc.detect_from_snapshots_stream(iter([])))
        assert reports == []


class TestQueryHelpers:
    def test_get_chains_by_entity(self, svc: AttackChainService) -> None:
        report = svc.detect_from_snapshot(make_multi_entity_snapshot())
        if report.statistics.total_chains > 0:
            entity = report.chains[0].entity_id
            filtered = svc.get_chains_by_entity(report, entity)
            assert all(c.entity_id == entity for c in filtered)

    def test_get_high_confidence_chains(self, svc: AttackChainService) -> None:
        report = svc.detect_from_snapshot(make_linear_snapshot())
        high = svc.get_high_confidence_chains(report, threshold=0.0)
        # threshold 0.0 → all chains returned
        assert len(high) == report.statistics.total_chains

    def test_get_high_confidence_chains_above_threshold(
        self, svc: AttackChainService, linear_snapshot
    ) -> None:
        report = svc.detect_from_snapshot(linear_snapshot)
        high = svc.get_high_confidence_chains(report, threshold=0.99)
        for c in high:
            assert c.evaluation.confidence >= 0.99

    def test_get_multi_tactic_chains(self, svc: AttackChainService) -> None:
        report = svc.detect_from_snapshot(make_linear_snapshot())
        multi = svc.get_multi_tactic_chains(report)
        for c in multi:
            assert c.evaluation.is_multi_tactic is True

    def test_list_reports_empty(self, svc: AttackChainService) -> None:
        assert svc.list_reports() == []


class TestReEvaluation:
    def test_re_evaluate_chains_returns_same_count(
        self, svc: AttackChainService
    ) -> None:
        chains = [make_chain(f"c{i}") for i in range(3)]
        updated = svc.re_evaluate_chains(chains)
        assert len(updated) == 3

    def test_re_evaluate_updates_evaluation(
        self, svc: AttackChainService
    ) -> None:
        chains = [make_chain()]
        updated = svc.re_evaluate_chains(chains)
        assert updated[0].evaluation is not None

    def test_re_evaluate_empty_node_chain_unchanged(
        self, svc: AttackChainService
    ) -> None:
        chain = make_chain()
        empty = chain.model_copy(update={"nodes": []})
        updated = svc.re_evaluate_chains([empty])
        assert len(updated) == 1
