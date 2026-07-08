"""tests/unit/attack_graph/test_service.py — AttackGraphService Integration Tests."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from backend.attack_graph.models import (
    AttackGraph,
    GraphSnapshot,
    GraphStatistics,
    GraphTraversalResult,
    NodeType,
)
from backend.attack_graph.service import AttackGraphService
from backend.core.config import Settings

from tests.unit.attack_graph.conftest import _tm, make_mapped_attack


@pytest.fixture()
def ag_settings(tmp_path: Path) -> Settings:
    return Settings(
        app_env="development",
        log_level="DEBUG",
        log_format="console",
        secret_key="test-secret-ag",  # noqa: S106
        api_key="test-api-ag",  # noqa: S106
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
def svc(ag_settings: Settings, tmp_path: Path) -> AttackGraphService:
    with patch("backend.attack_graph.service.get_settings", return_value=ag_settings):
        return AttackGraphService(
            store_dir=tmp_path / "ag",
            persist=False,
        )


@pytest.fixture()
def svc_persist(ag_settings: Settings, tmp_path: Path) -> AttackGraphService:
    with patch("backend.attack_graph.service.get_settings", return_value=ag_settings):
        return AttackGraphService(
            store_dir=tmp_path / "ag_persist",
            persist=True,
        )


class TestServiceInit:
    def test_get_status(self, svc: AttackGraphService) -> None:
        s = svc.get_status()
        assert "persist" in s
        assert "cached_graphs" in s
        assert s["persist"] is False


class TestBuildGraph:
    def test_returns_graph_and_snapshot(self, svc: AttackGraphService) -> None:
        mappings = [make_mapped_attack(alert_id=f"a{i}") for i in range(4)]
        graph, snapshot = svc.build_graph(mappings)
        assert isinstance(graph, AttackGraph)
        assert isinstance(snapshot, GraphSnapshot)

    def test_graph_has_nodes(self, svc: AttackGraphService) -> None:
        mappings = [make_mapped_attack()]
        graph, _ = svc.build_graph(mappings)
        assert graph.statistics.node_count > 0

    def test_alert_count_correct(self, svc: AttackGraphService) -> None:
        mappings = [make_mapped_attack(alert_id=f"a{i}") for i in range(5)]
        graph, _ = svc.build_graph(mappings)
        assert graph.statistics.alert_count == 5

    def test_custom_graph_id(self, svc: AttackGraphService) -> None:
        mappings = [make_mapped_attack()]
        graph, _ = svc.build_graph(mappings, graph_id="custom-id")
        assert graph.graph_id == "custom-id"

    def test_graph_cached_after_build(self, svc: AttackGraphService) -> None:
        mappings = [make_mapped_attack()]
        graph, _ = svc.build_graph(mappings)
        assert graph.graph_id in svc._cache

    def test_persist_saves_files(self, svc_persist: AttackGraphService) -> None:
        mappings = [make_mapped_attack()]
        graph, _ = svc_persist.build_graph(mappings)
        ids = svc_persist.list_graphs()
        assert graph.graph_id in ids


class TestBuildFromStream:
    def test_stream_build_returns_graph(self, svc: AttackGraphService) -> None:
        mappings = [make_mapped_attack(alert_id=f"a{i}") for i in range(3)]
        graph, snapshot = svc.build_graph_from_stream(iter(mappings))
        assert graph.statistics.alert_count == 3

    def test_empty_stream(self, svc: AttackGraphService) -> None:
        graph, snapshot = svc.build_graph_from_stream(iter([]))
        assert graph.statistics.node_count == 0


class TestLoadGraph:
    def test_load_persisted_graph(
        self, svc_persist: AttackGraphService
    ) -> None:
        mappings = [make_mapped_attack()]
        graph, _ = svc_persist.build_graph(mappings)
        # Fresh service — force load from disk
        from unittest.mock import patch
        from backend.core.config import Settings
        from pathlib import Path
        loaded_snap = svc_persist.load_graph(graph.graph_id)
        assert loaded_snap.graph_id == graph.graph_id

    def test_load_already_cached(self, svc: AttackGraphService) -> None:
        mappings = [make_mapped_attack()]
        graph, _ = svc.build_graph(mappings)
        snap = svc.load_graph(graph.graph_id)
        assert snap.graph_id == graph.graph_id


class TestStatistics:
    def test_get_graph_statistics(self, svc: AttackGraphService) -> None:
        mappings = [make_mapped_attack(alert_id=f"a{i}") for i in range(3)]
        graph, _ = svc.build_graph(mappings)
        stats = svc.get_graph_statistics(graph.graph_id)
        assert isinstance(stats, GraphStatistics)
        assert stats.alert_count == 3


class TestTraversalQueries:
    def test_query_nodes_by_type_alert(self, svc: AttackGraphService) -> None:
        mappings = [make_mapped_attack(alert_id=f"a{i}") for i in range(4)]
        graph, _ = svc.build_graph(mappings)
        alerts = svc.query_nodes_by_type(graph.graph_id, NodeType.ALERT)
        assert len(alerts) == 4

    def test_query_node_by_id(self, svc: AttackGraphService) -> None:
        mappings = [make_mapped_attack(mapping_id="map-qry")]
        graph, _ = svc.build_graph(mappings)
        node = svc.query_node(graph.graph_id, "alert::map-qry")
        assert node.node_type == NodeType.ALERT

    def test_query_neighbors(self, svc: AttackGraphService) -> None:
        mappings = [make_mapped_attack(mapping_id="map-nb")]
        graph, _ = svc.build_graph(mappings)
        result = svc.query_neighbors(graph.graph_id, "alert::map-nb")
        assert isinstance(result, GraphTraversalResult)

    def test_query_predecessors_of_alert(self, svc: AttackGraphService) -> None:
        mappings = [make_mapped_attack(mapping_id="map-pred")]
        graph, _ = svc.build_graph(mappings)
        result = svc.query_predecessors(graph.graph_id, "alert::map-pred")
        assert len(result.nodes) > 0
        assert all(n.node_type == NodeType.TECHNIQUE for n in result.nodes)

    def test_query_descendants(self, svc: AttackGraphService) -> None:
        mappings = [make_mapped_attack()]
        graph, _ = svc.build_graph(mappings)
        techs = svc.query_nodes_by_type(graph.graph_id, NodeType.TECHNIQUE)
        result = svc.query_descendants(graph.graph_id, techs[0].node_id)
        assert result.query_type == "descendants"

    def test_query_ancestors(self, svc: AttackGraphService) -> None:
        mappings = [make_mapped_attack(mapping_id="map-anc")]
        graph, _ = svc.build_graph(mappings)
        result = svc.query_ancestors(graph.graph_id, "alert::map-anc")
        assert result.query_type == "ancestors"

    def test_query_techniques_for_entity(self, svc: AttackGraphService) -> None:
        mappings = [make_mapped_attack(entity_id="alice::ws01",
                                       techniques=[_tm("T1110")])]
        graph, _ = svc.build_graph(mappings)
        eid = "entity::user_host::alice::ws01"
        techs = svc.query_techniques_for_entity(graph.graph_id, eid)
        assert all(n.node_type == NodeType.TECHNIQUE for n in techs)

    def test_query_techniques_by_tactic(self, svc: AttackGraphService) -> None:
        mappings = [make_mapped_attack(techniques=[_tm("T1110", "TA0006")])]
        graph, _ = svc.build_graph(mappings)
        techs = svc.query_techniques_by_tactic(graph.graph_id, "TA0006")
        assert len(techs) >= 1

    def test_query_temporal_order(self, svc: AttackGraphService) -> None:
        mappings = [make_mapped_attack(alert_id=f"a{i}") for i in range(3)]
        graph, _ = svc.build_graph(mappings)
        ordered = svc.query_temporal_order(graph.graph_id, NodeType.ALERT)
        times = [n.first_seen for n in ordered]
        assert times == sorted(times)

    def test_query_connected_components(self, svc: AttackGraphService) -> None:
        mappings = [make_mapped_attack()]
        graph, _ = svc.build_graph(mappings)
        comps = svc.query_connected_components(graph.graph_id)
        assert len(comps) >= 1

    def test_list_graphs(self, svc: AttackGraphService) -> None:
        mappings = [make_mapped_attack()]
        svc.build_graph(mappings)
        # Without persist, stored graphs list is empty
        ids = svc.list_graphs()
        assert isinstance(ids, list)
