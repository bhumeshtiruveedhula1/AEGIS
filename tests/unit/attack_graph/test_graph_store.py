"""tests/unit/attack_graph/test_graph_store.py — GraphStore Persistence Tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from backend.attack_graph.exceptions import GraphStorageError
from backend.attack_graph.graph_builder import AttackGraphBuilder
from backend.attack_graph.graph_store import GraphStore
from backend.attack_graph.models import GraphSnapshot

from tests.unit.attack_graph.conftest import make_mapped_attack


def _build_snapshot(graph_id: str = "g-001") -> GraphSnapshot:
    b = AttackGraphBuilder(graph_id=graph_id)
    b.add_batch([make_mapped_attack(alert_id=f"a{i}") for i in range(3)])
    _, snapshot = b.build()
    return snapshot


@pytest.fixture()
def store(tmp_path: Path) -> GraphStore:
    return GraphStore(store_dir=tmp_path / "ag")


class TestGraphStore:
    def test_dirs_created(self, tmp_path: Path) -> None:
        GraphStore(store_dir=tmp_path / "ag")
        assert (tmp_path / "ag" / "graphs").exists()
        assert (tmp_path / "ag" / "graphs" / "meta").exists()

    def test_save_snapshot_creates_file(self, store: GraphStore) -> None:
        snap = _build_snapshot()
        path = store.save_snapshot(snap)
        assert path.exists()
        assert path.suffix == ".json"

    def test_save_snapshot_atomic_no_tmp(self, store: GraphStore) -> None:
        store.save_snapshot(_build_snapshot())
        tmp_files = list((store._dir).glob("*.tmp"))
        assert len(tmp_files) == 0

    def test_load_snapshot_round_trip(self, store: GraphStore) -> None:
        snap = _build_snapshot("g-rt")
        store.save_snapshot(snap)
        loaded = store.load_snapshot("g-rt")
        assert loaded.graph_id == "g-rt"
        assert len(loaded.nodes) == len(snap.nodes)
        assert len(loaded.edges) == len(snap.edges)

    def test_load_snapshot_not_found_raises(self, store: GraphStore) -> None:
        with pytest.raises(GraphStorageError):
            store.load_snapshot("nonexistent-graph")

    def test_save_and_load_graph_meta(self, store: GraphStore) -> None:
        from backend.attack_graph.models import AttackGraph
        b = AttackGraphBuilder(graph_id="g-meta")
        b.add_mapped_attack(make_mapped_attack())
        graph, snap = b.build()
        store.save_graph_meta(graph)
        loaded = store.load_graph_meta("g-meta")
        assert loaded.graph_id == "g-meta"

    def test_list_graph_ids_empty(self, store: GraphStore) -> None:
        assert store.list_graph_ids() == []

    def test_list_graph_ids_after_saves(self, store: GraphStore) -> None:
        store.save_snapshot(_build_snapshot("g-1"))
        store.save_snapshot(_build_snapshot("g-2"))
        ids = store.list_graph_ids()
        assert len(ids) == 2

    def test_snapshot_to_nx_round_trip(self, store: GraphStore) -> None:
        import networkx as nx
        snap = _build_snapshot()
        store.save_snapshot(snap)
        loaded = store.load_snapshot(snap.graph_id)
        g = GraphStore.snapshot_to_nx(loaded)
        assert isinstance(g, nx.DiGraph)
        assert g.number_of_nodes() == len(loaded.nodes)
        assert g.number_of_edges() == len(loaded.edges)

    def test_node_map_from_snapshot(self, store: GraphStore) -> None:
        snap = _build_snapshot()
        store.save_snapshot(snap)
        loaded = store.load_snapshot(snap.graph_id)
        node_map = GraphStore.snapshot_to_node_map(loaded)
        assert len(node_map) == len(loaded.nodes)
        for nid, node in node_map.items():
            assert nid == node.node_id
