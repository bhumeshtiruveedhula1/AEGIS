"""tests/unit/attack_graph/test_models.py — GraphNode, GraphEdge, AttackGraph, GraphSnapshot Tests."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from backend.attack_graph.models import (
    GRAPH_SCHEMA_VERSION,
    AttackGraph,
    EdgeType,
    GraphEdge,
    GraphNode,
    GraphSnapshot,
    GraphStatistics,
    GraphTraversalResult,
    NodeType,
)


def _node(ntype: NodeType = NodeType.TECHNIQUE, value: str = "T1110") -> GraphNode:
    nid = GraphNode.make_id(ntype, value)
    return GraphNode(node_id=nid, node_type=ntype, label=value)


def _edge(src: str = "technique::T1110", dst: str = "alert::a1") -> GraphEdge:
    return GraphEdge(
        source_id=src, target_id=dst, edge_type=EdgeType.OBSERVED_ON
    )


class TestGraphNode:
    def test_make_id(self) -> None:
        nid = GraphNode.make_id(NodeType.TECHNIQUE, "T1110")
        assert nid == "technique::T1110"

    def test_make_id_alert(self) -> None:
        nid = GraphNode.make_id(NodeType.ALERT, "map-001")
        assert nid == "alert::map-001"

    def test_construction(self) -> None:
        n = _node()
        assert n.node_type == NodeType.TECHNIQUE
        assert n.observation_count == 1

    def test_merge_increments_count(self) -> None:
        n1 = _node()
        n2 = _node()
        merged = n1.merge(n2)
        assert merged.observation_count == 2

    def test_merge_updates_last_seen(self) -> None:
        early = datetime(2024, 1, 1, tzinfo=UTC)
        late = datetime(2024, 6, 1, tzinfo=UTC)
        n1 = _node().model_copy(update={"first_seen": early, "last_seen": early})
        n2 = _node().model_copy(update={"first_seen": late, "last_seen": late})
        merged = n1.merge(n2)
        assert merged.last_seen == late
        assert merged.first_seen == early

    def test_merge_unions_attributes(self) -> None:
        n1 = _node().model_copy(update={"attributes": {"a": 1}})
        n2 = _node().model_copy(update={"attributes": {"b": 2}})
        merged = n1.merge(n2)
        assert "a" in merged.attributes
        assert "b" in merged.attributes

    def test_json_round_trip(self) -> None:
        n = _node(NodeType.HOST, "workstation-01")
        reloaded = GraphNode.model_validate_json(n.model_dump_json())
        assert reloaded.node_id == n.node_id
        assert reloaded.node_type == NodeType.HOST

    def test_default_timestamps_utc(self) -> None:
        n = _node()
        assert n.first_seen.tzinfo is not None


class TestGraphEdge:
    def test_edge_key(self) -> None:
        e = _edge()
        src, dst, et = e.edge_key
        assert src == "technique::T1110"
        assert dst == "alert::a1"
        assert et == "observed_on"

    def test_json_round_trip(self) -> None:
        e = _edge()
        reloaded = GraphEdge.model_validate_json(e.model_dump_json())
        assert reloaded.source_id == e.source_id
        assert reloaded.edge_type == EdgeType.OBSERVED_ON


class TestAttackGraph:
    def test_unique_graph_id(self) -> None:
        a = AttackGraph(source_model_id="m")
        b = AttackGraph(source_model_id="m")
        assert a.graph_id != b.graph_id

    def test_graph_id_prefix(self) -> None:
        g = AttackGraph()
        assert g.graph_id.startswith("ag-")

    def test_schema_version(self) -> None:
        g = AttackGraph()
        assert g.schema_version == GRAPH_SCHEMA_VERSION

    def test_to_summary_keys(self) -> None:
        g = AttackGraph()
        s = g.to_summary()
        for k in ("graph_id", "nodes", "edges", "techniques", "is_dag"):
            assert k in s

    def test_json_round_trip(self) -> None:
        g = AttackGraph(source_model_id="m", mapped_attack_ids=["a", "b"])
        reloaded = AttackGraph.model_validate_json(g.model_dump_json())
        assert reloaded.graph_id == g.graph_id
        assert reloaded.mapped_attack_ids == ["a", "b"]


class TestGraphSnapshot:
    def test_snapshot_id_prefix(self) -> None:
        snap = GraphSnapshot(graph_id="g1")
        assert snap.snapshot_id.startswith("snap-")

    def test_schema_version(self) -> None:
        snap = GraphSnapshot(graph_id="g1")
        assert snap.schema_version == GRAPH_SCHEMA_VERSION

    def test_json_round_trip_with_nodes_edges(self) -> None:
        nodes = [_node(NodeType.HOST, "h1"), _node(NodeType.USER, "u1")]
        edges = [_edge()]
        snap = GraphSnapshot(graph_id="g1", nodes=nodes, edges=edges)
        reloaded = GraphSnapshot.model_validate_json(snap.model_dump_json())
        assert len(reloaded.nodes) == 2
        assert len(reloaded.edges) == 1

    def test_empty_snapshot(self) -> None:
        snap = GraphSnapshot(graph_id="g1")
        assert snap.nodes == []
        assert snap.edges == []


class TestGraphStatistics:
    def test_defaults_zero(self) -> None:
        s = GraphStatistics()
        assert s.node_count == 0
        assert s.is_dag is True

    def test_json_round_trip(self) -> None:
        s = GraphStatistics(node_count=5, edge_count=3, technique_count=2)
        reloaded = GraphStatistics.model_validate_json(s.model_dump_json())
        assert reloaded.node_count == 5


class TestGraphTraversalResult:
    def test_construction(self) -> None:
        r = GraphTraversalResult(query_type="neighbors", root_node_id="n1")
        assert r.nodes == []
        assert r.edges == []
        assert r.depth == 0
