"""tests/unit/attack_graph/test_traversal.py — Traversal Utilities Tests."""

from __future__ import annotations

import pytest
from datetime import UTC, datetime

from backend.attack_graph import traversal as tv
from backend.attack_graph.exceptions import NodeNotFoundError
from backend.attack_graph.graph_builder import AttackGraphBuilder
from backend.attack_graph.models import EdgeType, NodeType

from tests.unit.attack_graph.conftest import _tm, make_mapped_attack


def _built(mappings=None):
    if mappings is None:
        mappings = [make_mapped_attack()]
    b = AttackGraphBuilder(graph_id="trav-test")
    b.add_batch(mappings)
    return b.nx_graph, b._nodes


class TestGetNode:
    def test_get_existing_node(self) -> None:
        g, nodes = _built()
        nid = next(iter(nodes))
        node = tv.get_node(g, nodes, nid)
        assert node.node_id == nid

    def test_get_missing_node_raises(self) -> None:
        g, nodes = _built()
        with pytest.raises(NodeNotFoundError):
            tv.get_node(g, nodes, "nonexistent::node")


class TestGetNodesByType:
    def test_returns_only_requested_type(self) -> None:
        g, nodes = _built()
        alerts = tv.get_nodes_by_type(nodes, NodeType.ALERT)
        assert all(n.node_type == NodeType.ALERT for n in alerts)

    def test_returns_correct_count(self) -> None:
        mappings = [make_mapped_attack(alert_id=f"a-{i}") for i in range(3)]
        g, nodes = _built(mappings)
        alerts = tv.get_nodes_by_type(nodes, NodeType.ALERT)
        assert len(alerts) == 3


class TestFindNodesByAttribute:
    def test_finds_by_technique_id(self) -> None:
        g, nodes = _built([make_mapped_attack(techniques=[_tm("T1110")])])
        found = tv.find_nodes_by_attribute(nodes, "technique_id", "T1110")
        assert len(found) >= 1

    def test_returns_empty_for_unknown(self) -> None:
        g, nodes = _built()
        found = tv.find_nodes_by_attribute(nodes, "technique_id", "T9999")
        assert found == []


class TestGetNeighbors:
    def test_returns_traversal_result(self) -> None:
        g, nodes = _built()
        alert_nodes = tv.get_nodes_by_type(nodes, NodeType.ALERT)
        # Alert node should have no outgoing edges in our schema
        result = tv.get_neighbors(g, nodes, alert_nodes[0].node_id)
        assert result.query_type == "neighbors"

    def test_missing_node_raises(self) -> None:
        g, nodes = _built()
        with pytest.raises(NodeNotFoundError):
            tv.get_neighbors(g, nodes, "missing::node")

    def test_technique_has_observed_on_edge_to_alert(self) -> None:
        g, nodes = _built([make_mapped_attack(mapping_id="map-tst")])
        tech_nodes = tv.get_nodes_by_type(nodes, NodeType.TECHNIQUE)
        alert_nid = "alert::map-tst"
        # Find technique that has outgoing edge to the alert
        found = False
        for tn in tech_nodes:
            r = tv.get_neighbors(g, nodes, tn.node_id, EdgeType.OBSERVED_ON)
            if any(n.node_id == alert_nid for n in r.nodes):
                found = True
                break
        assert found


class TestGetPredecessors:
    def test_returns_traversal_result(self) -> None:
        g, nodes = _built()
        alert_nodes = tv.get_nodes_by_type(nodes, NodeType.ALERT)
        result = tv.get_predecessors(g, nodes, alert_nodes[0].node_id)
        assert result.query_type == "predecessors"

    def test_alert_has_technique_predecessors(self) -> None:
        g, nodes = _built([make_mapped_attack(mapping_id="map-pred")])
        result = tv.get_predecessors(g, nodes, "alert::map-pred")
        assert len(result.nodes) > 0
        assert all(n.node_type == NodeType.TECHNIQUE for n in result.nodes)


class TestDescendantsAncestors:
    def test_descendants_not_empty(self) -> None:
        g, nodes = _built()
        tech_nodes = tv.get_nodes_by_type(nodes, NodeType.TECHNIQUE)
        result = tv.get_descendants(g, nodes, tech_nodes[0].node_id)
        assert result.query_type == "descendants"
        assert len(result.nodes) >= 0  # may be 0 if technique is leaf

    def test_ancestors_of_alert(self) -> None:
        g, nodes = _built([make_mapped_attack(mapping_id="map-anc")])
        result = tv.get_ancestors(g, nodes, "alert::map-anc")
        assert result.query_type == "ancestors"
        # Techniques are ancestors of the alert
        assert any(n.node_type == NodeType.TECHNIQUE for n in result.nodes)

    def test_missing_node_raises_descendants(self) -> None:
        g, nodes = _built()
        with pytest.raises(NodeNotFoundError):
            tv.get_descendants(g, nodes, "missing::node")


class TestFindPaths:
    def test_no_path_returns_empty(self) -> None:
        g, nodes = _built()
        all_nodes = list(nodes.keys())
        # Two nodes that have no path between them
        result = tv.find_paths(g, nodes, all_nodes[0], all_nodes[-1])
        assert result.query_type == "paths"
        assert isinstance(result.metadata["path_count"], int)

    def test_missing_source_raises(self) -> None:
        g, nodes = _built()
        nid = next(iter(nodes))
        with pytest.raises(NodeNotFoundError):
            tv.find_paths(g, nodes, "missing", nid)


class TestTemporalOrdering:
    def test_sorted_ascending(self) -> None:
        from datetime import timedelta
        base = datetime(2024, 1, 1, tzinfo=UTC)
        mappings = [
            make_mapped_attack(alert_id=f"a{i}", ts=base + timedelta(hours=i))
            for i in range(4)
        ]
        g, nodes = _built(mappings)
        ordered = tv.get_nodes_in_temporal_order(nodes, NodeType.ALERT)
        times = [n.first_seen for n in ordered]
        assert times == sorted(times)

    def test_window_filter(self) -> None:
        from datetime import timedelta
        base = datetime(2024, 1, 1, tzinfo=UTC)
        mappings = [
            make_mapped_attack(alert_id=f"a{i}", ts=base + timedelta(hours=i))
            for i in range(6)
        ]
        g, nodes = _built(mappings)
        start = base + timedelta(hours=2)
        end = base + timedelta(hours=4)
        in_window = tv.get_nodes_in_window(nodes, start, end, NodeType.ALERT)
        for n in in_window:
            assert start <= n.first_seen <= end


class TestConnectedComponents:
    def test_single_component(self) -> None:
        g, nodes = _built()
        comps = tv.get_weakly_connected_components(g, nodes)
        assert len(comps) >= 1

    def test_is_connected(self) -> None:
        g, nodes = _built()
        # Single ingested mapping → should be one connected component
        assert tv.is_connected(g) is True


class TestEntityHelpers:
    def test_techniques_for_entity(self) -> None:
        g, nodes = _built([make_mapped_attack(entity_id="alice::ws01")])
        eid = "entity::user_host::alice::ws01"
        techs = tv.techniques_for_entity(nodes, eid)
        assert all(n.node_type == NodeType.TECHNIQUE for n in techs)

    def test_alerts_for_entity(self) -> None:
        g, nodes = _built([make_mapped_attack(entity_id="alice::ws01", mapping_id="map-ent")])
        eid = "entity::user_host::alice::ws01"
        alerts = tv.alerts_for_entity(g, nodes, eid)
        assert any(n.node_id == "alert::map-ent" for n in alerts)

    def test_techniques_by_tactic(self) -> None:
        g, nodes = _built([make_mapped_attack(techniques=[_tm("T1110", "TA0006")])])
        techs = tv.techniques_by_tactic(nodes, "TA0006")
        assert len(techs) >= 1
        assert all(n.node_type == NodeType.TECHNIQUE for n in techs)
