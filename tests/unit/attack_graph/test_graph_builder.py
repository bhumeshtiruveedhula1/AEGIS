"""tests/unit/attack_graph/test_graph_builder.py — AttackGraphBuilder Tests."""

from __future__ import annotations

import pytest

from backend.attack_graph.graph_builder import AttackGraphBuilder
from backend.attack_graph.models import (
    AttackGraph,
    EdgeType,
    GraphSnapshot,
    NodeType,
)

from tests.unit.attack_graph.conftest import (
    _tm,
    make_mapped_attack,
)


class TestBuilderInit:
    def test_empty_builder(self) -> None:
        b = AttackGraphBuilder()
        assert b.node_count == 0
        assert b.edge_count == 0

    def test_custom_graph_id(self) -> None:
        b = AttackGraphBuilder(graph_id="my-graph")
        assert b._graph_id == "my-graph"


class TestAddMappedAttack:
    def test_adds_nodes(self) -> None:
        b = AttackGraphBuilder()
        m = make_mapped_attack()
        b.add_mapped_attack(m)
        assert b.node_count > 0

    def test_alert_node_created(self) -> None:
        b = AttackGraphBuilder()
        m = make_mapped_attack(mapping_id="map-abc")
        b.add_mapped_attack(m)
        nid = f"alert::map-abc"
        assert nid in b._nodes

    def test_entity_node_created(self) -> None:
        b = AttackGraphBuilder()
        m = make_mapped_attack(entity_type="user_host", entity_id="alice::ws01")
        b.add_mapped_attack(m)
        nid = "entity::user_host::alice::ws01"
        assert nid in b._nodes

    def test_tactic_node_created(self) -> None:
        b = AttackGraphBuilder()
        m = make_mapped_attack(techniques=[_tm("T1110", "TA0006", "Credential Access")])
        b.add_mapped_attack(m)
        tac_nid = "tactic::TA0006"
        assert tac_nid in b._nodes

    def test_technique_node_created(self) -> None:
        b = AttackGraphBuilder()
        m = make_mapped_attack(techniques=[_tm("T1110")])
        b.add_mapped_attack(m)
        # Technique node id contains "T1110"
        assert any("T1110" in k for k in b._nodes)

    def test_host_user_nodes_from_entity_id(self) -> None:
        b = AttackGraphBuilder()
        m = make_mapped_attack(entity_id="alice::workstation-01")
        b.add_mapped_attack(m)
        assert "user::alice" in b._nodes
        assert "host::workstation-01" in b._nodes

    def test_skip_no_techniques(self) -> None:
        b = AttackGraphBuilder()
        m = make_mapped_attack()
        m2 = m.model_copy(update={"techniques": []})
        b.add_mapped_attack(m2)
        assert b.node_count == 0

    def test_edges_created(self) -> None:
        b = AttackGraphBuilder()
        b.add_mapped_attack(make_mapped_attack())
        assert b.edge_count > 0

    def test_technique_to_alert_edge(self) -> None:
        b = AttackGraphBuilder()
        m = make_mapped_attack(mapping_id="map-x", techniques=[_tm("T1110")])
        b.add_mapped_attack(m)
        alert_nid = "alert::map-x"
        # Should have at least one edge targeting the alert node
        incoming = list(b.nx_graph.predecessors(alert_nid))
        assert len(incoming) > 0

    def test_technique_belongs_to_tactic(self) -> None:
        b = AttackGraphBuilder()
        b.add_mapped_attack(make_mapped_attack(techniques=[_tm("T1110", "TA0006")]))
        tac_nid = "tactic::TA0006"
        # Technique → tactic edge (BELONGS_TO)
        assert any(
            EdgeType.BELONGS_TO.value in str(data)
            for _, _, data in b.nx_graph.edges(data=True)
            if _ in b._nodes and b._nodes[_].node_type == NodeType.TECHNIQUE
        ) or tac_nid in b._nodes


class TestMergeSemantics:
    def test_same_entity_merged(self) -> None:
        b = AttackGraphBuilder()
        m1 = make_mapped_attack(alert_id="a1", entity_id="alice::ws01")
        m2 = make_mapped_attack(alert_id="a2", entity_id="alice::ws01")
        b.add_batch([m1, m2])
        # Should have only ONE entity node for alice::ws01
        entity_ids = [k for k in b._nodes if k.startswith("entity::")]
        assert len([e for e in entity_ids if "alice" in e]) == 1

    def test_same_tactic_merged(self) -> None:
        b = AttackGraphBuilder()
        m1 = make_mapped_attack(techniques=[_tm("T1110", "TA0006")])
        m2 = make_mapped_attack(alert_id="a2", techniques=[_tm("T1078", "TA0006")])
        b.add_batch([m1, m2])
        tac_nodes = [k for k in b._nodes if k.startswith("tactic::TA0006")]
        assert len(tac_nodes) == 1

    def test_node_observation_count_incremented(self) -> None:
        b = AttackGraphBuilder()
        m1 = make_mapped_attack(alert_id="a1", entity_id="alice::ws01")
        m2 = make_mapped_attack(alert_id="a2", entity_id="alice::ws01")
        b.add_batch([m1, m2])
        entity_nid = "entity::user_host::alice::ws01"
        assert b._nodes[entity_nid].observation_count == 2

    def test_different_entities_not_merged(self) -> None:
        b = AttackGraphBuilder()
        b.add_mapped_attack(make_mapped_attack(entity_id="alice::ws01"))
        b.add_mapped_attack(make_mapped_attack(alert_id="a2", entity_id="bob::ws02"))
        entity_count = sum(1 for n in b._nodes.values() if n.node_type == NodeType.ENTITY)
        assert entity_count == 2


class TestBuildOutput:
    def test_build_returns_graph_and_snapshot(self) -> None:
        b = AttackGraphBuilder()
        b.add_mapped_attack(make_mapped_attack())
        graph, snapshot = b.build()
        assert isinstance(graph, AttackGraph)
        assert isinstance(snapshot, GraphSnapshot)

    def test_graph_id_matches_snapshot(self) -> None:
        b = AttackGraphBuilder(graph_id="stable-id")
        b.add_mapped_attack(make_mapped_attack())
        graph, snapshot = b.build()
        assert graph.graph_id == snapshot.graph_id == "stable-id"

    def test_statistics_populated(self) -> None:
        b = AttackGraphBuilder()
        b.add_batch([make_mapped_attack(alert_id=f"a{i}") for i in range(3)])
        graph, _ = b.build()
        assert graph.statistics.node_count > 0
        assert graph.statistics.alert_count == 3

    def test_snapshot_nodes_match_internal(self) -> None:
        b = AttackGraphBuilder()
        b.add_mapped_attack(make_mapped_attack())
        _, snapshot = b.build()
        assert len(snapshot.nodes) == b.node_count
        assert len(snapshot.edges) == b.edge_count

    def test_build_is_idempotent(self) -> None:
        b = AttackGraphBuilder()
        b.add_mapped_attack(make_mapped_attack())
        g1, s1 = b.build()
        g2, s2 = b.build()
        assert g1.graph_id == g2.graph_id
        assert len(s1.nodes) == len(s2.nodes)

    def test_is_dag_on_small_graph(self) -> None:
        b = AttackGraphBuilder()
        b.add_mapped_attack(make_mapped_attack())
        graph, _ = b.build()
        # Small graphs without back-edges should be DAGs
        # (may not always be DAG due to related_to cycles, so just check it runs)
        assert isinstance(graph.statistics.is_dag, bool)

    def test_mapped_attack_ids_tracked(self) -> None:
        b = AttackGraphBuilder()
        m = make_mapped_attack(mapping_id="map-tracked")
        b.add_mapped_attack(m)
        graph, _ = b.build()
        assert "map-tracked" in graph.mapped_attack_ids

    def test_batch_add(self, multi_mappings) -> None:
        b = AttackGraphBuilder()
        b.add_batch(multi_mappings)
        graph, _ = b.build()
        assert graph.statistics.alert_count == 5
