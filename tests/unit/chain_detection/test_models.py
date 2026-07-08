"""tests/unit/chain_detection/test_models.py — Chain Data Model Tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from backend.chain_detection.models import (
    CHAIN_SCHEMA_VERSION,
    AttackChain,
    ChainEvidence,
    ChainEvaluation,
    ChainLink,
    ChainNode,
    ChainReport,
    ChainStatistics,
)

from tests.unit.chain_detection.conftest import (
    BASE_TS,
    _make_chain_node,
    _make_eval,
    make_chain,
)


class TestChainNode:
    def test_construction(self) -> None:
        n = _make_chain_node()
        assert n.technique_id == "T1110"
        assert n.step_index == 0

    def test_confidence_bounds(self) -> None:
        with pytest.raises(Exception):
            _make_chain_node(conf=1.5)
        with pytest.raises(Exception):
            _make_chain_node(conf=-0.1)

    def test_to_summary_keys(self) -> None:
        n = _make_chain_node()
        s = n.to_summary()
        for k in ("step", "technique_id", "tactic_name", "confidence", "first_seen"):
            assert k in s

    def test_json_round_trip(self) -> None:
        n = _make_chain_node("T1059", "TA0002", "Execution", 0.65, 1)
        reloaded = ChainNode.model_validate_json(n.model_dump_json())
        assert reloaded.technique_id == "T1059"
        assert reloaded.step_index == 1


class TestChainLink:
    def test_construction(self) -> None:
        lnk = ChainLink(
            source_node_id="technique::T1110",
            target_node_id="technique::T1059",
            link_type="precedes",
        )
        assert lnk.temporal_gap_seconds == 0.0

    def test_link_key(self) -> None:
        lnk = ChainLink(
            source_node_id="a", target_node_id="b", link_type="precedes"
        )
        assert lnk.link_key == ("a", "b")

    def test_json_round_trip(self) -> None:
        lnk = ChainLink(
            source_node_id="x", target_node_id="y",
            link_type="related_to", temporal_gap_seconds=3600.0,
        )
        reloaded = ChainLink.model_validate_json(lnk.model_dump_json())
        assert reloaded.temporal_gap_seconds == pytest.approx(3600.0)


class TestChainEvaluation:
    def test_construction(self) -> None:
        ev = _make_eval()
        assert 0.0 <= ev.confidence <= 1.0

    def test_confidence_bounds(self) -> None:
        with pytest.raises(Exception):
            ChainEvaluation(
                confidence=1.5, avg_step_confidence=0.5,
                tactic_coverage_ratio=0.2, temporal_consistency_score=1.0,
                observation_strength=0.1,
            )

    def test_json_round_trip(self) -> None:
        ev = _make_eval(confidence=0.72, is_multi_tactic=True)
        reloaded = ChainEvaluation.model_validate_json(ev.model_dump_json())
        assert reloaded.confidence == pytest.approx(0.72)
        assert reloaded.is_multi_tactic is True


class TestAttackChain:
    def test_unique_chain_id(self) -> None:
        a = make_chain()
        b = make_chain()
        assert a.chain_id != b.chain_id

    def test_chain_id_prefix(self) -> None:
        c = make_chain()
        assert c.chain_id.startswith("chain-")

    def test_schema_version(self) -> None:
        c = make_chain()
        assert c.schema_version == CHAIN_SCHEMA_VERSION

    def test_length_property(self) -> None:
        c = make_chain()
        assert c.length == len(c.nodes)

    def test_tactic_sequence_ordered(self) -> None:
        nodes = [
            _make_chain_node("T1110", "TA0006", "Credential Access", step=0),
            _make_chain_node("T1059", "TA0002", "Execution", step=1),
        ]
        c = make_chain(nodes=nodes)
        assert c.tactic_sequence == ["Credential Access", "Execution"]

    def test_tactic_sequence_deduplicates_consecutive(self) -> None:
        nodes = [
            _make_chain_node("T1110", "TA0006", "Credential Access", step=0),
            _make_chain_node("T1078", "TA0006", "Credential Access", step=1),
        ]
        c = make_chain(nodes=nodes)
        assert c.tactic_sequence == ["Credential Access"]

    def test_technique_ids(self) -> None:
        c = make_chain()
        assert c.technique_ids == [n.technique_id for n in c.nodes]

    def test_nodes_sorted_by_step_index(self) -> None:
        n0 = _make_chain_node("T1110", step=0)
        n1 = _make_chain_node("T1059", "TA0002", "Execution", step=1)
        # Pass in reverse order
        c = make_chain(nodes=[n1, n0])
        assert c.nodes[0].step_index == 0
        assert c.nodes[1].step_index == 1

    def test_to_summary_keys(self) -> None:
        c = make_chain()
        s = c.to_summary()
        for k in ("chain_id", "length", "confidence", "tactic_sequence", "technique_ids"):
            assert k in s

    def test_json_round_trip(self) -> None:
        c = make_chain(chain_id="chain-rt-01")
        reloaded = AttackChain.model_validate_json(c.model_dump_json())
        assert reloaded.chain_id == "chain-rt-01"
        assert len(reloaded.nodes) == len(c.nodes)
        assert len(reloaded.links) == len(c.links)


class TestChainReport:
    def test_report_id_prefix(self) -> None:
        r = ChainReport(graph_id="g1")
        assert r.report_id.startswith("crpt-")

    def test_empty_report_statistics(self) -> None:
        r = ChainReport(graph_id="g1", chains=[])
        assert r.statistics.total_chains == 0
        assert r.statistics.avg_confidence == 0.0

    def test_statistics_computed(self) -> None:
        chains = [make_chain(f"c{i}") for i in range(4)]
        r = ChainReport(graph_id="g1", chains=chains)
        assert r.statistics.total_chains == 4
        assert r.statistics.avg_confidence > 0.0

    def test_entities_affected(self) -> None:
        c1 = make_chain(entity_id="alice::ws01")
        c2 = make_chain(entity_id="bob::ws02")
        r = ChainReport(graph_id="g1", chains=[c1, c2])
        assert r.statistics.entities_affected == 2

    def test_to_summary_keys(self) -> None:
        r = ChainReport(graph_id="g1", chains=[make_chain()])
        s = r.to_summary()
        for k in ("report_id", "graph_id", "total_chains", "avg_confidence"):
            assert k in s

    def test_json_round_trip(self) -> None:
        r = ChainReport(graph_id="g1", chains=[make_chain("c-rt")])
        reloaded = ChainReport.model_validate_json(r.model_dump_json())
        assert reloaded.report_id == r.report_id
        assert len(reloaded.chains) == 1
