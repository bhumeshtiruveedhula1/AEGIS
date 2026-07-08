"""tests/unit/chain_detection/conftest.py — Shared Chain Detection Fixtures."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from backend.attack_graph.graph_builder import AttackGraphBuilder
from backend.attack_graph.models import GraphSnapshot
from backend.chain_detection.models import (
    AttackChain,
    ChainEvidence,
    ChainEvaluation,
    ChainLink,
    ChainNode,
)
from backend.mitre.models import (
    AttackTactic,
    AttackTechnique,
    MappedAttack,
    TechniqueMapping,
)

BASE_TS = datetime(2024, 6, 10, 10, 0, tzinfo=UTC)


def _tactic(tid: str, name: str) -> AttackTactic:
    return AttackTactic(tactic_id=tid, name=name, short_name=name.lower().replace(" ", "-"))


def _technique(tid: str, tactic: AttackTactic) -> AttackTechnique:
    return AttackTechnique(technique_id=tid, name=f"Technique {tid}", tactic=tactic)


def _tm(tid: str, tac_id: str, tac_name: str, conf: float = 0.75) -> TechniqueMapping:
    tac = _tactic(tac_id, tac_name)
    return TechniqueMapping(
        technique=_technique(tid, tac),
        confidence=conf,
        evidence=["test"],
        matched_features=[f"feat_{tid}"],
        shap_contributors=[f"feat_{tid}"],
        shap_total_contribution=0.4,
    )


def make_mapped_attack(
    mapping_id: str,
    alert_id: str,
    entity_id: str,
    techniques: list[TechniqueMapping],
    ts: datetime | None = None,
) -> MappedAttack:
    t = ts or BASE_TS
    return MappedAttack(
        mapping_id=mapping_id,
        alert_id=alert_id,
        model_id="iforest-cd-test",
        entity_type="user_host",
        entity_id=entity_id,
        event_id=f"evt-{alert_id}",
        anomaly_score=0.82,
        techniques=techniques,
        mapped_at=t,
    )


def make_linear_snapshot(entity_id: str = "alice::ws01") -> GraphSnapshot:
    """
    Build a graph with a clear 3-step attack chain for entity_id:
      T1110 (Credential Access) -> T1059 (Execution) -> T1041 (Exfiltration)
    """
    mappings = [
        make_mapped_attack(
            "map-a", "alert-a", entity_id,
            [_tm("T1110", "TA0006", "Credential Access", 0.80)],
            ts=BASE_TS,
        ),
        make_mapped_attack(
            "map-b", "alert-b", entity_id,
            [_tm("T1059", "TA0002", "Execution", 0.70)],
            ts=BASE_TS + timedelta(hours=1),
        ),
        make_mapped_attack(
            "map-c", "alert-c", entity_id,
            [_tm("T1041", "TA0010", "Exfiltration", 0.65)],
            ts=BASE_TS + timedelta(hours=2),
        ),
    ]
    builder = AttackGraphBuilder(graph_id="snap-linear")
    builder.add_batch(mappings)
    _, snapshot = builder.build()
    return snapshot


def make_multi_entity_snapshot() -> GraphSnapshot:
    """Two entities, each with a 2-step chain."""
    mappings = [
        make_mapped_attack(
            "map-e1a", "alert-e1a", "alice::ws01",
            [_tm("T1110", "TA0006", "Credential Access", 0.80)],
            ts=BASE_TS,
        ),
        make_mapped_attack(
            "map-e1b", "alert-e1b", "alice::ws01",
            [_tm("T1059", "TA0002", "Execution", 0.70)],
            ts=BASE_TS + timedelta(hours=1),
        ),
        make_mapped_attack(
            "map-e2a", "alert-e2a", "bob::ws02",
            [_tm("T1078", "TA0001", "Initial Access", 0.75)],
            ts=BASE_TS,
        ),
        make_mapped_attack(
            "map-e2b", "alert-e2b", "bob::ws02",
            [_tm("T1041", "TA0010", "Exfiltration", 0.65)],
            ts=BASE_TS + timedelta(hours=1),
        ),
    ]
    builder = AttackGraphBuilder(graph_id="snap-multi")
    builder.add_batch(mappings)
    _, snapshot = builder.build()
    return snapshot


def make_single_step_snapshot(entity_id: str = "solo::host") -> GraphSnapshot:
    """Single technique — below MIN_CHAIN_LENGTH, should yield no chains."""
    mappings = [
        make_mapped_attack(
            "map-solo", "alert-solo", entity_id,
            [_tm("T1110", "TA0006", "Credential Access", 0.80)],
        ),
    ]
    builder = AttackGraphBuilder(graph_id="snap-solo")
    builder.add_batch(mappings)
    _, snapshot = builder.build()
    return snapshot


def make_empty_snapshot() -> GraphSnapshot:
    builder = AttackGraphBuilder(graph_id="snap-empty")
    _, snapshot = builder.build()
    return snapshot


def _make_chain_node(
    tid: str = "T1110",
    tac_id: str = "TA0006",
    tac_name: str = "Credential Access",
    conf: float = 0.75,
    step: int = 0,
    obs: int = 1,
    ts: datetime | None = None,
) -> ChainNode:
    t = ts or BASE_TS
    return ChainNode(
        chain_node_id=f"technique::{tid}::user_host::alice::ws01",
        technique_id=tid,
        technique_name=f"Technique {tid}",
        tactic_id=tac_id,
        tactic_name=tac_name,
        entity_id="alice::ws01",
        entity_type="user_host",
        confidence=conf,
        observation_count=obs,
        first_seen=t,
        last_seen=t,
        step_index=step,
    )


def _make_eval(**kwargs) -> ChainEvaluation:
    defaults = dict(
        confidence=0.6,
        avg_step_confidence=0.7,
        tactic_coverage_ratio=0.2,
        temporal_consistency_score=1.0,
        observation_strength=0.1,
    )
    defaults.update(kwargs)
    return ChainEvaluation(**defaults)


def make_chain(
    chain_id: str | None = None,
    entity_id: str = "alice::ws01",
    nodes: list[ChainNode] | None = None,
    graph_id: str = "g-test",
) -> AttackChain:
    if nodes is None:
        nodes = [
            _make_chain_node("T1110", "TA0006", "Credential Access", 0.8, 0, ts=BASE_TS),
            _make_chain_node("T1059", "TA0002", "Execution", 0.7, 1, ts=BASE_TS + timedelta(hours=1)),
        ]
    links = [
        ChainLink(
            source_node_id=nodes[i].chain_node_id,
            target_node_id=nodes[i + 1].chain_node_id,
            link_type="precedes",
        )
        for i in range(len(nodes) - 1)
    ]
    import uuid
    return AttackChain(
        chain_id=chain_id or f"chain-{uuid.uuid4().hex[:8]}",
        graph_id=graph_id,
        entity_id=entity_id,
        entity_type="user_host",
        nodes=nodes,
        links=links,
        evidence=ChainEvidence(
            tactic_sequence=[n.tactic_name for n in nodes],
            technique_ids=[n.technique_id for n in nodes],
        ),
        evaluation=_make_eval(is_multi_tactic=len({n.tactic_id for n in nodes}) > 1),
    )


@pytest.fixture()
def linear_snapshot() -> GraphSnapshot:
    return make_linear_snapshot()


@pytest.fixture()
def multi_entity_snapshot() -> GraphSnapshot:
    return make_multi_entity_snapshot()


@pytest.fixture()
def single_step_snapshot() -> GraphSnapshot:
    return make_single_step_snapshot()


@pytest.fixture()
def empty_snapshot() -> GraphSnapshot:
    return make_empty_snapshot()


@pytest.fixture()
def sample_chain() -> AttackChain:
    return make_chain()
