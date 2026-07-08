"""tests/unit/attack_graph/conftest.py — Shared Attack Graph Fixtures."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from backend.attack_graph.graph_builder import AttackGraphBuilder
from backend.attack_graph.models import AttackGraph, GraphSnapshot
from backend.mitre.models import (
    AttackTactic,
    AttackTechnique,
    MappedAttack,
    TechniqueMapping,
)

MODEL_ID = "iforest-ag-test"


def _tactic(tid: str = "TA0006", name: str = "Credential Access") -> AttackTactic:
    return AttackTactic(tactic_id=tid, name=name, short_name=name.lower().replace(" ", "-"))


def _technique(tid: str = "T1110", tactic: AttackTactic | None = None) -> AttackTechnique:
    return AttackTechnique(
        technique_id=tid,
        name=f"Technique {tid}",
        tactic=tactic or _tactic(),
    )


def _tm(
    tid: str = "T1110",
    tactic_id: str = "TA0006",
    tactic_name: str = "Credential Access",
    confidence: float = 0.75,
) -> TechniqueMapping:
    tac = _tactic(tactic_id, tactic_name)
    tech = _technique(tid, tac)
    return TechniqueMapping(
        technique=tech,
        confidence=confidence,
        evidence=["Anomaly score high."],
        matched_features=["auth_failure_rate_baseline"],
        shap_contributors=["auth_failure_rate_baseline"],
        shap_total_contribution=0.4,
    )


def make_mapped_attack(
    mapping_id: str | None = None,
    alert_id: str = "alert-001",
    entity_type: str = "user_host",
    entity_id: str = "alice::workstation-01",
    anomaly_score: float = 0.82,
    techniques: list[TechniqueMapping] | None = None,
    ts: datetime | None = None,
) -> MappedAttack:
    import uuid
    mid = mapping_id or f"map-{uuid.uuid4().hex[:8]}"
    tms = techniques or [_tm()]
    t = ts or datetime(2024, 6, 10, 10, 0, tzinfo=UTC)
    return MappedAttack(
        mapping_id=mid,
        alert_id=alert_id,
        model_id=MODEL_ID,
        entity_type=entity_type,
        entity_id=entity_id,
        event_id=f"evt-{alert_id}",
        anomaly_score=anomaly_score,
        techniques=tms,
        mapped_at=t,
    )


@pytest.fixture()
def single_mapping() -> MappedAttack:
    return make_mapped_attack()


@pytest.fixture()
def multi_mappings() -> list[MappedAttack]:
    return [
        make_mapped_attack(
            alert_id=f"alert-{i}",
            entity_id=f"user_{i % 2}::host_{i % 3}",
            anomaly_score=0.7 + i * 0.03,
            techniques=[
                _tm("T1110", "TA0006", "Credential Access", 0.8),
                _tm("T1059", "TA0002", "Execution", 0.6),
            ],
            ts=datetime(2024, 6, 10, 10 + i, 0, tzinfo=UTC),
        )
        for i in range(5)
    ]


@pytest.fixture()
def built_graph(multi_mappings) -> tuple[AttackGraph, GraphSnapshot, AttackGraphBuilder]:
    builder = AttackGraphBuilder(graph_id="test-ag-001")
    builder.add_batch(multi_mappings)
    graph, snapshot = builder.build()
    return graph, snapshot, builder
