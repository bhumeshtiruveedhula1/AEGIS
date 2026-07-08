"""tests/unit/context/conftest.py — Shared context test fixtures."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from backend.attack_graph.models import AttackGraph, GraphStatistics
from backend.chain_detection.models import (
    AttackChain,
    ChainEvidence,
    ChainEvaluation,
    ChainLink,
    ChainNode,
)
from backend.context.service import AttackContextService
from backend.context.storage import ContextStore
from backend.detection.models import DetectionAlert, EntityKey
from backend.explainability.models import ExplanationResult, FeatureContribution
from backend.mitre.models import MappedAttack, TechniqueMapping
from backend.normalization.models import CanonicalEvent

BASE_TS = datetime(2024, 6, 10, 10, 0, 0, tzinfo=UTC)


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_alert(
    entity_type: str = "user",
    entity_id: str = "alice",
    anomaly_score: float = 0.85,
    event_host: str = "ws01",
    event_user: str = "alice",
) -> DetectionAlert:
    return DetectionAlert(
        model_id="iso-v1",
        entity_key=EntityKey(entity_type=entity_type, entity_id=entity_id),
        event_id="evt-001",
        event_type="authentication",
        event_source="windows",
        event_timestamp=BASE_TS,
        event_host=event_host,
        event_user=event_user,
        anomaly_score=anomaly_score,
        raw_if_score=-0.12,
        threshold_used=0.5,
        is_alert=True,
        feature_dimension=10,
        raw_feature_values={"failed_logins": 20.0, "hour_of_day": 3.0},
        novelty_count=2,
        baseline_available=True,
    )


def make_explanation(alert: DetectionAlert) -> ExplanationResult:
    from backend.explainability.models import FeatureContribution
    contrib = FeatureContribution(
        feature_name="failed_logins",
        raw_value=20.0,
        shap_value=0.4,
        abs_shap_value=0.4,
        contribution_rank=1,
        contribution_pct=80.0,
        direction="anomaly",  # must be 'anomaly' or 'normal' per FeatureContribution schema
    )
    return ExplanationResult(
        alert_id=alert.alert_id,
        model_id=alert.model_id,
        entity_type="user",
        entity_id="alice",
        event_id=alert.event_id,
        anomaly_score=alert.anomaly_score,
        expected_value=0.1,
        total_abs_shap=0.5,
        feature_contributions=[contrib],
        top_features=["failed_logins"],
        raw_feature_values={"failed_logins": 20.0},
    )


def make_graph() -> AttackGraph:
    stats = GraphStatistics(
        node_count=5,
        edge_count=4,
        technique_count=3,
        tactic_count=2,
        alert_count=1,
        entity_count=1,
        is_dag=True,
        tactic_distribution={"TA0006": 2, "TA0008": 1},
        technique_distribution={"T1110": 2, "T1021": 1},
    )
    return AttackGraph(
        source_model_id="iso-v1",
        mapped_attack_ids=["map-001"],
        statistics=stats,
    )


def make_chain(alert: DetectionAlert) -> AttackChain:
    node1 = ChainNode(
        chain_node_id="n1",
        technique_id="T1110",
        technique_name="Brute Force",
        tactic_id="TA0006",
        tactic_name="Credential Access",
        entity_id="alice",
        entity_type="user",
        confidence=0.9,
        observation_count=20,
        first_seen=BASE_TS,
        last_seen=BASE_TS,
        step_index=0,
    )
    node2 = ChainNode(
        chain_node_id="n2",
        technique_id="T1021",
        technique_name="Remote Services",
        tactic_id="TA0008",
        tactic_name="Lateral Movement",
        entity_id="alice",
        entity_type="user",
        confidence=0.75,
        observation_count=5,
        first_seen=BASE_TS,
        last_seen=BASE_TS,
        step_index=1,
    )
    link = ChainLink(
        source_node_id="n1",
        target_node_id="n2",
        link_type="precedes",
    )
    evidence = ChainEvidence(
        alert_ids=[alert.alert_id],
        mapping_ids=["map-001"],
        tactic_sequence=["Credential Access", "Lateral Movement"],
        technique_ids=["T1110", "T1021"],
        matched_features=["failed_logins"],
        total_observations=25,
    )
    evaluation = ChainEvaluation(
        confidence=0.82,
        avg_step_confidence=0.825,
        tactic_coverage_ratio=0.143,
        temporal_consistency_score=1.0,
        observation_strength=0.5,
        is_multi_tactic=True,
        is_temporally_ordered=True,
        chain_length=2,
        tactic_count=2,
    )
    return AttackChain(
        graph_id="graph-001",
        entity_id="alice",
        entity_type="user",
        nodes=[node1, node2],
        links=[link],
        evidence=evidence,
        evaluation=evaluation,
    )


def make_canonical_event(host: str = "ws01", src_ip: str | None = None) -> CanonicalEvent:
    return CanonicalEvent(
        event_id="evt-canon-001",
        timestamp=BASE_TS,
        source="windows",
        event_type="authentication",
        host=host,
        user="alice",
        resource="ws01",
        action="logon_failure",
        result="failure",
        raw_log="source=windows action=logon_failure",
        src_ip=src_ip,
        logon_type="network",
        auth_package="NTLM",
        windows_event_id=4625,
    )


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture()
def alert() -> DetectionAlert:
    return make_alert()


@pytest.fixture()
def explanation(alert: DetectionAlert) -> ExplanationResult:
    return make_explanation(alert)


@pytest.fixture()
def graph() -> AttackGraph:
    return make_graph()


@pytest.fixture()
def chain(alert: DetectionAlert) -> AttackChain:
    return make_chain(alert)


@pytest.fixture()
def events() -> list[CanonicalEvent]:
    return [
        make_canonical_event("ws01", "10.0.0.1"),
        make_canonical_event("ws02"),
    ]


@pytest.fixture()
def store(tmp_path: Path) -> ContextStore:
    return ContextStore(store_dir=tmp_path / "ctx_store")


@pytest.fixture()
def svc(tmp_path: Path) -> AttackContextService:
    return AttackContextService(
        store_dir=tmp_path / "ctx_svc",
        persist=False,
    )


@pytest.fixture()
def svc_persist(tmp_path: Path) -> AttackContextService:
    return AttackContextService(
        store_dir=tmp_path / "ctx_persist",
        persist=True,
    )
