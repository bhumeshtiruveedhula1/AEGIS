"""tests/unit/orchestrator/conftest.py — Shared orchestrator test fixtures."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

import pytest

from backend.context.models import (
    AttackContext,
    BehavioralSummary,
    ChainSummary,
    ContextCompleteness,
    ContextIdentity,
    DetectionSummary,
    GraphSummary,
    MitreSummary,
    StatisticalSummary,
    SupportingEvidence,
)
from backend.orchestrator.models import (
    ApprovalRecord,
    BlastRadiusReport,
    OrchestratorRecord,
    PlaybookAction,
    ResponsePlaybook,
)
from backend.orchestrator.playbooks import PlaybookRegistry

BASE_TS = datetime(2024, 6, 10, 10, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# AttackContext helpers
# ---------------------------------------------------------------------------


def make_context(
    anomaly_score: float = 0.75,
    tactic_ids: list[str] | None = None,
    technique_ids: list[str] | None = None,
    has_chain: bool = False,
    has_graph: bool = False,
    has_ot: bool = False,
    host: str = "ws-01",
    user: str = "alice",
    entity_type: str = "user",
    entity_id: str = "alice",
    baseline_available: bool = True,
) -> AttackContext:
    mitre = MitreSummary(
        all_tactic_ids=tactic_ids or [],
        all_technique_ids=technique_ids or [],
        technique_count=len(technique_ids or []),
        tactic_count=len(tactic_ids or []),
    )
    graph = (
        GraphSummary(
            graph_id="g-001",
            node_count=4,
            edge_count=3,
            technique_count=2,
            tactic_count=1,
            alert_count=1,
            entity_count=2,
            is_dag=True,
        )
        if has_graph
        else None
    )

    chain = (
        ChainSummary(
            chain_id="chain-001",
            chain_length=3,
            confidence=0.7,
            tactic_sequence=["TA0001", "TA0008"],
            technique_sequence=["T1078", "T1021"],
            tactic_count=2,
            is_multi_tactic=True,
            is_temporally_ordered=True,
            observation_strength=0.6,
            matched_alert_ids=["alert-001", "alert-002"],
            matched_features=["failed_logins"],
            total_observations=3,
        )
        if has_chain
        else None
    )

    evidence = SupportingEvidence(
        affected_hosts=[host],
        affected_users=[user],
        has_ot_indicators=has_ot,
    )

    behavioral = BehavioralSummary(
        entity_key=f"{entity_type}::{entity_id}",
        baseline_available=baseline_available,
        novel_features=[],
        novelty_count=0,
        feature_dimension=10,
    )

    return AttackContext(
        identity=ContextIdentity(
            alert_id="alert-001",
            entity_type=entity_type,
            entity_id=entity_id,
            host=host,
            user=user,
        ),
        detection=DetectionSummary(
            model_id="iso-v1",
            anomaly_score=anomaly_score,
            threshold_used=0.46,
            raw_if_score=-0.12,
            feature_dimension=10,
            novelty_count=2,
            baseline_available=baseline_available,
            detection_timestamp=BASE_TS,
        ),
        mitre=mitre,
        graph=graph,
        chain=chain,
        evidence=evidence,
        behavioral=behavioral,
        statistical=StatisticalSummary(
            anomaly_score=anomaly_score,
            feature_count=10,
            baseline_coverage=1.0 if baseline_available else 0.0,
        ),
        completeness=ContextCompleteness(completeness_pct=80.0),
    )


def make_playbook(
    playbook_id: str = "test_pb",
    severity_threshold: float = 0.5,
    requires_chain: bool = False,
    trigger_tactics: list[str] | None = None,
    trigger_techniques: list[str] | None = None,
) -> ResponsePlaybook:
    return ResponsePlaybook(
        playbook_id=playbook_id,
        name="Test Playbook",
        description="Test playbook for unit tests.",
        severity_threshold=severity_threshold,
        requires_chain=requires_chain,
        trigger_tactics=trigger_tactics or [],
        trigger_techniques=trigger_techniques or [],
        actions=[
            PlaybookAction(
                action_type="observe_only",
                description="Test action.",
                rollback_description="N/A",
            )
        ],
    )


def make_approval(
    orchestration_id: str = "orch-test",
    status: str = "PENDING",
) -> ApprovalRecord:
    return ApprovalRecord(
        orchestration_id=orchestration_id,
        status=status,  # type: ignore[arg-type]
        ttl_seconds=3600,
    )


def make_record(
    context: AttackContext | None = None,
    status: str = "PENDING",
) -> OrchestratorRecord:
    ctx = context or make_context()
    playbook = make_playbook()
    blast = BlastRadiusReport(
        affected_hosts=["ws-01"],
        affected_users=["alice"],
        affected_entity_ids=["alice"],
        alert_ids_in_scope=["alert-001"],
        estimated_scope="SINGLE_HOST",
    )
    approval = make_approval(status=status)
    return OrchestratorRecord(
        context_id=ctx.context_id,
        alert_id=ctx.identity.alert_id,
        entity_id=ctx.identity.entity_id,
        entity_type=ctx.identity.entity_type,
        playbook=playbook,
        blast_radius=blast,
        approval=approval,
    )


# ---------------------------------------------------------------------------
# Pytest fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def ctx() -> AttackContext:
    return make_context()


@pytest.fixture()
def ctx_with_chain() -> AttackContext:
    return make_context(
        has_chain=True,
        has_graph=True,
        anomaly_score=0.8,
        tactic_ids=["TA0008"],
        technique_ids=["T1021"],
    )


@pytest.fixture()
def ctx_ot() -> AttackContext:
    return make_context(has_ot=True, anomaly_score=0.6)


@pytest.fixture()
def ctx_low_score() -> AttackContext:
    return make_context(anomaly_score=0.2)


@pytest.fixture()
def registry() -> PlaybookRegistry:
    return PlaybookRegistry()


@pytest.fixture()
def pending_record() -> OrchestratorRecord:
    return make_record(status="PENDING")


@pytest.fixture()
def approved_record() -> OrchestratorRecord:
    return make_record(status="APPROVED")


@pytest.fixture()
def tmp_store_dir(tmp_path: Path) -> Path:
    return tmp_path / "orchestrator"
