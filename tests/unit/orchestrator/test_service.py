"""
tests/unit/orchestrator/test_service.py — OrchestratorService integration tests.

Tests the full orchestration workflow:
  orchestrate → approve/reject → execute
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

import pytest

from backend.orchestrator.exceptions import ExecutionError
from backend.orchestrator.models import OrchestratorRecord
from backend.orchestrator.service import OrchestratorService
from tests.unit.orchestrator.conftest import make_context


@pytest.fixture()
def svc(tmp_path: Path) -> OrchestratorService:
    return OrchestratorService(
        store_dir=tmp_path / "orchestrator",
        audit_dir=tmp_path / "orchestrator" / "audit",
        approval_ttl_s=3600,
    )


class TestOrchestratorServiceOrchestrate:
    def test_returns_orchestrator_record(self, svc, ctx) -> None:
        record = svc.orchestrate(ctx)
        assert isinstance(record, OrchestratorRecord)

    def test_approval_status_is_pending(self, svc, ctx) -> None:
        record = svc.orchestrate(ctx)
        assert record.approval.status == "PENDING"

    def test_context_id_set(self, svc, ctx) -> None:
        record = svc.orchestrate(ctx)
        assert record.context_id == ctx.context_id

    def test_alert_id_set(self, svc, ctx) -> None:
        record = svc.orchestrate(ctx)
        assert record.alert_id == ctx.identity.alert_id

    def test_entity_id_set(self, svc, ctx) -> None:
        record = svc.orchestrate(ctx)
        assert record.entity_id == ctx.identity.entity_id

    def test_playbook_selected(self, svc, ctx) -> None:
        record = svc.orchestrate(ctx)
        assert record.playbook.playbook_id is not None

    def test_blast_radius_computed(self, svc, ctx) -> None:
        record = svc.orchestrate(ctx)
        assert record.blast_radius.estimated_scope != ""

    def test_audit_trail_has_events(self, svc, ctx) -> None:
        record = svc.orchestrate(ctx)
        assert len(record.audit_trail) >= 2  # playbook_selected + approval_requested

    def test_record_persisted(self, svc, ctx) -> None:
        record = svc.orchestrate(ctx)
        loaded = svc.get(record.orchestration_id)
        assert loaded.orchestration_id == record.orchestration_id

    def test_orchestrate_ot_context(self, svc, ctx_ot) -> None:
        record = svc.orchestrate(ctx_ot)
        assert record.playbook.playbook_id == "ot_containment"

    def test_orchestrate_low_score_observe_only(self, svc, ctx_low_score) -> None:
        record = svc.orchestrate(ctx_low_score)
        assert record.playbook.playbook_id == "observe_only"


class TestOrchestratorServiceApprove:
    def test_approve_sets_approved(self, svc, ctx) -> None:
        record = svc.orchestrate(ctx)
        approved = svc.approve(record.orchestration_id, decided_by="analyst@soc.com")
        assert approved.approval.status == "APPROVED"

    def test_approve_sets_decided_by(self, svc, ctx) -> None:
        record = svc.orchestrate(ctx)
        approved = svc.approve(record.orchestration_id, decided_by="analyst@soc.com")
        assert approved.approval.decided_by == "analyst@soc.com"

    def test_approve_adds_audit_event(self, svc, ctx) -> None:
        record = svc.orchestrate(ctx)
        initial_audit_count = len(record.audit_trail)
        approved = svc.approve(record.orchestration_id, decided_by="analyst@soc.com")
        assert len(approved.audit_trail) > initial_audit_count

    def test_approve_persists_state(self, svc, ctx) -> None:
        record = svc.orchestrate(ctx)
        svc.approve(record.orchestration_id, decided_by="bob")
        loaded = svc.get(record.orchestration_id)
        assert loaded.approval.status == "APPROVED"


class TestOrchestratorServiceReject:
    def test_reject_sets_rejected(self, svc, ctx) -> None:
        record = svc.orchestrate(ctx)
        rejected = svc.reject(record.orchestration_id, decided_by="analyst", reason="FP")
        assert rejected.approval.status == "REJECTED"

    def test_reject_reason_preserved(self, svc, ctx) -> None:
        record = svc.orchestrate(ctx)
        rejected = svc.reject(
            record.orchestration_id, decided_by="analyst", reason="False positive"
        )
        assert rejected.approval.reason == "False positive"

    def test_reject_persists_state(self, svc, ctx) -> None:
        record = svc.orchestrate(ctx)
        svc.reject(record.orchestration_id, decided_by="analyst")
        loaded = svc.get(record.orchestration_id)
        assert loaded.approval.status == "REJECTED"


class TestOrchestratorServiceExecute:
    def test_execute_approved_returns_record(self, svc, ctx) -> None:
        record = svc.orchestrate(ctx)
        svc.approve(record.orchestration_id, decided_by="analyst")
        executed = svc.execute(record.orchestration_id)
        assert executed.execution is not None

    def test_execute_outcome_simulated_success(self, svc, ctx) -> None:
        record = svc.orchestrate(ctx)
        svc.approve(record.orchestration_id, decided_by="analyst")
        executed = svc.execute(record.orchestration_id)
        assert executed.execution.outcome == "SIMULATED_SUCCESS"

    def test_execute_pending_raises(self, svc, ctx) -> None:
        record = svc.orchestrate(ctx)
        with pytest.raises(ExecutionError):
            svc.execute(record.orchestration_id)

    def test_execute_rejected_raises(self, svc, ctx) -> None:
        record = svc.orchestrate(ctx)
        svc.reject(record.orchestration_id, decided_by="analyst")
        with pytest.raises(ExecutionError):
            svc.execute(record.orchestration_id)

    def test_execute_adds_audit_events(self, svc, ctx) -> None:
        record = svc.orchestrate(ctx)
        svc.approve(record.orchestration_id, decided_by="analyst")
        executed = svc.execute(record.orchestration_id)
        types = [e.event_type for e in executed.audit_trail]
        assert "execution_started" in types
        assert "execution_complete" in types

    def test_execute_persists_execution(self, svc, ctx) -> None:
        record = svc.orchestrate(ctx)
        svc.approve(record.orchestration_id, decided_by="analyst")
        svc.execute(record.orchestration_id)
        loaded = svc.get(record.orchestration_id)
        assert loaded.execution is not None


class TestOrchestratorServiceQuery:
    def test_list_ids_returns_orchestration(self, svc, ctx) -> None:
        record = svc.orchestrate(ctx)
        ids = svc.list_ids()
        assert record.orchestration_id in ids

    def test_list_by_alert(self, svc, ctx) -> None:
        record = svc.orchestrate(ctx)
        results = svc.list_by_alert(record.alert_id)
        assert any(r.orchestration_id == record.orchestration_id for r in results)

    def test_multiple_orchestrations_independent(self, svc) -> None:
        ctx1 = make_context(entity_id="alice")
        ctx2 = make_context(entity_id="bob")
        r1 = svc.orchestrate(ctx1)
        r2 = svc.orchestrate(ctx2)
        assert r1.orchestration_id != r2.orchestration_id
        loaded1 = svc.get(r1.orchestration_id)
        loaded2 = svc.get(r2.orchestration_id)
        assert loaded1.entity_id == "alice"
        assert loaded2.entity_id == "bob"
