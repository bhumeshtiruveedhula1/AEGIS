"""tests/unit/orchestrator/test_models.py — Model serialization and contract tests."""

from __future__ import annotations

import json

from backend.orchestrator.models import (
    ORCHESTRATOR_SCHEMA_VERSION,
    ApprovalRecord,
    BlastRadiusReport,
    ExecutionResult,
    OrchestratorAuditEvent,
    OrchestratorRecord,
    PlaybookAction,
    ResponsePlaybook,
)
from tests.unit.orchestrator.conftest import make_approval, make_playbook, make_record


class TestPlaybookAction:
    def test_round_trip(self) -> None:
        action = PlaybookAction(
            action_type="isolate_host",
            description="Isolate.",
            rollback_description="Remove rule.",
            estimated_duration_s=10,
        )
        restored = PlaybookAction.model_validate_json(action.model_dump_json())
        assert restored.action_type == "isolate_host"
        assert restored.estimated_duration_s == 10

    def test_parameters_default_empty(self) -> None:
        action = PlaybookAction(action_type="observe_only", description="obs")
        assert action.parameters == {}


class TestResponsePlaybook:
    def test_round_trip(self) -> None:
        pb = make_playbook()
        restored = ResponsePlaybook.model_validate_json(pb.model_dump_json())
        assert restored.playbook_id == pb.playbook_id

    def test_empty_trigger_lists(self) -> None:
        pb = make_playbook()
        assert pb.trigger_tactics == []
        assert pb.trigger_techniques == []

    def test_json_has_required_fields(self) -> None:
        pb = make_playbook()
        data = json.loads(pb.model_dump_json())
        for field in ("playbook_id", "name", "severity_threshold", "actions"):
            assert field in data


class TestBlastRadiusReport:
    def test_round_trip(self) -> None:
        report = BlastRadiusReport(
            affected_hosts=["h1", "h2"],
            affected_users=["alice"],
            estimated_scope="LATERAL",
        )
        restored = BlastRadiusReport.model_validate_json(report.model_dump_json())
        assert restored.estimated_scope == "LATERAL"
        assert restored.affected_hosts == ["h1", "h2"]

    def test_defaults(self) -> None:
        report = BlastRadiusReport()
        assert report.estimated_scope == "UNKNOWN"
        assert report.baseline_available is True


class TestApprovalRecord:
    def test_default_status_pending(self) -> None:
        record = make_approval()
        assert record.status == "PENDING"

    def test_round_trip(self) -> None:
        record = make_approval()
        restored = ApprovalRecord.model_validate_json(record.model_dump_json())
        assert restored.approval_id == record.approval_id
        assert restored.status == "PENDING"

    def test_decided_at_none_on_pending(self) -> None:
        record = make_approval()
        assert record.decided_at is None


class TestExecutionResult:
    def test_default_outcome_not_executed(self) -> None:
        result = ExecutionResult(orchestration_id="orch-x", playbook_id="pb-x")
        assert result.outcome == "NOT_EXECUTED"
        assert result.simulated is True

    def test_round_trip(self) -> None:
        result = ExecutionResult(
            orchestration_id="orch-x",
            playbook_id="pb-x",
            outcome="SIMULATED_SUCCESS",
        )
        restored = ExecutionResult.model_validate_json(result.model_dump_json())
        assert restored.outcome == "SIMULATED_SUCCESS"


class TestOrchestratorRecord:
    def test_schema_version(self) -> None:
        record = make_record()
        assert record.schema_version == ORCHESTRATOR_SCHEMA_VERSION

    def test_round_trip(self) -> None:
        record = make_record()
        restored = OrchestratorRecord.model_validate_json(record.model_dump_json())
        assert restored.orchestration_id == record.orchestration_id
        assert restored.approval.status == "PENDING"

    def test_to_summary_keys(self) -> None:
        record = make_record()
        summary = record.to_summary()
        for key in (
            "orchestration_id",
            "context_id",
            "alert_id",
            "playbook_id",
            "approval_status",
            "execution_outcome",
            "blast_radius_scope",
        ):
            assert key in summary

    def test_to_summary_execution_outcome_default(self) -> None:
        record = make_record()
        assert record.to_summary()["execution_outcome"] == "NOT_EXECUTED"

    def test_audit_trail_starts_empty(self) -> None:
        record = make_record()
        assert record.audit_trail == []


class TestOrchestratorAuditEvent:
    def test_round_trip(self) -> None:
        evt = OrchestratorAuditEvent(
            orchestration_id="orch-1",
            alert_id="alert-1",
            event_type="playbook_selected",
            actor="system",
        )
        restored = OrchestratorAuditEvent.model_validate_json(evt.model_dump_json())
        assert restored.event_type == "playbook_selected"
        assert restored.event_id == evt.event_id

    def test_default_actor_is_system(self) -> None:
        evt = OrchestratorAuditEvent(orchestration_id="o", alert_id="a", event_type="test")
        assert evt.actor == "system"
