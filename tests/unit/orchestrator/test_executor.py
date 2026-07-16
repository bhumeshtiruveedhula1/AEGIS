"""tests/unit/orchestrator/test_executor.py — Mock executor tests."""

from __future__ import annotations

import pytest

from backend.orchestrator.exceptions import ExecutionError
from backend.orchestrator.executor import MockExecutor
from backend.orchestrator.models import ExecutionResult
from tests.unit.orchestrator.conftest import make_record


class TestMockExecutor:
    def setup_method(self) -> None:
        self.executor = MockExecutor()

    def test_execute_approved_record(self, approved_record) -> None:
        result = self.executor.execute(approved_record)
        assert isinstance(result, ExecutionResult)
        assert result.simulated is True

    def test_outcome_simulated_success(self, approved_record) -> None:
        result = self.executor.execute(approved_record)
        assert result.outcome == "SIMULATED_SUCCESS"

    def test_all_actions_simulated(self, approved_record) -> None:
        result = self.executor.execute(approved_record)
        expected_count = len(approved_record.playbook.actions)
        assert len(result.actions_simulated) == expected_count

    def test_each_action_is_simulated(self, approved_record) -> None:
        result = self.executor.execute(approved_record)
        for action_result in result.actions_simulated:
            assert action_result.simulated is True
            assert action_result.outcome == "OK"

    def test_execution_id_unique_per_run(self, approved_record) -> None:
        r1 = self.executor.execute(approved_record)
        r2 = self.executor.execute(approved_record)
        assert r1.execution_id != r2.execution_id

    def test_started_and_completed_at_set(self, approved_record) -> None:
        result = self.executor.execute(approved_record)
        assert result.started_at is not None
        assert result.completed_at is not None
        assert result.completed_at >= result.started_at

    def test_pending_record_raises_execution_error(self, pending_record) -> None:
        with pytest.raises(ExecutionError) as exc_info:
            self.executor.execute(pending_record)
        assert "PENDING" in str(exc_info.value)

    def test_rejected_record_raises_execution_error(self) -> None:
        record = make_record(status="REJECTED")
        with pytest.raises(ExecutionError):
            self.executor.execute(record)

    def test_orchestration_id_in_result(self, approved_record) -> None:
        result = self.executor.execute(approved_record)
        assert result.orchestration_id == approved_record.orchestration_id

    def test_playbook_id_in_result(self, approved_record) -> None:
        result = self.executor.execute(approved_record)
        assert result.playbook_id == approved_record.playbook.playbook_id

    def test_action_types_match_playbook(self, approved_record) -> None:
        result = self.executor.execute(approved_record)
        expected_types = [a.action_type for a in approved_record.playbook.actions]
        actual_types = [r.action_type for r in result.actions_simulated]
        assert actual_types == expected_types
