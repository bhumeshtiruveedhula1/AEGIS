"""
backend.orchestrator.executor — Mock Response Executor
=======================================================
Module 6.1 — Response Orchestrator

Simulates playbook execution. No real infrastructure actions.
No external integrations. No destructive operations.

Every action in the playbook is simulated in order and produces a
SimulatedActionResult. Execution is deterministic — same inputs produce
same outputs. No randomness.
"""

from __future__ import annotations

from datetime import UTC, datetime

import structlog

from backend.orchestrator.exceptions import ExecutionError
from backend.orchestrator.models import (
    ExecutionResult,
    OrchestratorRecord,
    SimulatedActionResult,
)

logger = structlog.get_logger(__name__)


class MockExecutor:
    """
    Simulates response playbook execution.

    Stateless — no shared mutable state.
    Thread-safe by design.
    """

    def execute(self, record: OrchestratorRecord) -> ExecutionResult:
        """
        Simulate execution of all actions in the orchestration record's playbook.

        Parameters
        ----------
        record : OrchestratorRecord — must have approval.status == "APPROVED".

        Returns
        -------
        ExecutionResult with all actions simulated.

        Raises
        ------
        ExecutionError if record is not in APPROVED state.
        """
        if record.approval.status != "APPROVED":
            raise ExecutionError(
                f"Cannot execute orchestration {record.orchestration_id}: "
                f"approval status is {record.approval.status!r}, expected APPROVED.",
                context={
                    "orchestration_id": record.orchestration_id,
                    "approval_status": record.approval.status,
                },
            )

        started_at = datetime.now(UTC)
        action_results: list[SimulatedActionResult] = []

        for action in record.playbook.actions:
            result = SimulatedActionResult(
                action_type=action.action_type,
                description=action.description,
                simulated=True,
                outcome="OK",
                detail=(
                    f"[SIMULATED] {action.description} "
                    f"(rollback: {action.rollback_description or 'none'})"
                ),
            )
            action_results.append(result)
            logger.debug(
                "action_simulated",
                orchestration_id=record.orchestration_id,
                action_type=action.action_type,
            )

        completed_at = datetime.now(UTC)

        # Determine overall outcome
        outcomes = {r.outcome for r in action_results}
        if not action_results:
            overall_outcome = "SIMULATED_FAILURE"
        elif "FAILED" in outcomes:
            overall_outcome = "SIMULATED_PARTIAL"
        else:
            overall_outcome = "SIMULATED_SUCCESS"

        execution = ExecutionResult(
            orchestration_id=record.orchestration_id,
            playbook_id=record.playbook.playbook_id,
            simulated=True,
            outcome=overall_outcome,  # type: ignore[arg-type]
            actions_simulated=action_results,
            started_at=started_at,
            completed_at=completed_at,
        )

        logger.info(
            "execution_complete",
            orchestration_id=record.orchestration_id,
            playbook_id=record.playbook.playbook_id,
            outcome=overall_outcome,
            action_count=len(action_results),
            duration_ms=round((completed_at - started_at).total_seconds() * 1000, 2),
        )

        return execution
