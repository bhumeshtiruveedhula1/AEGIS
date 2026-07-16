"""
backend.orchestrator — Response Orchestrator
============================================
Module 6.1 — Response Orchestrator

Deterministic response orchestration layer consuming AttackContext.

Public API
----------
    from backend.orchestrator import OrchestratorService, OrchestratorRecord
    from backend.orchestrator import ResponsePlaybook, BlastRadiusReport, ApprovalRecord

Entry point
-----------
    svc = OrchestratorService()
    record = svc.orchestrate(context)          # select playbook, compute blast radius, create pending approval
    record = svc.approve(orchestration_id, decided_by="analyst@soc.com")
    record = svc.execute(orchestration_id)     # simulated only — no real infrastructure actions
"""

from __future__ import annotations

from backend.orchestrator.exceptions import (
    ApprovalAlreadyProcessedError,
    ApprovalExpiredError,
    ExecutionError,
    OrchestratorError,
    OrchestratorSchemaError,
    OrchestratorStorageError,
    PlaybookNotFoundError,
)
from backend.orchestrator.models import (
    ORCHESTRATOR_SCHEMA_VERSION,
    ApprovalRecord,
    BlastRadiusReport,
    ExecutionResult,
    OrchestratorAuditEvent,
    OrchestratorRecord,
    PlaybookAction,
    ResponsePlaybook,
    SimulatedActionResult,
)
from backend.orchestrator.playbooks import PlaybookRegistry, get_playbook_registry
from backend.orchestrator.service import OrchestratorService

__all__ = [
    # Service
    "OrchestratorService",
    # Models
    "OrchestratorRecord",
    "ResponsePlaybook",
    "PlaybookAction",
    "BlastRadiusReport",
    "ApprovalRecord",
    "ExecutionResult",
    "SimulatedActionResult",
    "OrchestratorAuditEvent",
    "ORCHESTRATOR_SCHEMA_VERSION",
    # Playbooks
    "PlaybookRegistry",
    "get_playbook_registry",
    # Exceptions
    "OrchestratorError",
    "PlaybookNotFoundError",
    "ApprovalExpiredError",
    "ApprovalAlreadyProcessedError",
    "ExecutionError",
    "OrchestratorStorageError",
    "OrchestratorSchemaError",
]
