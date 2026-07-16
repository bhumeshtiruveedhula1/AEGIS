"""backend.orchestrator.exceptions — Response Orchestrator Exception Hierarchy."""

from __future__ import annotations

from backend.core.exceptions import ResponseEngineError


class OrchestratorError(ResponseEngineError):
    """Base class for all Response Orchestrator errors."""

    http_status_code = 500
    error_code = "orchestrator_error"


class PlaybookNotFoundError(OrchestratorError):
    """Raised when no playbook matches the given AttackContext."""

    http_status_code = 404
    error_code = "playbook_not_found"


class ApprovalExpiredError(OrchestratorError):
    """Raised when an approval record has passed its TTL without a decision."""

    http_status_code = 410
    error_code = "approval_expired"


class ApprovalAlreadyProcessedError(OrchestratorError):
    """Raised when attempting to approve/reject an already-decided record."""

    http_status_code = 409
    error_code = "approval_already_processed"


class ExecutionError(OrchestratorError):
    """Raised when mock execution fails to produce a structured result."""

    http_status_code = 500
    error_code = "execution_error"


class OrchestratorStorageError(OrchestratorError):
    """Raised on I/O failure persisting or loading orchestrator records."""

    http_status_code = 500
    error_code = "orchestrator_storage_error"


class OrchestratorSchemaError(OrchestratorError):
    """Raised on schema version mismatch when loading a persisted record."""

    http_status_code = 500
    error_code = "orchestrator_schema_error"
