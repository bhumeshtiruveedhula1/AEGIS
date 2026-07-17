"""backend.audit.exceptions — Audit Ledger Exception Hierarchy."""

from __future__ import annotations

from backend.core.exceptions import AuditError


class AuditLedgerError(AuditError):
    """Base for all Audit Ledger errors."""

    http_status_code = 500
    error_code = "audit_ledger_error"


class AuditStorageError(AuditLedgerError):
    """Raised on I/O failure persisting or loading audit records."""

    error_code = "audit_storage_error"


class AuditSchemaError(AuditLedgerError):
    """Raised when an audit record cannot be deserialised (schema mismatch)."""

    error_code = "audit_schema_error"


class AuditRecordNotFoundError(AuditLedgerError):
    """Raised when a requested audit record does not exist."""

    http_status_code = 404
    error_code = "audit_record_not_found"


class AuditIntegrityError(AuditLedgerError):
    """Raised when ledger integrity verification detects a problem."""

    error_code = "audit_integrity_error"


class AuditQueryError(AuditLedgerError):
    """Raised when an invalid query is submitted to the ledger."""

    http_status_code = 400
    error_code = "audit_query_error"
