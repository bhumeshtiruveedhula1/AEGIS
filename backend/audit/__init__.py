"""
backend.audit — Audit Ledger
=============================
Module 7.2 — Immutable Audit Ledger for Operation AEGIS

Provides the permanent forensic record of every significant action
performed by the platform. Append-only. Immutable. Queryable.

Public API
----------
    from backend.audit.service import AuditService
    from backend.audit.models import AuditEventType, AuditQuery, AuditEntry
    from backend.audit.integrity import IntegrityReport

    svc = AuditService()
    entry = svc.record_event(
        AuditEventType.DETECTION_ALERT,
        source_module="detection",
        alert_id="alert-001",
        severity="high",
        outcome="success",
    )
    result = svc.query(AuditQuery(alert_id="alert-001"))
    report = svc.verify_integrity()
    stats  = svc.get_statistics()
"""

from backend.audit.exceptions import (
    AuditIntegrityError,
    AuditLedgerError,
    AuditQueryError,
    AuditRecordNotFoundError,
    AuditSchemaError,
    AuditStorageError,
)
from backend.audit.models import (
    AUDIT_SCHEMA_VERSION,
    AuditActor,
    AuditEntry,
    AuditEventType,
    AuditMetadata,
    AuditQuery,
    AuditResult,
    LedgerStatistics,
)
from backend.audit.service import AuditService

__all__ = [
    # Service
    "AuditService",
    # Models
    "AUDIT_SCHEMA_VERSION",
    "AuditActor",
    "AuditEntry",
    "AuditEventType",
    "AuditMetadata",
    "AuditQuery",
    "AuditResult",
    "LedgerStatistics",
    # Exceptions
    "AuditIntegrityError",
    "AuditLedgerError",
    "AuditQueryError",
    "AuditRecordNotFoundError",
    "AuditSchemaError",
    "AuditStorageError",
]
