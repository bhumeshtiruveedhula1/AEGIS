"""tests/unit/audit/conftest.py — Shared fixtures for audit ledger tests."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path

from backend.audit.ledger import AuditLedger
from backend.audit.models import (
    AuditEntry,
    AuditEventType,
    AuditMetadata,
)
from backend.audit.service import AuditService
from backend.audit.storage import AuditStore


@pytest.fixture()
def store_dir(tmp_path: Path) -> Path:
    return tmp_path / "audit"


@pytest.fixture()
def store(store_dir: Path) -> AuditStore:
    return AuditStore(store_dir)


@pytest.fixture()
def ledger(store_dir: Path) -> AuditLedger:
    return AuditLedger(store_dir)


@pytest.fixture()
def service(store_dir: Path) -> AuditService:
    return AuditService(store_dir=store_dir)


@pytest.fixture()
def sample_metadata() -> AuditMetadata:
    return AuditMetadata(
        source_module="detection",
        alert_id="alert-001",
        context_id="ctx-001",
        entity_id="entity-001",
        host="host-01",
        user="user-01",
    )


@pytest.fixture()
def sample_entry(sample_metadata: AuditMetadata) -> AuditEntry:
    return AuditEntry(
        event_type=AuditEventType.DETECTION_ALERT,
        metadata=sample_metadata,
        severity="high",
        outcome="success",
        description="Test detection alert",
    )
