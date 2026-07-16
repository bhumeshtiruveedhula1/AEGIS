"""tests/unit/orchestrator/test_approval.py — Approval lifecycle state machine tests."""

from __future__ import annotations

import pytest

from backend.orchestrator.approval import ApprovalManager
from backend.orchestrator.exceptions import (
    ApprovalAlreadyProcessedError,
)
from backend.orchestrator.models import ApprovalRecord
from tests.unit.orchestrator.conftest import make_approval


class TestCreatePending:
    def test_status_is_pending(self) -> None:
        record = ApprovalManager.create_pending("orch-1")
        assert record.status == "PENDING"

    def test_decided_at_is_none(self) -> None:
        record = ApprovalManager.create_pending("orch-1")
        assert record.decided_at is None

    def test_orchestration_id_set(self) -> None:
        record = ApprovalManager.create_pending("orch-abc")
        assert record.orchestration_id == "orch-abc"

    def test_custom_ttl(self) -> None:
        record = ApprovalManager.create_pending("orch-1", ttl_seconds=120)
        assert record.ttl_seconds == 120


class TestApprove:
    def test_pending_to_approved(self) -> None:
        record = ApprovalManager.create_pending("orch-1")
        approved = ApprovalManager.approve(record, decided_by="analyst@soc.com")
        assert approved.status == "APPROVED"
        assert approved.decided_by == "analyst@soc.com"
        assert approved.decided_at is not None

    def test_reason_preserved(self) -> None:
        record = ApprovalManager.create_pending("orch-1")
        approved = ApprovalManager.approve(record, decided_by="bob", reason="Confirmed attack")
        assert approved.reason == "Confirmed attack"

    def test_already_approved_raises(self) -> None:
        record = make_approval(status="APPROVED")
        with pytest.raises(ApprovalAlreadyProcessedError):
            ApprovalManager.approve(record, decided_by="bob")

    def test_already_rejected_raises(self) -> None:
        record = make_approval(status="REJECTED")
        with pytest.raises(ApprovalAlreadyProcessedError):
            ApprovalManager.approve(record, decided_by="bob")

    def test_expired_raises_expired_error(self) -> None:
        record = make_approval(status="EXPIRED")
        with pytest.raises(ApprovalAlreadyProcessedError):
            ApprovalManager.approve(record, decided_by="bob")

    def test_original_record_unchanged(self) -> None:
        """Verify immutability — approve returns a new record."""
        record = ApprovalManager.create_pending("orch-1")
        _ = ApprovalManager.approve(record, decided_by="bob")
        assert record.status == "PENDING"  # original unchanged


class TestReject:
    def test_pending_to_rejected(self) -> None:
        record = ApprovalManager.create_pending("orch-1")
        rejected = ApprovalManager.reject(record, decided_by="analyst@soc.com", reason="FP")
        assert rejected.status == "REJECTED"
        assert rejected.decided_by == "analyst@soc.com"
        assert rejected.reason == "FP"

    def test_already_approved_raises(self) -> None:
        record = make_approval(status="APPROVED")
        with pytest.raises(ApprovalAlreadyProcessedError):
            ApprovalManager.reject(record, decided_by="bob")

    def test_original_record_unchanged(self) -> None:
        record = ApprovalManager.create_pending("orch-1")
        _ = ApprovalManager.reject(record, decided_by="bob")
        assert record.status == "PENDING"


class TestCheckExpiry:
    def test_non_pending_unchanged(self) -> None:
        record = make_approval(status="APPROVED")
        result = ApprovalManager.check_expiry(record)
        assert result.status == "APPROVED"

    def test_pending_within_ttl_unchanged(self) -> None:
        record = ApprovalManager.create_pending("orch-1", ttl_seconds=3600)
        result = ApprovalManager.check_expiry(record)
        assert result.status == "PENDING"

    def test_pending_past_ttl_becomes_expired(self) -> None:
        # TTL of 0 → immediately expired
        record = ApprovalRecord(
            orchestration_id="orch-x",
            status="PENDING",
            ttl_seconds=0,
        )
        result = ApprovalManager.check_expiry(record)
        assert result.status == "EXPIRED"

    def test_expired_has_decided_at(self) -> None:
        record = ApprovalRecord(
            orchestration_id="orch-x",
            status="PENDING",
            ttl_seconds=0,
        )
        result = ApprovalManager.check_expiry(record)
        assert result.decided_at is not None
