"""tests/unit/audit/test_service.py — AuditService integration tests."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from backend.audit.models import AuditEventType, AuditQuery

if TYPE_CHECKING:
    from backend.audit.service import AuditService


class TestAuditServiceRecordEvent:
    def test_record_event_returns_entry(self, service: AuditService) -> None:
        entry = service.record_event(
            AuditEventType.DETECTION_ALERT,
            source_module="detection",
            alert_id="a-001",
            severity="high",
            outcome="success",
        )
        assert "aud-" in entry.audit_id
        assert entry.metadata.alert_id == "a-001"
        assert entry.severity == "high"

    def test_record_event_persisted(self, service: AuditService) -> None:
        entry = service.record_event(AuditEventType.CONTEXT_CREATED, source_module="context")
        retrieved = service.get_entry(entry.audit_id)
        assert retrieved.audit_id == entry.audit_id

    def test_record_detection_helper(self, service: AuditService) -> None:
        entry = service.record_detection(
            alert_id="a-001",
            entity_id="e-001",
            severity="high",
            anomaly_score=0.91,
            host="host-01",
        )
        assert entry.event_type == "detection_alert"
        assert entry.payload["anomaly_score"] == 0.91
        assert entry.severity == "high"

    def test_record_context_created_helper(self, service: AuditService) -> None:
        entry = service.record_context_created("ctx-001", "a-001", "e-001")
        assert entry.event_type == "context_created"
        assert entry.metadata.context_id == "ctx-001"

    def test_record_orchestration_created_helper(self, service: AuditService) -> None:
        entry = service.record_orchestration_created("orch-001", "ctx-001", "isolate_host")
        assert entry.event_type == "orchestration_created"
        assert entry.metadata.orchestration_id == "orch-001"
        assert entry.payload["playbook_id"] == "isolate_host"

    def test_record_approval_approved(self, service: AuditService) -> None:
        entry = service.record_approval_decision("orch-001", "APPROVED", "analyst@corp.com")
        assert entry.event_type == "approval_approved"
        assert entry.actor.actor_type == "operator"

    def test_record_approval_rejected(self, service: AuditService) -> None:
        entry = service.record_approval_decision("orch-001", "REJECTED", "analyst@corp.com")
        assert entry.event_type == "approval_rejected"

    def test_record_approval_expired(self, service: AuditService) -> None:
        entry = service.record_approval_decision("orch-001", "EXPIRED", "system")
        assert entry.event_type == "approval_expired"


class TestAuditServiceQuery:
    def test_query_empty_returns_zero(self, service: AuditService) -> None:
        result = service.query(AuditQuery())
        assert result.total_matched == 0
        assert result.entries == []

    def test_query_by_alert_id(self, service: AuditService) -> None:
        service.record_event(AuditEventType.DETECTION_ALERT, "detection", alert_id="a-001")
        service.record_event(AuditEventType.DETECTION_ALERT, "detection", alert_id="a-002")
        result = service.query(AuditQuery(alert_id="a-001"))
        assert result.total_matched == 1

    def test_query_limit_offset(self, service: AuditService) -> None:
        for _ in range(10):
            service.record_event(AuditEventType.METRIC_COLLECTED, "metrics")
        result = service.query(AuditQuery(limit=3, offset=2))
        assert len(result.entries) == 3

    def test_get_by_context(self, service: AuditService) -> None:
        service.record_event(AuditEventType.CONTEXT_CREATED, "context", context_id="ctx-X")
        service.record_event(AuditEventType.MITRE_MAPPED, "mitre", context_id="ctx-X")
        service.record_event(AuditEventType.CONTEXT_CREATED, "context", context_id="ctx-Y")
        entries = service.get_by_context("ctx-X")
        assert len(entries) == 2

    def test_get_by_alert(self, service: AuditService) -> None:
        service.record_event(AuditEventType.DETECTION_ALERT, "detection", alert_id="a-001")
        service.record_event(AuditEventType.SHAP_EXPLANATION, "shap", alert_id="a-001")
        entries = service.get_by_alert("a-001")
        assert len(entries) == 2

    def test_get_by_orchestration(self, service: AuditService) -> None:
        service.record_event(AuditEventType.ORCHESTRATION_CREATED, "orch", orchestration_id="o-001")
        service.record_event(AuditEventType.APPROVAL_APPROVED, "orch", orchestration_id="o-001")
        entries = service.get_by_orchestration("o-001")
        assert len(entries) == 2

    def test_get_for_date(self, service: AuditService) -> None:
        service.record_event(AuditEventType.PLATFORM_STARTED, "platform")
        entries = service.get_for_date(datetime.now(UTC))
        assert len(entries) >= 1


class TestAuditServiceIntegrity:
    def test_verify_clean_ledger(self, service: AuditService) -> None:
        service.record_event(AuditEventType.DETECTION_ALERT, "detection", alert_id="a-001")
        service.record_event(AuditEventType.CONTEXT_CREATED, "context", context_id="ctx-001")
        report = service.verify_integrity()
        assert report.passed is True
        assert report.total_entries == 2

    def test_verify_empty_ledger_passes(self, service: AuditService) -> None:
        report = service.verify_integrity()
        assert report.passed is True
        assert report.total_entries == 0


class TestAuditServiceStatistics:
    def test_stats_empty(self, service: AuditService) -> None:
        stats = service.get_statistics()
        assert stats.total_entries == 0
        assert stats.oldest_entry_at is None

    def test_stats_populated(self, service: AuditService) -> None:
        service.record_detection("a-001", "e-001", "high", 0.9)
        service.record_detection("a-002", "e-002", "medium", 0.7)
        service.record_event(AuditEventType.CONTEXT_CREATED, "context", context_id="ctx-001")

        stats = service.get_statistics()
        assert stats.total_entries == 3
        assert "detection_alert" in stats.event_type_counts
        assert stats.event_type_counts["detection_alert"] == 2
        assert stats.event_type_counts["context_created"] == 1
        assert stats.oldest_entry_at is not None
        assert stats.newest_entry_at is not None
        assert stats.oldest_entry_at <= stats.newest_entry_at

    def test_count(self, service: AuditService) -> None:
        service.record_event(AuditEventType.METRIC_COLLECTED, "metrics")
        service.record_event(AuditEventType.METRIC_COLLECTED, "metrics")
        assert service.count() == 2


class TestAuditServiceAppendOnly:
    def test_multiple_records_accumulate(self, service: AuditService) -> None:
        """Records accumulate — none are deleted or overwritten."""
        for i in range(5):
            service.record_event(
                AuditEventType.DETECTION_ALERT,
                source_module="detection",
                alert_id=f"a-{i:03d}",
            )
        assert service.count() == 5

    def test_sequence_numbers_unique(self, service: AuditService) -> None:
        entries = [
            service.record_event(AuditEventType.METRIC_COLLECTED, "metrics") for _ in range(10)
        ]
        seqs = [e.sequence_number for e in entries]
        assert len(seqs) == len(set(seqs)), "Duplicate sequence numbers found"
        assert seqs == sorted(seqs), "Sequence numbers not monotonically increasing"
