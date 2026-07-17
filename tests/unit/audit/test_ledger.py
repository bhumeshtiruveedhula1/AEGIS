"""tests/unit/audit/test_ledger.py — AuditLedger append and retrieval tests."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from backend.audit.models import (
    AuditActor,
    AuditEntry,
    AuditEventType,
    AuditMetadata,
)

if TYPE_CHECKING:
    from backend.audit.ledger import AuditLedger


def _meta(module: str = "test", alert_id: str = "a-001") -> AuditMetadata:
    return AuditMetadata(source_module=module, alert_id=alert_id)


class TestAuditLedgerRecord:
    def test_record_returns_entry(self, ledger: AuditLedger) -> None:
        entry = ledger.record(
            AuditEventType.DETECTION_ALERT,
            _meta(),
            description="test",
        )
        assert isinstance(entry, AuditEntry)
        assert entry.audit_id.startswith("aud-")

    def test_record_assigns_monotonic_sequence(self, ledger: AuditLedger) -> None:
        e1 = ledger.record(AuditEventType.DETECTION_ALERT, _meta())
        e2 = ledger.record(AuditEventType.CONTEXT_CREATED, _meta())
        assert e2.sequence_number == e1.sequence_number + 1

    def test_record_with_string_event_type(self, ledger: AuditLedger) -> None:
        entry = ledger.record("detection_alert", _meta())
        assert entry.event_type == "detection_alert"

    def test_record_custom_actor(self, ledger: AuditLedger) -> None:
        actor = AuditActor.operator("analyst@corp.com")
        entry = ledger.record(AuditEventType.APPROVAL_APPROVED, _meta(), actor=actor)
        assert entry.actor.actor_type == "operator"
        assert entry.actor.actor_id == "analyst@corp.com"

    def test_record_persisted_and_retrievable(self, ledger: AuditLedger) -> None:
        entry = ledger.record(AuditEventType.DETECTION_ALERT, _meta())
        retrieved = ledger.get(entry.audit_id)
        assert retrieved.audit_id == entry.audit_id


class TestAuditLedgerAppend:
    def test_append_overwrites_sequence(self, ledger: AuditLedger) -> None:
        """append() should always assign the next monotonic seq, ignoring caller value."""
        pre_built = AuditEntry(
            sequence_number=9999,
            event_type=AuditEventType.PLATFORM_STARTED,
            metadata=_meta(),
        )
        appended = ledger.append(pre_built)
        # Sequence must be 0 (first entry), not 9999
        assert appended.sequence_number == 0

    def test_append_sequence_increments(self, ledger: AuditLedger) -> None:
        e1 = ledger.append(AuditEntry(event_type=AuditEventType.PLATFORM_STARTED, metadata=_meta()))
        e2 = ledger.append(AuditEntry(event_type=AuditEventType.PLATFORM_STOPPED, metadata=_meta()))
        assert e2.sequence_number == e1.sequence_number + 1


class TestAuditLedgerReadback:
    def test_get_for_date_today(self, ledger: AuditLedger) -> None:
        ledger.record(AuditEventType.DETECTION_ALERT, _meta())
        ledger.record(AuditEventType.CONTEXT_CREATED, _meta())
        today = ledger.get_for_date(datetime.now(UTC))
        assert len(today) == 2

    def test_get_all_returns_all(self, ledger: AuditLedger) -> None:
        for _ in range(5):
            ledger.record(AuditEventType.DETECTION_ALERT, _meta())
        assert len(ledger.get_all()) == 5

    def test_count(self, ledger: AuditLedger) -> None:
        ledger.record(AuditEventType.METRIC_COLLECTED, _meta())
        ledger.record(AuditEventType.METRIC_COLLECTED, _meta())
        assert ledger.count() == 2

    def test_list_ids(self, ledger: AuditLedger) -> None:
        e = ledger.record(AuditEventType.DETECTION_ALERT, _meta())
        assert e.audit_id in ledger.list_ids()


class TestAuditLedgerEmpty:
    def test_empty_ledger_get_all_returns_empty(self, ledger: AuditLedger) -> None:
        assert ledger.get_all() == []

    def test_empty_ledger_count_zero(self, ledger: AuditLedger) -> None:
        assert ledger.count() == 0

    def test_empty_ledger_list_ids_empty(self, ledger: AuditLedger) -> None:
        assert ledger.list_ids() == []
