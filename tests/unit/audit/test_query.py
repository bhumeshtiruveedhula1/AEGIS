from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest

from backend.audit.exceptions import AuditQueryError
from backend.audit.models import AuditEventType, AuditMetadata, AuditQuery
from backend.audit.query import AuditQueryEngine

if TYPE_CHECKING:
    from backend.audit.ledger import AuditLedger


def _record(
    ledger: AuditLedger,
    event_type: AuditEventType = AuditEventType.DETECTION_ALERT,
    alert_id: str = "a-001",
    context_id: str | None = None,
    severity: str | None = "high",
    outcome: str | None = "success",
    source_module: str = "detection",
    host: str | None = "host-01",
    user: str | None = "user-01",
    ts: datetime | None = None,
) -> None:
    meta = AuditMetadata(
        source_module=source_module,
        alert_id=alert_id,
        context_id=context_id,
        host=host,
        user=user,
    )
    ledger.record(
        event_type,
        meta,
        severity=severity,
        outcome=outcome,
        timestamp=ts,
    )


class TestAuditQueryEngineBasic:
    def test_empty_query_returns_all(self, ledger: AuditLedger) -> None:
        _record(ledger)
        _record(ledger)
        engine = AuditQueryEngine(ledger)
        result = engine.query(AuditQuery())
        assert result.total_matched == 2

    def test_filter_by_alert_id(self, ledger: AuditLedger) -> None:
        _record(ledger, alert_id="a-001")
        _record(ledger, alert_id="a-002")
        engine = AuditQueryEngine(ledger)
        result = engine.query(AuditQuery(alert_id="a-001"))
        assert result.total_matched == 1
        assert result.entries[0].metadata.alert_id == "a-001"

    def test_filter_by_event_type(self, ledger: AuditLedger) -> None:
        _record(ledger, event_type=AuditEventType.DETECTION_ALERT)
        _record(ledger, event_type=AuditEventType.CONTEXT_CREATED)
        engine = AuditQueryEngine(ledger)
        result = engine.query(AuditQuery(event_type=AuditEventType.CONTEXT_CREATED))
        assert result.total_matched == 1

    def test_filter_by_severity(self, ledger: AuditLedger) -> None:
        _record(ledger, severity="high")
        _record(ledger, severity="low")
        engine = AuditQueryEngine(ledger)
        result = engine.query(AuditQuery(severity="high"))
        assert result.total_matched == 1

    def test_filter_by_outcome(self, ledger: AuditLedger) -> None:
        _record(ledger, outcome="success")
        _record(ledger, outcome="failure")
        engine = AuditQueryEngine(ledger)
        result = engine.query(AuditQuery(outcome="failure"))
        assert result.total_matched == 1

    def test_filter_by_host(self, ledger: AuditLedger) -> None:
        _record(ledger, host="host-01")
        _record(ledger, host="host-99")
        engine = AuditQueryEngine(ledger)
        result = engine.query(AuditQuery(host="host-01"))
        assert result.total_matched == 1

    def test_filter_by_user(self, ledger: AuditLedger) -> None:
        _record(ledger, user="alice")
        _record(ledger, user="bob")
        engine = AuditQueryEngine(ledger)
        result = engine.query(AuditQuery(user="alice"))
        assert result.total_matched == 1

    def test_filter_by_source_module(self, ledger: AuditLedger) -> None:
        _record(ledger, source_module="detection")
        _record(ledger, source_module="orchestrator")
        engine = AuditQueryEngine(ledger)
        result = engine.query(AuditQuery(source_module="orchestrator"))
        assert result.total_matched == 1

    def test_combined_filters_anded(self, ledger: AuditLedger) -> None:
        _record(ledger, alert_id="a-001", severity="high")
        _record(ledger, alert_id="a-001", severity="low")
        _record(ledger, alert_id="a-002", severity="high")
        engine = AuditQueryEngine(ledger)
        result = engine.query(AuditQuery(alert_id="a-001", severity="high"))
        assert result.total_matched == 1


class TestAuditQueryEngineTimeRange:
    def test_filter_after(self, ledger: AuditLedger) -> None:
        now = datetime.now(UTC)
        _record(ledger, ts=now - timedelta(hours=2))
        _record(ledger, ts=now)
        engine = AuditQueryEngine(ledger)
        result = engine.query(AuditQuery(after=now - timedelta(hours=1)))
        assert result.total_matched == 1

    def test_filter_before(self, ledger: AuditLedger) -> None:
        now = datetime.now(UTC)
        _record(ledger, ts=now - timedelta(hours=2))
        _record(ledger, ts=now)
        engine = AuditQueryEngine(ledger)
        result = engine.query(AuditQuery(before=now - timedelta(hours=1)))
        assert result.total_matched == 1

    def test_invalid_range_raises(self, ledger: AuditLedger) -> None:
        now = datetime.now(UTC)
        with pytest.raises(AuditQueryError):
            AuditQueryEngine(ledger).query(AuditQuery(after=now, before=now - timedelta(hours=1)))


class TestAuditQueryEnginePagination:
    def test_limit_respected(self, ledger: AuditLedger) -> None:
        for _ in range(10):
            _record(ledger)
        engine = AuditQueryEngine(ledger)
        result = engine.query(AuditQuery(limit=3))
        assert len(result.entries) == 3
        assert result.total_matched == 10

    def test_offset(self, ledger: AuditLedger) -> None:
        for _ in range(5):
            _record(ledger)
        engine = AuditQueryEngine(ledger)
        all_r = engine.query(AuditQuery(limit=5))
        paged = engine.query(AuditQuery(limit=5, offset=2))
        assert len(paged.entries) == 3
        assert paged.entries[0].audit_id == all_r.entries[2].audit_id

    def test_ascending_ordering(self, ledger: AuditLedger) -> None:
        now = datetime.now(UTC)
        _record(ledger, ts=now - timedelta(seconds=10))
        _record(ledger, ts=now)
        engine = AuditQueryEngine(ledger)
        asc = engine.query(AuditQuery(ascending=True))
        desc = engine.query(AuditQuery(ascending=False))
        assert asc.entries[0].timestamp < asc.entries[1].timestamp
        assert desc.entries[0].timestamp > desc.entries[1].timestamp


class TestAuditQueryEngineShortcuts:
    def test_get_by_id(self, ledger: AuditLedger) -> None:
        _record(ledger)
        entry_id = ledger.list_ids()[0]
        engine = AuditQueryEngine(ledger)
        found = engine.get_by_id(entry_id)
        assert found.audit_id == entry_id

    def test_get_by_context(self, ledger: AuditLedger) -> None:
        _record(ledger, context_id="ctx-A")
        _record(ledger, context_id="ctx-B")
        _record(ledger, context_id="ctx-A")
        engine = AuditQueryEngine(ledger)
        entries = engine.get_by_context("ctx-A")
        assert len(entries) == 2

    def test_get_by_alert(self, ledger: AuditLedger) -> None:
        _record(ledger, alert_id="a-001")
        _record(ledger, alert_id="a-002")
        engine = AuditQueryEngine(ledger)
        entries = engine.get_by_alert("a-001")
        assert len(entries) == 1
