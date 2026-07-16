"""tests/unit/audit/test_models.py — AuditEntry and supporting model tests."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from backend.audit.models import (
    AUDIT_SCHEMA_VERSION,
    AuditActor,
    AuditEntry,
    AuditEventType,
    AuditMetadata,
    AuditQuery,
    LedgerStatistics,
)


class TestAuditActor:
    def test_system_factory(self) -> None:
        a = AuditActor.system("detection")
        assert a.actor_type == "system"
        assert a.actor_id == "detection"

    def test_operator_factory(self) -> None:
        a = AuditActor.operator("analyst@corp.com", ip="10.0.0.1")
        assert a.actor_type == "operator"
        assert a.actor_id == "analyst@corp.com"
        assert a.ip_address == "10.0.0.1"

    def test_invalid_actor_type_raises(self) -> None:
        with pytest.raises(ValidationError):
            AuditActor(actor_type="alien", actor_id="x")

    def test_frozen(self) -> None:
        a = AuditActor.system()
        with pytest.raises(ValidationError):
            a.actor_id = "changed"  # type: ignore[misc]


class TestAuditMetadata:
    def test_required_source_module(self) -> None:
        m = AuditMetadata(source_module="detection")
        assert m.source_module == "detection"

    def test_optional_fields_default_none(self) -> None:
        m = AuditMetadata(source_module="test")
        assert m.alert_id is None
        assert m.context_id is None
        assert m.extra == {}


class TestAuditEntry:
    def test_created_with_defaults(self, sample_entry: AuditEntry) -> None:
        assert "aud-" in sample_entry.audit_id
        assert sample_entry.schema_version == AUDIT_SCHEMA_VERSION
        assert sample_entry.sequence_number == 0

    def test_event_type_stored_as_string_value(self) -> None:
        meta = AuditMetadata(source_module="test")
        e = AuditEntry(event_type=AuditEventType.CONTEXT_CREATED, metadata=meta)
        assert e.event_type == "context_created"

    def test_invalid_severity_raises(self, sample_metadata: AuditMetadata) -> None:
        with pytest.raises(ValidationError):
            AuditEntry(
                event_type=AuditEventType.DETECTION_ALERT,
                metadata=sample_metadata,
                severity="ultra",
            )

    def test_invalid_outcome_raises(self, sample_metadata: AuditMetadata) -> None:
        with pytest.raises(ValidationError):
            AuditEntry(
                event_type=AuditEventType.DETECTION_ALERT,
                metadata=sample_metadata,
                outcome="maybe",
            )

    def test_frozen_immutable(self, sample_entry: AuditEntry) -> None:
        with pytest.raises(ValidationError):
            sample_entry.description = "changed"  # type: ignore[misc]

    def test_timestamp_utc_aware(self, sample_entry: AuditEntry) -> None:
        assert sample_entry.timestamp.tzinfo is not None

    def test_serialise_round_trip(self, sample_entry: AuditEntry) -> None:
        json_str = sample_entry.model_dump_json()
        reloaded = AuditEntry.model_validate_json(json_str)
        assert reloaded.audit_id == sample_entry.audit_id
        assert reloaded.event_type == sample_entry.event_type


class TestAuditQuery:
    def test_defaults(self) -> None:
        q = AuditQuery()
        assert q.limit == 100
        assert q.offset == 0
        assert q.ascending is False

    def test_all_filters_optional(self) -> None:
        q = AuditQuery(alert_id="x", severity="high", limit=10)
        assert q.alert_id == "x"
        assert q.severity == "high"
        assert q.limit == 10


class TestLedgerStatistics:
    def test_empty_stats(self) -> None:
        stats = LedgerStatistics()
        assert stats.total_entries == 0
        assert stats.dates_covered == []
