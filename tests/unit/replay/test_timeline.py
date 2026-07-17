"""tests/unit/replay/test_timeline.py — TimelineBuilder tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from backend.audit.models import AuditEntry, AuditEventType
from backend.replay.models import ReplayEventType

if TYPE_CHECKING:
    from backend.replay.timeline import TimelineBuilder


def _entry(
    *,
    ts: datetime,
    event_type: AuditEventType = AuditEventType.DETECTION_ALERT,
    alert_id: str = "a-001",
    context_id: str | None = None,
    orchestration_id: str | None = None,
) -> AuditEntry:
    from tests.unit.replay.conftest import _make_audit_entry
    return _make_audit_entry(
        ts=ts,
        event_type=event_type,
        alert_id=alert_id,
        context_id=context_id,
        orchestration_id=orchestration_id,
    )


class TestTimelineBuilderBasic:
    def test_empty_entries_returns_empty_timeline(self, builder: TimelineBuilder) -> None:
        tl = builder.build([])
        assert tl.is_empty
        assert tl.length == 0

    def test_single_entry(self, builder: TimelineBuilder, sample_entries: list[AuditEntry]) -> None:
        tl = builder.build([sample_entries[0]])
        assert tl.length == 1
        assert tl.frames[0].frame_index == 0

    def test_frames_chronological_order(self, builder: TimelineBuilder) -> None:
        base = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        entries = [
            _entry(ts=base + timedelta(minutes=2)),
            _entry(ts=base),
            _entry(ts=base + timedelta(minutes=1)),
        ]
        tl = builder.build(entries)
        ts = [f.timestamp for f in tl.frames]
        assert ts == sorted(ts), "Frames must be chronological"

    def test_frame_indices_sequential(self, builder: TimelineBuilder, sample_entries: list[AuditEntry]) -> None:
        tl = builder.build(sample_entries)
        indices = [f.frame_index for f in tl.frames]
        assert indices == list(range(len(sample_entries)))

    def test_source_query_preserved(self, builder: TimelineBuilder, sample_entries: list[AuditEntry]) -> None:
        tl = builder.build(sample_entries, source_query="alert:a-001")
        assert tl.source_query == "alert:a-001"

    def test_event_type_mapping(self, builder: TimelineBuilder) -> None:
        base = datetime(2026, 1, 1, tzinfo=UTC)
        entries = [
            _entry(ts=base, event_type=AuditEventType.DETECTION_ALERT),
            _entry(ts=base + timedelta(minutes=1), event_type=AuditEventType.SHAP_EXPLANATION),
            _entry(ts=base + timedelta(minutes=2), event_type=AuditEventType.MITRE_MAPPED),
            _entry(ts=base + timedelta(minutes=3), event_type=AuditEventType.ORCHESTRATION_CREATED),
        ]
        tl = builder.build(entries)
        types = [f.event_type for f in tl.frames]
        assert types[0] == ReplayEventType.DETECTION
        assert types[1] == ReplayEventType.EXPLANATION
        assert types[2] == ReplayEventType.MITRE_MAPPING
        assert types[3] == ReplayEventType.ORCHESTRATION

    def test_all_entries_included(self, builder: TimelineBuilder, sample_entries: list[AuditEntry]) -> None:
        tl = builder.build(sample_entries)
        assert tl.length == len(sample_entries)


class TestTimelineBuilderFilters:
    def test_build_for_alert(self, builder: TimelineBuilder) -> None:
        base = datetime(2026, 1, 1, tzinfo=UTC)
        entries = [
            _entry(ts=base, alert_id="a-001"),
            _entry(ts=base + timedelta(minutes=1), alert_id="a-002"),
            _entry(ts=base + timedelta(minutes=2), alert_id="a-001"),
        ]
        tl = builder.build_for_alert(entries, "a-001")
        assert tl.length == 2
        assert "alert:a-001" in tl.source_query

    def test_build_for_context(self, builder: TimelineBuilder) -> None:
        base = datetime(2026, 1, 1, tzinfo=UTC)
        entries = [
            _entry(ts=base, context_id="ctx-001"),
            _entry(ts=base + timedelta(minutes=1), context_id="ctx-002"),
            _entry(ts=base + timedelta(minutes=2), context_id="ctx-001"),
        ]
        tl = builder.build_for_context(entries, "ctx-001")
        assert tl.length == 2

    def test_build_for_orchestration(self, builder: TimelineBuilder) -> None:
        base = datetime(2026, 1, 1, tzinfo=UTC)
        entries = [
            _entry(ts=base, orchestration_id="orch-001"),
            _entry(ts=base + timedelta(minutes=1), orchestration_id="orch-002"),
        ]
        tl = builder.build_for_orchestration(entries, "orch-001")
        assert tl.length == 1

    def test_filter_no_matches_returns_empty(self, builder: TimelineBuilder, sample_entries: list[AuditEntry]) -> None:
        tl = builder.build_for_alert(sample_entries, "nonexistent")
        assert tl.is_empty

    def test_deterministic_same_input_same_order(self, builder: TimelineBuilder, sample_entries: list[AuditEntry]) -> None:
        tl1 = builder.build(sample_entries)
        tl2 = builder.build(list(reversed(sample_entries)))
        audit_ids_1 = [f.audit_id for f in tl1.frames]
        audit_ids_2 = [f.audit_id for f in tl2.frames]
        assert audit_ids_1 == audit_ids_2


class TestTimelineFrame:
    def test_frame_has_correct_module(self, builder: TimelineBuilder, sample_entries: list[AuditEntry]) -> None:
        tl = builder.build([sample_entries[0]])
        assert tl.frames[0].source_module == "detection"

    def test_frame_audit_id_matches_entry(self, builder: TimelineBuilder, sample_entries: list[AuditEntry]) -> None:
        tl = builder.build([sample_entries[0]])
        assert tl.frames[0].audit_id == sample_entries[0].audit_id

    def test_frame_correlation_ids(self, builder: TimelineBuilder) -> None:
        base = datetime(2026, 1, 1, tzinfo=UTC)
        e = _entry(ts=base, alert_id="a-001", context_id="ctx-001")
        tl = builder.build([e])
        assert tl.frames[0].correlation["alert_id"] == "a-001"
        assert tl.frames[0].correlation["context_id"] == "ctx-001"
