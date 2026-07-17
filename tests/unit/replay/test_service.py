"""tests/unit/replay/test_service.py — ReplayService integration tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from backend.audit.models import AuditEventType
from backend.audit.service import AuditService

if TYPE_CHECKING:
    from backend.replay.service import ReplayService


def _seed_audit(audit: AuditService, alert_id: str = "a-001", n: int = 3) -> None:
    """Write n audit entries with the given alert_id."""
    base = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    for i in range(n):
        audit.record_event(
            AuditEventType.DETECTION_ALERT,
            source_module="detection",
            alert_id=alert_id,
            timestamp=base + timedelta(minutes=i),
            description=f"alert event {i}",
        )


class TestReplayServiceBuildByAlert:
    def test_build_session_creates_frames(self, service: ReplayService, store_dir) -> None:
        audit = AuditService(store_dir=store_dir / "audit")
        _seed_audit(audit, "a-svc-001", n=3)
        svc = type(service)(store_dir=store_dir, audit_service=audit)
        session = svc.build_session_for_alert("a-svc-001")
        assert session.total_frames == 3
        assert session.alert_id == "a-svc-001"
        assert session.replay_type == "alert"

    def test_build_session_is_persisted(self, service: ReplayService, store_dir) -> None:
        audit = AuditService(store_dir=store_dir / "audit")
        _seed_audit(audit, "a-svc-002", n=2)
        svc = type(service)(store_dir=store_dir, audit_service=audit)
        session = svc.build_session_for_alert("a-svc-002", persist=True)
        loaded = svc.load_session(session.session_id)
        assert loaded.session_id == session.session_id

    def test_build_session_not_persisted(self, service: ReplayService, store_dir) -> None:
        audit = AuditService(store_dir=store_dir / "audit")
        _seed_audit(audit, "a-svc-003", n=2)
        svc = type(service)(store_dir=store_dir, audit_service=audit)
        svc.build_session_for_alert("a-svc-003", persist=False)
        assert svc.count_sessions() == 0

    def test_build_session_empty_alert_no_frames(self, service: ReplayService, store_dir) -> None:
        audit = AuditService(store_dir=store_dir / "audit")
        svc = type(service)(store_dir=store_dir, audit_service=audit)
        session = svc.build_session_for_alert("nonexistent", persist=False)
        assert session.total_frames == 0


class TestReplayServiceBuildByContext:
    def test_build_session_for_context(self, service: ReplayService, store_dir) -> None:
        audit = AuditService(store_dir=store_dir / "audit")
        base = datetime(2026, 1, 1, tzinfo=UTC)
        for i in range(4):
            audit.record_event(
                AuditEventType.CONTEXT_CREATED,
                source_module="context",
                context_id="ctx-001",
                timestamp=base + timedelta(minutes=i),
            )
        svc = type(service)(store_dir=store_dir, audit_service=audit)
        session = svc.build_session_for_context("ctx-001", persist=False)
        assert session.total_frames == 4
        assert session.context_id == "ctx-001"


class TestReplayServicePlayer:
    def test_player_start(self, store_dir) -> None:
        from backend.replay.service import ReplayService
        from tests.unit.replay.conftest import _make_session
        svc = ReplayService(store_dir=store_dir, audit_service=AuditService(store_dir=store_dir / "audit"))
        s = _make_session(3)
        svc.save_session(s)
        step, updated = svc.player_start(s.session_id)
        assert step.frame is not None
        assert updated.is_started

    def test_player_next(self, store_dir) -> None:
        from backend.replay.service import ReplayService
        from tests.unit.replay.conftest import _make_session
        svc = ReplayService(store_dir=store_dir, audit_service=AuditService(store_dir=store_dir / "audit"))
        s = _make_session(3)
        svc.save_session(s)
        svc.player_start(s.session_id)
        step, updated = svc.player_next(s.session_id)
        assert updated.current_index == 1

    def test_player_seek(self, store_dir) -> None:
        from backend.replay.service import ReplayService
        from tests.unit.replay.conftest import _make_session
        svc = ReplayService(store_dir=store_dir, audit_service=AuditService(store_dir=store_dir / "audit"))
        s = _make_session(5)
        svc.save_session(s)
        step, updated = svc.player_seek(s.session_id, 3)
        assert updated.current_index == 3

    def test_player_first_last(self, store_dir) -> None:
        from backend.replay.service import ReplayService
        from tests.unit.replay.conftest import _make_session
        svc = ReplayService(store_dir=store_dir, audit_service=AuditService(store_dir=store_dir / "audit"))
        s = _make_session(4)
        svc.save_session(s)
        svc.player_last(s.session_id)
        _, pos = svc.player_first(s.session_id)
        assert pos.current_index == 0


class TestReplayServiceFrameAccess:
    def test_get_frame(self, store_dir) -> None:
        from backend.replay.service import ReplayService
        from tests.unit.replay.conftest import _make_session
        svc = ReplayService(store_dir=store_dir, audit_service=AuditService(store_dir=store_dir / "audit"))
        s = _make_session(4)
        svc.save_session(s)
        frame = svc.get_frame(s.session_id, 2)
        assert frame.frame_index == 2

    def test_get_frames_slice(self, store_dir) -> None:
        from backend.replay.service import ReplayService
        from tests.unit.replay.conftest import _make_session
        svc = ReplayService(store_dir=store_dir, audit_service=AuditService(store_dir=store_dir / "audit"))
        s = _make_session(5)
        svc.save_session(s)
        frames = svc.get_frames(s.session_id, start=1, end=4)
        assert len(frames) == 3


class TestReplayServiceStatistics:
    def test_statistics_empty(self, store_dir) -> None:
        from backend.replay.service import ReplayService
        svc = ReplayService(store_dir=store_dir, audit_service=AuditService(store_dir=store_dir / "audit"))
        stats = svc.get_statistics()
        assert stats.total_sessions == 0

    def test_statistics_populated(self, store_dir) -> None:
        from backend.replay.service import ReplayService
        from tests.unit.replay.conftest import _make_session
        svc = ReplayService(store_dir=store_dir, audit_service=AuditService(store_dir=store_dir / "audit"))
        svc.save_session(_make_session(3))
        svc.save_session(_make_session(2))
        stats = svc.get_statistics()
        assert stats.total_sessions == 2
        assert stats.total_frames_across_sessions == 5

    def test_count_sessions(self, store_dir) -> None:
        from backend.replay.service import ReplayService
        from tests.unit.replay.conftest import _make_session
        svc = ReplayService(store_dir=store_dir, audit_service=AuditService(store_dir=store_dir / "audit"))
        for _ in range(3):
            svc.save_session(_make_session(1))
        assert svc.count_sessions() == 3


class TestReplayServiceListSessions:
    def test_list_sessions_empty(self, service: ReplayService) -> None:
        assert service.list_sessions() == []

    def test_list_sessions_returns_summaries(self, store_dir) -> None:
        from backend.replay.service import ReplayService
        from tests.unit.replay.conftest import _make_session
        svc = ReplayService(store_dir=store_dir, audit_service=AuditService(store_dir=store_dir / "audit"))
        svc.save_session(_make_session(2))
        svc.save_session(_make_session(3))
        summaries = svc.list_sessions()
        assert len(summaries) == 2
