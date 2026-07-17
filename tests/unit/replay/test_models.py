"""tests/unit/replay/test_models.py — ReplayFrame, ReplayTimeline, ReplaySession, ReplayPosition tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from backend.replay.models import (
    REPLAY_SCHEMA_VERSION,
    ReplayEventType,
    ReplayFrame,
    ReplayPosition,
    ReplaySession,
    ReplayStatistics,
    ReplayTimeline,
)


def _frame(index: int = 0) -> ReplayFrame:
    t = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    return ReplayFrame(
        frame_index=index,
        audit_id=f"aud-{index}",
        event_type=ReplayEventType.DETECTION,
        timestamp=t + timedelta(minutes=index),
        recorded_at=t + timedelta(minutes=index, seconds=1),
        source_module="detection",
        description=f"frame {index}",
    )


class TestReplayFrame:
    def test_defaults(self) -> None:
        f = _frame(0)
        assert "aud-0" in f.audit_id
        assert f.event_type == "detection"
        assert f.frame_index == 0
        assert f.schema_version == REPLAY_SCHEMA_VERSION

    def test_frozen(self) -> None:
        f = _frame()
        with pytest.raises(ValidationError):
            f.description = "changed"  # type: ignore[misc]

    def test_timezone_naive_timestamp_gets_utc(self) -> None:
        naive = datetime(2026, 1, 1, 12, 0, 0)
        f = ReplayFrame(
            frame_index=0,
            audit_id="a",
            timestamp=naive,
            recorded_at=datetime.now(UTC),
            source_module="test",
        )
        assert f.timestamp.tzinfo is not None

    def test_negative_frame_index_invalid(self) -> None:
        with pytest.raises(ValidationError):
            ReplayFrame(
                frame_index=-1,
                audit_id="x",
                timestamp=datetime.now(UTC),
                recorded_at=datetime.now(UTC),
                source_module="test",
            )

    def test_serialise_round_trip(self) -> None:
        f = _frame(2)
        restored = ReplayFrame.model_validate_json(f.model_dump_json())
        assert restored.audit_id == f.audit_id
        assert restored.frame_index == f.frame_index


class TestReplayTimeline:
    def test_empty(self) -> None:
        tl = ReplayTimeline(frames=(), source_query="empty")
        assert tl.is_empty
        assert tl.length == 0
        assert tl.first_at is None
        assert tl.last_at is None

    def test_with_frames(self) -> None:
        frames = tuple(_frame(i) for i in range(3))
        tl = ReplayTimeline(frames=frames, source_query="test")
        assert not tl.is_empty
        assert tl.length == 3
        assert tl.first_at == frames[0].timestamp
        assert tl.last_at == frames[2].timestamp

    def test_timeline_id_generated(self) -> None:
        tl = ReplayTimeline()
        assert "tl-" in tl.timeline_id

    def test_frozen(self) -> None:
        tl = ReplayTimeline()
        with pytest.raises(ValidationError):
            tl.source_query = "changed"  # type: ignore[misc]

    def test_serialise_round_trip(self) -> None:
        frames = tuple(_frame(i) for i in range(2))
        tl = ReplayTimeline(frames=frames)
        restored = ReplayTimeline.model_validate_json(tl.model_dump_json())
        assert restored.timeline_id == tl.timeline_id
        assert len(restored.frames) == 2


class TestReplaySession:
    def test_session_id_generated(self) -> None:
        s = ReplaySession(timeline=ReplayTimeline())
        assert "rpl-" in s.session_id

    def test_total_frames_property(self) -> None:
        frames = tuple(_frame(i) for i in range(4))
        tl = ReplayTimeline(frames=frames)
        s = ReplaySession(timeline=tl)
        assert s.total_frames == 4

    def test_current_frame_none_when_not_started(self) -> None:
        frames = tuple(_frame(i) for i in range(3))
        s = ReplaySession(timeline=ReplayTimeline(frames=frames))
        assert s.current_index == -1
        assert s.current_frame is None

    def test_position_property(self) -> None:
        s = ReplaySession(timeline=ReplayTimeline(frames=tuple(_frame(i) for i in range(3))))
        pos = s.position
        assert isinstance(pos, ReplayPosition)
        assert pos.total_frames == 3

    def test_frozen(self) -> None:
        s = ReplaySession(timeline=ReplayTimeline())
        with pytest.raises(ValidationError):
            s.name = "changed"  # type: ignore[misc]

    def test_serialise_round_trip(self) -> None:
        frames = tuple(_frame(i) for i in range(2))
        s = ReplaySession(timeline=ReplayTimeline(frames=frames), name="test")
        restored = ReplaySession.model_validate_json(s.model_dump_json())
        assert restored.session_id == s.session_id
        assert restored.total_frames == 2


class TestReplayPosition:
    def test_not_started(self) -> None:
        pos = ReplayPosition(session_id="s-1", index=-1, total_frames=5)
        assert not pos.at_start
        assert not pos.at_end

    def test_at_start(self) -> None:
        pos = ReplayPosition(session_id="s-1", index=0, total_frames=5, is_started=True)
        assert pos.at_start
        assert not pos.at_end

    def test_at_end(self) -> None:
        pos = ReplayPosition(session_id="s-1", index=4, total_frames=5, is_started=True, is_finished=True)
        assert pos.at_end
        assert not pos.at_start

    def test_progress_pct_zero_frames(self) -> None:
        pos = ReplayPosition(session_id="s-1", index=-1, total_frames=0)
        assert pos.progress_pct == 0.0

    def test_progress_pct_mid(self) -> None:
        pos = ReplayPosition(session_id="s-1", index=2, total_frames=5, is_started=True)
        assert pos.progress_pct == 60.0


class TestReplayStatistics:
    def test_defaults(self) -> None:
        stats = ReplayStatistics()
        assert stats.total_sessions == 0
        assert stats.total_frames_across_sessions == 0
        assert stats.replay_type_counts == {}
