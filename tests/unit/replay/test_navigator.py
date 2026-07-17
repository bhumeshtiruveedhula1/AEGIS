"""tests/unit/replay/test_navigator.py — ReplayNavigator lookup and traversal tests."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from backend.replay.exceptions import ReplayNavigationError, ReplaySessionNotFoundError
from backend.replay.navigator import ReplayNavigator

if TYPE_CHECKING:
    from backend.replay.storage import ReplayStore


def _make_and_save(store: ReplayStore, **kwargs) -> str:
    from tests.unit.replay.conftest import _make_session
    s = _make_session(3)
    # Override fields
    s = s.model_copy(update=kwargs)
    store.save(s)
    return s.session_id


class TestReplayNavigatorSessionLookup:
    def test_get_session_existing(self, store: ReplayStore) -> None:
        from tests.unit.replay.conftest import _make_session
        s = _make_session(3)
        store.save(s)
        nav = ReplayNavigator(store)
        loaded = nav.get_session(s.session_id)
        assert loaded.session_id == s.session_id

    def test_get_session_missing_raises(self, store: ReplayStore) -> None:
        nav = ReplayNavigator(store)
        with pytest.raises(ReplaySessionNotFoundError):
            nav.get_session("nonexistent")

    def test_list_sessions_empty(self, store: ReplayStore) -> None:
        nav = ReplayNavigator(store)
        assert nav.list_sessions() == []

    def test_list_sessions_returns_summaries(self, store: ReplayStore) -> None:
        from tests.unit.replay.conftest import _make_session
        for _ in range(3):
            store.save(_make_session(2))
        nav = ReplayNavigator(store)
        summaries = nav.list_sessions()
        assert len(summaries) == 3

    def test_list_sessions_pagination(self, store: ReplayStore) -> None:
        from tests.unit.replay.conftest import _make_session
        for _ in range(5):
            store.save(_make_session(2))
        nav = ReplayNavigator(store)
        page = nav.list_sessions(limit=2, offset=0)
        assert len(page) == 2


class TestReplayNavigatorByField:
    def test_get_by_alert(self, store: ReplayStore) -> None:
        from tests.unit.replay.conftest import _make_session
        s1 = _make_session(2)
        s1 = s1.model_copy(update={"alert_id": "a-special"})
        s2 = _make_session(2)
        store.save(s1)
        store.save(s2)
        nav = ReplayNavigator(store)
        results = nav.get_sessions_by_alert("a-special")
        assert len(results) == 1
        assert results[0].alert_id == "a-special"

    def test_get_by_context(self, store: ReplayStore) -> None:
        from tests.unit.replay.conftest import _make_session
        s = _make_session(2)
        s = s.model_copy(update={"context_id": "ctx-999"})
        store.save(s)
        nav = ReplayNavigator(store)
        results = nav.get_sessions_by_context("ctx-999")
        assert len(results) == 1

    def test_get_by_orchestration(self, store: ReplayStore) -> None:
        from tests.unit.replay.conftest import _make_session
        s = _make_session(2)
        s = s.model_copy(update={"orchestration_id": "orch-001"})
        store.save(s)
        nav = ReplayNavigator(store)
        results = nav.get_sessions_by_orchestration("orch-001")
        assert len(results) == 1

    def test_get_by_type(self, store: ReplayStore) -> None:
        from tests.unit.replay.conftest import _make_session
        s = _make_session(2)
        s = s.model_copy(update={"replay_type": "context"})
        store.save(s)
        store.save(_make_session(2))  # replay_type = "alert"
        nav = ReplayNavigator(store)
        results = nav.get_sessions_by_type("context")
        assert len(results) == 1


class TestReplayNavigatorFrames:
    def test_get_frame(self, store: ReplayStore) -> None:
        from tests.unit.replay.conftest import _make_session
        s = _make_session(3)
        store.save(s)
        nav = ReplayNavigator(store)
        frame = nav.get_frame(s.session_id, 1)
        assert frame.frame_index == 1

    def test_get_frame_out_of_bounds(self, store: ReplayStore) -> None:
        from tests.unit.replay.conftest import _make_session
        s = _make_session(3)
        store.save(s)
        nav = ReplayNavigator(store)
        with pytest.raises(ReplayNavigationError):
            nav.get_frame(s.session_id, 99)

    def test_get_frames_by_event_type(self, store: ReplayStore) -> None:
        from tests.unit.replay.conftest import _make_session
        s = _make_session(3)
        store.save(s)
        nav = ReplayNavigator(store)
        frames = nav.get_frames_by_event_type(s.session_id, "detection")
        assert all(f.event_type == "detection" for f in frames)

    def test_find_frame_by_audit_id(self, store: ReplayStore) -> None:
        from tests.unit.replay.conftest import _make_session
        s = _make_session(3)
        store.save(s)
        target_audit_id = s.timeline.frames[1].audit_id
        nav = ReplayNavigator(store)
        frame = nav.find_frame_by_audit_id(s.session_id, target_audit_id)
        assert frame is not None
        assert frame.audit_id == target_audit_id

    def test_find_frame_by_audit_id_missing(self, store: ReplayStore) -> None:
        from tests.unit.replay.conftest import _make_session
        s = _make_session(3)
        store.save(s)
        nav = ReplayNavigator(store)
        frame = nav.find_frame_by_audit_id(s.session_id, "nonexistent")
        assert frame is None

    def test_get_frames_range(self, store: ReplayStore) -> None:
        from tests.unit.replay.conftest import _make_session
        s = _make_session(5)
        store.save(s)
        nav = ReplayNavigator(store)
        frames = nav.get_frames_range(s.session_id, start=1, end=3)
        assert len(frames) == 2
        assert frames[0].frame_index == 1

    def test_count_sessions(self, store: ReplayStore) -> None:
        from tests.unit.replay.conftest import _make_session
        for _ in range(4):
            store.save(_make_session(2))
        nav = ReplayNavigator(store)
        assert nav.count_sessions() == 4

    def test_count_frames(self, store: ReplayStore) -> None:
        from tests.unit.replay.conftest import _make_session
        s = _make_session(5)
        store.save(s)
        nav = ReplayNavigator(store)
        assert nav.count_frames(s.session_id) == 5
