"""tests/unit/replay/test_player.py — ReplayPlayer navigation tests."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from backend.replay.exceptions import ReplayNavigationError
from backend.replay.player import ReplayPlayer

if TYPE_CHECKING:
    from backend.replay.models import ReplaySession


class TestReplayPlayerStart:
    def test_start_sets_index_zero(self, player_3: ReplayPlayer) -> None:
        step = player_3.start()
        assert player_3.session.current_index == 0
        assert step.action == "start"

    def test_start_returns_first_frame(self, player_3: ReplayPlayer) -> None:
        step = player_3.start()
        assert step.frame is not None
        assert step.frame.frame_index == 0

    def test_start_empty_raises(self, empty_session: ReplaySession) -> None:
        p = ReplayPlayer(empty_session)
        with pytest.raises(ReplayNavigationError):
            p.start()

    def test_start_sets_is_started(self, player_3: ReplayPlayer) -> None:
        player_3.start()
        assert player_3.session.is_started

    def test_start_clears_finished(self, session_3: ReplaySession) -> None:
        p = ReplayPlayer(session_3)
        p.start()
        p.last()
        p.stop()
        p.start()
        assert not p.session.is_finished


class TestReplayPlayerStop:
    def test_stop_resets_index(self, started_player: ReplayPlayer) -> None:
        started_player.stop()
        assert started_player.session.current_index == -1

    def test_stop_clears_started(self, started_player: ReplayPlayer) -> None:
        started_player.stop()
        assert not started_player.session.is_started

    def test_stop_returns_no_frame(self, started_player: ReplayPlayer) -> None:
        step = started_player.stop()
        assert step.frame is None
        assert step.action == "stop"


class TestReplayPlayerPauseResume:
    def test_pause_sets_paused(self, started_player: ReplayPlayer) -> None:
        started_player.pause()
        assert started_player.session.is_paused

    def test_resume_clears_paused(self, started_player: ReplayPlayer) -> None:
        started_player.pause()
        started_player.resume()
        assert not started_player.session.is_paused

    def test_pause_without_start_raises(self, player_3: ReplayPlayer) -> None:
        with pytest.raises(ReplayNavigationError):
            player_3.pause()

    def test_resume_without_pause_raises(self, started_player: ReplayPlayer) -> None:
        with pytest.raises(ReplayNavigationError):
            started_player.resume()

    def test_pause_keeps_current_frame(self, started_player: ReplayPlayer) -> None:
        started_player.next()
        step = started_player.pause()
        assert step.frame is not None
        assert step.frame.frame_index == 1


class TestReplayPlayerNext:
    def test_next_advances_index(self, started_player: ReplayPlayer) -> None:
        started_player.next()
        assert started_player.session.current_index == 1

    def test_next_without_start_raises(self, player_3: ReplayPlayer) -> None:
        with pytest.raises(ReplayNavigationError):
            player_3.next()

    def test_next_at_last_marks_finished(self, session_3: ReplaySession) -> None:
        p = ReplayPlayer(session_3)
        p.start()
        p.next()
        p.next()
        assert p.session.is_finished

    def test_next_after_finished_raises(self, session_3: ReplaySession) -> None:
        p = ReplayPlayer(session_3)
        p.start()
        p.next()
        p.next()
        with pytest.raises(ReplayNavigationError):
            p.next()

    def test_next_returns_frame(self, started_player: ReplayPlayer) -> None:
        step = started_player.next()
        assert step.frame is not None
        assert step.action == "next"
        assert step.frame.frame_index == 1


class TestReplayPlayerPrevious:
    def test_previous_decrements_index(self, session_3: ReplaySession) -> None:
        p = ReplayPlayer(session_3)
        p.start()
        p.next()
        p.previous()
        assert p.session.current_index == 0

    def test_previous_at_start_raises(self, started_player: ReplayPlayer) -> None:
        with pytest.raises(ReplayNavigationError):
            started_player.previous()

    def test_previous_without_start_raises(self, player_3: ReplayPlayer) -> None:
        with pytest.raises(ReplayNavigationError):
            player_3.previous()

    def test_previous_clears_finished(self, session_3: ReplaySession) -> None:
        p = ReplayPlayer(session_3)
        p.last()
        p.previous()
        assert not p.session.is_finished


class TestReplayPlayerSeek:
    def test_seek_valid_index(self, player_3: ReplayPlayer) -> None:
        step = player_3.seek(2)
        assert step.frame is not None
        assert step.frame.frame_index == 2
        assert step.action == "seek"

    def test_seek_zero(self, player_3: ReplayPlayer) -> None:
        player_3.seek(2)
        player_3.seek(0)
        assert player_3.session.current_index == 0
        assert not player_3.session.is_finished

    def test_seek_last_marks_finished(self, player_3: ReplayPlayer) -> None:
        player_3.seek(2)
        assert player_3.session.is_finished

    def test_seek_out_of_bounds_raises(self, player_3: ReplayPlayer) -> None:
        with pytest.raises(ReplayNavigationError):
            player_3.seek(99)

    def test_seek_negative_raises(self, player_3: ReplayPlayer) -> None:
        with pytest.raises(ReplayNavigationError):
            player_3.seek(-1)

    def test_seek_empty_raises(self, empty_session: ReplaySession) -> None:
        p = ReplayPlayer(empty_session)
        with pytest.raises(ReplayNavigationError):
            p.seek(0)


class TestReplayPlayerFirstLast:
    def test_first_jumps_to_zero(self, session_3: ReplaySession) -> None:
        p = ReplayPlayer(session_3)
        p.seek(2)
        step = p.first()
        assert p.session.current_index == 0
        assert step.action == "first"

    def test_last_jumps_to_end(self, player_3: ReplayPlayer) -> None:
        step = player_3.last()
        assert player_3.session.current_index == 2
        assert player_3.session.is_finished
        assert step.action == "last"

    def test_first_empty_raises(self, empty_session: ReplaySession) -> None:
        p = ReplayPlayer(empty_session)
        with pytest.raises(ReplayNavigationError):
            p.first()

    def test_last_empty_raises(self, empty_session: ReplaySession) -> None:
        p = ReplayPlayer(empty_session)
        with pytest.raises(ReplayNavigationError):
            p.last()


class TestReplayPlayerGetFrame:
    def test_get_frame_does_not_change_position(self, started_player: ReplayPlayer) -> None:
        idx_before = started_player.session.current_index
        started_player.get_frame(2)
        assert started_player.session.current_index == idx_before

    def test_get_frame_out_of_bounds_raises(self, player_3: ReplayPlayer) -> None:
        with pytest.raises(ReplayNavigationError):
            player_3.get_frame(99)

    def test_get_frames_slice(self, player_3: ReplayPlayer) -> None:
        frames = player_3.get_frames(0, 2)
        assert len(frames) == 2
        assert frames[0].frame_index == 0
        assert frames[1].frame_index == 1


class TestReplayPlayerProgress:
    def test_progress_at_start(self, session_3: ReplaySession) -> None:
        p = ReplayPlayer(session_3)
        p.start()
        assert p.position.progress_pct == pytest.approx(100 / 3, rel=0.01)

    def test_progress_at_end(self, player_3: ReplayPlayer) -> None:
        player_3.last()
        assert player_3.position.progress_pct == 100.0
