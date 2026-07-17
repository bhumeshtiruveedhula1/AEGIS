"""
backend.replay.navigator — Forensic Replay Navigator
=====================================================
Module 7.3 — Forensic Replay Engine

Provides efficient lookup and chronological traversal over
stored ReplaySessions and ReplayFrames.

The Navigator is read-only — it does not mutate sessions.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from backend.replay.exceptions import ReplayNavigationError
from backend.replay.models import ReplayFrame, ReplaySession, ReplaySummary

if TYPE_CHECKING:
    from backend.replay.storage import ReplayStore

logger = structlog.get_logger(__name__)


class ReplayNavigator:
    """
    Provides lookup and traversal over persisted ReplaySessions.

    Parameters
    ----------
    store : ReplayStore instance to navigate over.
    """

    def __init__(self, store: ReplayStore) -> None:
        self._store = store

    # ── Session lookup ────────────────────────────────────────────────────────

    def get_session(self, session_id: str) -> ReplaySession:
        """Load a single session by ID."""
        return self._store.load(session_id)

    def list_sessions(self, *, limit: int = 100, offset: int = 0) -> list[ReplaySummary]:
        """Return summaries of all stored sessions, newest first."""
        all_ids = self._store.list_ids()
        page_ids = all_ids[offset : offset + limit]
        summaries: list[ReplaySummary] = []
        for sid in page_ids:
            try:
                session = self._store.load(sid)
                summaries.append(_session_to_summary(session))
            except Exception:
                pass
        return summaries

    def get_sessions_by_alert(self, alert_id: str) -> list[ReplaySummary]:
        """Return summaries of all sessions linked to an alert_id."""
        all_sessions = self._store.load_all()
        return [
            _session_to_summary(s)
            for s in all_sessions
            if s.alert_id == alert_id
        ]

    def get_sessions_by_context(self, context_id: str) -> list[ReplaySummary]:
        """Return summaries of all sessions linked to a context_id."""
        all_sessions = self._store.load_all()
        return [
            _session_to_summary(s)
            for s in all_sessions
            if s.context_id == context_id
        ]

    def get_sessions_by_orchestration(self, orchestration_id: str) -> list[ReplaySummary]:
        """Return summaries of all sessions linked to an orchestration_id."""
        all_sessions = self._store.load_all()
        return [
            _session_to_summary(s)
            for s in all_sessions
            if s.orchestration_id == orchestration_id
        ]

    def get_sessions_by_type(self, replay_type: str) -> list[ReplaySummary]:
        """Return summaries of all sessions with the given replay_type."""
        all_sessions = self._store.load_all()
        return [
            _session_to_summary(s)
            for s in all_sessions
            if s.replay_type == replay_type
        ]

    # ── Frame lookup ──────────────────────────────────────────────────────────

    def get_frame(self, session_id: str, frame_index: int) -> ReplayFrame:
        """Return a single frame from a session by index."""
        session = self._store.load(session_id)
        if not (0 <= frame_index < session.total_frames):
            raise ReplayNavigationError(
                f"Frame index {frame_index} out of range [0, {session.total_frames - 1}].",
                context={"session_id": session_id, "requested": frame_index},
            )
        return session.timeline.frames[frame_index]

    def get_frames_by_event_type(
        self,
        session_id: str,
        event_type: str,
    ) -> list[ReplayFrame]:
        """Return all frames in a session matching the given event_type."""
        session = self._store.load(session_id)
        return [
            f for f in session.timeline.frames
            if str(f.event_type) == event_type
        ]

    def get_frames_by_source_module(
        self,
        session_id: str,
        source_module: str,
    ) -> list[ReplayFrame]:
        """Return all frames in a session from the given source_module."""
        session = self._store.load(session_id)
        return [
            f for f in session.timeline.frames
            if f.source_module == source_module
        ]

    def find_frame_by_audit_id(
        self,
        session_id: str,
        audit_id: str,
    ) -> ReplayFrame | None:
        """Find the frame in a session with the given audit_id."""
        session = self._store.load(session_id)
        for frame in session.timeline.frames:
            if frame.audit_id == audit_id:
                return frame
        return None

    def get_frames_range(
        self,
        session_id: str,
        *,
        start: int = 0,
        end: int | None = None,
    ) -> list[ReplayFrame]:
        """Return a slice of frames [start:end] from a session."""
        session = self._store.load(session_id)
        frames = session.timeline.frames
        return list(frames[start:end])

    # ── Statistics helpers ────────────────────────────────────────────────────

    def count_sessions(self) -> int:
        """Total number of stored sessions."""
        return len(self._store.list_ids())

    def count_frames(self, session_id: str) -> int:
        """Total frames in a specific session."""
        session = self._store.load(session_id)
        return session.total_frames


# ── Helper ────────────────────────────────────────────────────────────────────

def _session_to_summary(session: ReplaySession) -> ReplaySummary:
    return ReplaySummary(
        session_id=session.session_id,
        name=session.name,
        replay_type=session.replay_type,
        total_frames=session.total_frames,
        alert_id=session.alert_id,
        context_id=session.context_id,
        orchestration_id=session.orchestration_id,
        created_at=session.created_at,
        is_started=session.is_started,
        is_finished=session.is_finished,
        first_event_at=session.timeline.first_at,
        last_event_at=session.timeline.last_at,
    )
