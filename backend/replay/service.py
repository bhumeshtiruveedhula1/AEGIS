"""
backend.replay.service — Forensic Replay Service
=================================================
Module 7.3 — Forensic Replay Engine

Single public facade for all Forensic Replay operations.

Responsibilities
----------------
- Build replay sessions from stored audit data
- Load and save sessions
- Navigate by alert / context / orchestration / audit history
- Expose replay data for the dashboard
- Generate replay statistics

The service reads from AuditService. It never regenerates upstream data.
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import structlog

from backend.audit.service import AuditService
from backend.replay.models import (
    ReplaySession,
    ReplayStatistics,
    ReplayStep,
    ReplaySummary,
)
from backend.replay.navigator import ReplayNavigator
from backend.replay.player import ReplayPlayer
from backend.replay.storage import ReplayStore
from backend.replay.timeline import TimelineBuilder

if TYPE_CHECKING:
    from pathlib import Path

    from backend.replay.models import ReplayFrame

logger = structlog.get_logger(__name__)


class ReplayService:
    """
    Public facade for the Forensic Replay Engine.

    Parameters
    ----------
    store_dir   : Directory for storing ReplaySession files.
                  Defaults to <data_dir>/replay from project settings.
    audit_service : AuditService instance. Created from settings if None.
    """

    def __init__(
        self,
        store_dir: Path | None = None,
        audit_service: AuditService | None = None,
    ) -> None:
        if store_dir is None:
            from backend.core.config import get_settings
            store_dir = get_settings().data_dir / "replay"

        self._store = ReplayStore(store_dir)
        self._navigator = ReplayNavigator(self._store)
        self._builder = TimelineBuilder()
        self._audit = audit_service or AuditService()
        logger.debug("replay_service_ready", store_dir=str(store_dir))

    # ── Build sessions ────────────────────────────────────────────────────────

    def build_session_for_alert(
        self,
        alert_id: str,
        *,
        name: str = "",
        persist: bool = True,
    ) -> ReplaySession:
        """
        Build a replay session containing all audit events for an alert.

        Parameters
        ----------
        alert_id : Alert correlation ID.
        name     : Optional display name.
        persist  : Whether to save the session (default True).
        """
        entries = self._audit.get_by_alert(alert_id, limit=10_000)
        timeline = self._builder.build_for_alert(entries, alert_id)
        session = ReplaySession(
            name=name or f"Alert replay: {alert_id}",
            replay_type="alert",
            alert_id=alert_id,
            timeline=timeline,
        )
        if persist:
            self._store.save(session)
        logger.info(
            "replay_session_built",
            session_id=session.session_id,
            replay_type="alert",
            frames=session.total_frames,
            alert_id=alert_id,
        )
        return session

    def build_session_for_context(
        self,
        context_id: str,
        *,
        name: str = "",
        persist: bool = True,
    ) -> ReplaySession:
        """Build a replay session for all events linked to a context_id."""
        entries = self._audit.get_by_context(context_id, limit=10_000)
        timeline = self._builder.build_for_context(entries, context_id)
        session = ReplaySession(
            name=name or f"Context replay: {context_id}",
            replay_type="context",
            context_id=context_id,
            timeline=timeline,
        )
        if persist:
            self._store.save(session)
        logger.info(
            "replay_session_built",
            session_id=session.session_id,
            replay_type="context",
            frames=session.total_frames,
            context_id=context_id,
        )
        return session

    def build_session_for_orchestration(
        self,
        orchestration_id: str,
        *,
        name: str = "",
        persist: bool = True,
    ) -> ReplaySession:
        """Build a replay session for all events linked to an orchestration_id."""
        entries = self._audit.get_by_orchestration(orchestration_id, limit=10_000)
        timeline = self._builder.build_for_orchestration(entries, orchestration_id)
        session = ReplaySession(
            name=name or f"Orchestration replay: {orchestration_id}",
            replay_type="orchestration",
            orchestration_id=orchestration_id,
            timeline=timeline,
        )
        if persist:
            self._store.save(session)
        return session

    def build_session_for_date(
        self,
        date: datetime | None = None,
        *,
        name: str = "",
        persist: bool = True,
    ) -> ReplaySession:
        """Build a full-day replay session from all audit events for a date."""
        target = date or datetime.now(UTC)
        entries = self._audit.get_for_date(target)
        date_str = target.strftime("%Y-%m-%d")
        timeline = self._builder.build(entries, source_query=f"date:{date_str}")
        session = ReplaySession(
            name=name or f"Daily audit replay: {date_str}",
            replay_type="audit",
            timeline=timeline,
        )
        if persist:
            self._store.save(session)
        return session

    # ── Session management ────────────────────────────────────────────────────

    def load_session(self, session_id: str) -> ReplaySession:
        """Load a stored session by ID."""
        return self._store.load(session_id)

    def save_session(self, session: ReplaySession) -> None:
        """Persist an updated session (e.g. after player navigation)."""
        self._store.save(session)

    def list_sessions(self, *, limit: int = 100, offset: int = 0) -> list[ReplaySummary]:
        """List summaries of all stored sessions, newest first."""
        return self._navigator.list_sessions(limit=limit, offset=offset)

    def get_sessions_by_alert(self, alert_id: str) -> list[ReplaySummary]:
        return self._navigator.get_sessions_by_alert(alert_id)

    def get_sessions_by_context(self, context_id: str) -> list[ReplaySummary]:
        return self._navigator.get_sessions_by_context(context_id)

    # ── Player operations ─────────────────────────────────────────────────────

    def get_player(self, session_id: str) -> ReplayPlayer:
        """Return a ReplayPlayer loaded with the requested session."""
        session = self._store.load(session_id)
        return ReplayPlayer(session)

    def player_start(self, session_id: str) -> tuple[ReplayStep, ReplaySession]:
        """Start playback and persist updated session."""
        player = self.get_player(session_id)
        step = player.start()
        self._store.save(player.session)
        return step, player.session

    def player_next(self, session_id: str) -> tuple[ReplayStep, ReplaySession]:
        """Advance one frame and persist."""
        player = self.get_player(session_id)
        step = player.next()
        self._store.save(player.session)
        return step, player.session

    def player_previous(self, session_id: str) -> tuple[ReplayStep, ReplaySession]:
        """Go back one frame and persist."""
        player = self.get_player(session_id)
        step = player.previous()
        self._store.save(player.session)
        return step, player.session

    def player_seek(self, session_id: str, index: int) -> tuple[ReplayStep, ReplaySession]:
        """Seek to frame index and persist."""
        player = self.get_player(session_id)
        step = player.seek(index)
        self._store.save(player.session)
        return step, player.session

    def player_first(self, session_id: str) -> tuple[ReplayStep, ReplaySession]:
        player = self.get_player(session_id)
        step = player.first()
        self._store.save(player.session)
        return step, player.session

    def player_last(self, session_id: str) -> tuple[ReplayStep, ReplaySession]:
        player = self.get_player(session_id)
        step = player.last()
        self._store.save(player.session)
        return step, player.session

    def player_pause(self, session_id: str) -> tuple[ReplayStep, ReplaySession]:
        player = self.get_player(session_id)
        step = player.pause()
        self._store.save(player.session)
        return step, player.session

    def player_resume(self, session_id: str) -> tuple[ReplayStep, ReplaySession]:
        player = self.get_player(session_id)
        step = player.resume()
        self._store.save(player.session)
        return step, player.session

    # ── Frame access ──────────────────────────────────────────────────────────

    def get_frame(self, session_id: str, frame_index: int) -> ReplayFrame:
        """Retrieve a single frame without changing session position."""
        return self._navigator.get_frame(session_id, frame_index)

    def get_frames(
        self,
        session_id: str,
        *,
        start: int = 0,
        end: int | None = None,
    ) -> list[ReplayFrame]:
        """Return a slice of frames without changing session position."""
        return self._navigator.get_frames_range(session_id, start=start, end=end)

    # ── Statistics ────────────────────────────────────────────────────────────

    def get_statistics(self) -> ReplayStatistics:
        """Generate aggregate statistics across all stored sessions."""
        sessions = self._store.load_all()
        if not sessions:
            return ReplayStatistics()

        type_counts: Counter[str] = Counter()
        total_frames = 0
        started = 0
        finished = 0

        for s in sessions:
            type_counts[s.replay_type] += 1
            total_frames += s.total_frames
            if s.is_started:
                started += 1
            if s.is_finished:
                finished += 1

        return ReplayStatistics(
            total_sessions=len(sessions),
            total_frames_across_sessions=total_frames,
            replay_type_counts=dict(type_counts),
            sessions_started=started,
            sessions_finished=finished,
        )

    def count_sessions(self) -> int:
        """Total number of stored replay sessions."""
        return self._store.count()
