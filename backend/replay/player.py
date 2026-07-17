"""
backend.replay.player — Forensic Replay Player
===============================================
Module 7.3 — Forensic Replay Engine

Implements replay playback over a ReplaySession.

The player is purely navigational — it advances/retreats through stored
ReplayFrames. It never regenerates data. All frames are pre-built
and stored in the ReplayTimeline.

Supported operations
--------------------
start    — Begin playback from the first frame
stop     — Stop playback and reset to -1 (before start)
pause    — Pause at current position
resume   — Resume from paused position
next     — Advance one frame
previous — Go back one frame
first    — Jump to frame 0
last     — Jump to the final frame
seek     — Jump to any frame by index
"""

from __future__ import annotations

import structlog

from backend.replay.exceptions import ReplayNavigationError
from backend.replay.models import ReplayFrame, ReplayPosition, ReplaySession, ReplayStep

logger = structlog.get_logger(__name__)


class ReplayPlayer:
    """
    Stateless replay player — produces updated ReplaySession snapshots.

    Every operation returns a new (session, step) pair rather than
    mutating state. Callers decide whether to persist the updated session.

    Parameters
    ----------
    session : The ReplaySession to operate on.
    """

    def __init__(self, session: ReplaySession) -> None:
        self._session = session

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def session(self) -> ReplaySession:
        return self._session

    @property
    def position(self) -> ReplayPosition:
        return self._session.position

    @property
    def current_frame(self) -> ReplayFrame | None:
        return self._session.current_frame

    @property
    def total_frames(self) -> int:
        return self._session.total_frames

    # ── Playback controls ─────────────────────────────────────────────────────

    def start(self) -> ReplayStep:
        """Begin playback at frame 0."""
        if self._session.total_frames == 0:
            raise ReplayNavigationError(
                "Cannot start replay: timeline is empty.",
                context={"session_id": self._session.session_id},
            )
        self._session = self._update(index=0, is_started=True, is_paused=False, is_finished=False)
        return ReplayStep(
            frame=self._session.current_frame,
            position=self._session.position,
            action="start",
        )

    def stop(self) -> ReplayStep:
        """Stop playback and reset position to -1 (before start)."""
        self._session = self._update(index=-1, is_started=False, is_paused=False, is_finished=False)
        return ReplayStep(
            frame=None,
            position=self._session.position,
            action="stop",
        )

    def pause(self) -> ReplayStep:
        """Pause at current frame."""
        if not self._session.is_started:
            raise ReplayNavigationError(
                "Cannot pause: replay has not started.",
                context={"session_id": self._session.session_id},
            )
        self._session = self._update(is_paused=True)
        return ReplayStep(
            frame=self._session.current_frame,
            position=self._session.position,
            action="pause",
        )

    def resume(self) -> ReplayStep:
        """Resume from paused state."""
        if not self._session.is_paused:
            raise ReplayNavigationError(
                "Cannot resume: replay is not paused.",
                context={"session_id": self._session.session_id},
            )
        self._session = self._update(is_paused=False)
        return ReplayStep(
            frame=self._session.current_frame,
            position=self._session.position,
            action="resume",
        )

    def next(self) -> ReplayStep:
        """Advance one frame. Marks session as finished when at last frame."""
        if not self._session.is_started:
            raise ReplayNavigationError(
                "Cannot advance: replay has not started. Call start() first.",
                context={"session_id": self._session.session_id},
            )
        if self._session.is_finished:
            raise ReplayNavigationError(
                "Cannot advance: replay has finished.",
                context={"session_id": self._session.session_id},
            )

        new_index = self._session.current_index + 1
        is_finished = new_index >= self._session.total_frames - 1

        # Cap at last frame
        new_index = min(new_index, self._session.total_frames - 1)
        self._session = self._update(index=new_index, is_finished=is_finished)

        logger.debug(
            "replay_next",
            session_id=self._session.session_id,
            index=new_index,
            total=self._session.total_frames,
        )
        return ReplayStep(
            frame=self._session.current_frame,
            position=self._session.position,
            action="next",
        )

    def previous(self) -> ReplayStep:
        """Go back one frame."""
        if not self._session.is_started:
            raise ReplayNavigationError(
                "Cannot go back: replay has not started.",
                context={"session_id": self._session.session_id},
            )
        if self._session.current_index <= 0:
            raise ReplayNavigationError(
                "Cannot go back: already at first frame.",
                context={"session_id": self._session.session_id, "index": self._session.current_index},
            )

        new_index = self._session.current_index - 1
        self._session = self._update(index=new_index, is_finished=False)

        logger.debug(
            "replay_previous",
            session_id=self._session.session_id,
            index=new_index,
        )
        return ReplayStep(
            frame=self._session.current_frame,
            position=self._session.position,
            action="previous",
        )

    def first(self) -> ReplayStep:
        """Jump to the first frame."""
        if self._session.total_frames == 0:
            raise ReplayNavigationError(
                "Cannot seek to first: timeline is empty.",
                context={"session_id": self._session.session_id},
            )
        self._session = self._update(index=0, is_started=True, is_paused=False, is_finished=False)
        return ReplayStep(
            frame=self._session.current_frame,
            position=self._session.position,
            action="first",
        )

    def last(self) -> ReplayStep:
        """Jump to the last frame."""
        if self._session.total_frames == 0:
            raise ReplayNavigationError(
                "Cannot seek to last: timeline is empty.",
                context={"session_id": self._session.session_id},
            )
        last_idx = self._session.total_frames - 1
        self._session = self._update(index=last_idx, is_started=True, is_paused=False, is_finished=True)
        return ReplayStep(
            frame=self._session.current_frame,
            position=self._session.position,
            action="last",
        )

    def seek(self, index: int) -> ReplayStep:
        """
        Jump to any frame by index.

        Parameters
        ----------
        index : Zero-based frame index. Must be within [0, total_frames - 1].
        """
        if self._session.total_frames == 0:
            raise ReplayNavigationError(
                "Cannot seek: timeline is empty.",
                context={"session_id": self._session.session_id},
            )
        if not (0 <= index < self._session.total_frames):
            raise ReplayNavigationError(
                f"Seek index {index} out of range [0, {self._session.total_frames - 1}].",
                context={
                    "session_id": self._session.session_id,
                    "requested": index,
                    "total": self._session.total_frames,
                },
            )
        is_finished = index == self._session.total_frames - 1
        self._session = self._update(index=index, is_started=True, is_paused=False, is_finished=is_finished)

        logger.debug(
            "replay_seek",
            session_id=self._session.session_id,
            index=index,
        )
        return ReplayStep(
            frame=self._session.current_frame,
            position=self._session.position,
            action="seek",
        )

    def get_frame(self, index: int) -> ReplayFrame:
        """Retrieve any frame by index without changing position."""
        if not (0 <= index < self._session.total_frames):
            raise ReplayNavigationError(
                f"Frame index {index} out of range.",
                context={"requested": index, "total": self._session.total_frames},
            )
        return self._session.timeline.frames[index]

    def get_frames(self, start: int = 0, end: int | None = None) -> list[ReplayFrame]:
        """Return a slice of frames [start:end] without changing position."""
        frames = self._session.timeline.frames
        return list(frames[start:end])

    # ── Internal ──────────────────────────────────────────────────────────────

    def _update(
        self,
        *,
        index: int | None = None,
        is_started: bool | None = None,
        is_paused: bool | None = None,
        is_finished: bool | None = None,
    ) -> ReplaySession:
        """Produce an updated (frozen) ReplaySession copy."""
        from datetime import UTC, datetime

        updates: dict[str, object] = {"updated_at": datetime.now(UTC)}
        if index is not None:
            updates["current_index"] = index
        if is_started is not None:
            updates["is_started"] = is_started
        if is_paused is not None:
            updates["is_paused"] = is_paused
        if is_finished is not None:
            updates["is_finished"] = is_finished
        return self._session.model_copy(update=updates)
