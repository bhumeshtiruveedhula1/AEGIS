"""
backend.replay.models — Forensic Replay Data Models
=====================================================
Module 7.3 — Forensic Replay Engine

Immutable Pydantic models for the replay engine.
All models are pure data — no replay logic.

Hierarchy
---------
ReplayEventType    — enum of replay-visible event categories
ReplayFrame        — single timestamped event in a timeline
ReplayTimeline     — ordered sequence of ReplayFrames
ReplayPosition     — cursor position within a session
ReplayStep         — result of a navigation action
ReplaySession      — named replay instance with timeline + metadata
ReplaySummary      — lightweight summary of a session
ReplayStatistics   — aggregate stats across all sessions
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import ConfigDict, Field, field_validator

from backend.shared.models import CyberShieldBaseModel
from backend.shared.utils.id_utils import generate_id

REPLAY_SCHEMA_VERSION = "1.0.0"


# ── Event category enum ───────────────────────────────────────────────────────


class ReplayEventType(str, Enum):
    """High-level category used to classify each ReplayFrame."""

    DETECTION = "detection"
    EXPLANATION = "explanation"
    MITRE_MAPPING = "mitre_mapping"
    ATTACK_GRAPH = "attack_graph"
    ATTACK_CHAIN = "attack_chain"
    CONTEXT = "context"
    ORCHESTRATION = "orchestration"
    APPROVAL = "approval"
    EXECUTION = "execution"
    AUDIT = "audit"
    PLATFORM = "platform"
    UNKNOWN = "unknown"


# ── Replay frame ──────────────────────────────────────────────────────────────


class ReplayFrame(CyberShieldBaseModel):
    """
    Single event in a replay timeline.

    A ReplayFrame is a read-only snapshot of one historical event.
    It wraps the audit entry data plus enriched display fields.

    Fields
    ------
    frame_index    : Zero-based position within the parent timeline
    audit_id       : Source AuditEntry identifier
    event_type     : High-level replay category
    timestamp      : UTC event time (from audit record)
    recorded_at    : UTC time the audit entry was written
    source_module  : Backend module that generated the event
    description    : Human-readable event summary
    severity       : Optional severity hint
    outcome        : Optional outcome string
    actor_id       : Actor who performed the event
    correlation    : Correlation IDs (alert_id, context_id, etc.)
    payload        : Original module-specific data (read-only copy)
    schema_version : For forward-compatibility
    """

    model_config = ConfigDict(frozen=True, use_enum_values=True)

    frame_index: int = Field(ge=0)
    audit_id: str
    event_type: ReplayEventType = Field(default=ReplayEventType.UNKNOWN)
    timestamp: datetime
    recorded_at: datetime
    source_module: str
    description: str = Field(default="")
    severity: str | None = Field(default=None)
    outcome: str | None = Field(default=None)
    actor_id: str = Field(default="system")
    correlation: dict[str, str | None] = Field(default_factory=dict)
    payload: dict[str, Any] = Field(default_factory=dict)
    schema_version: str = Field(default=REPLAY_SCHEMA_VERSION)

    @field_validator("timestamp", "recorded_at", mode="before")
    @classmethod
    def _ensure_utc(cls, v: Any) -> datetime:
        if isinstance(v, datetime):
            return v if v.tzinfo is not None else v.replace(tzinfo=UTC)
        return v


# ── Timeline ──────────────────────────────────────────────────────────────────


class ReplayTimeline(CyberShieldBaseModel):
    """
    Ordered, immutable sequence of ReplayFrames.

    Frames are guaranteed to be in chronological order (by timestamp).
    """

    model_config = ConfigDict(frozen=True)

    timeline_id: str = Field(default_factory=lambda: f"tl-{generate_id()}")
    frames: tuple[ReplayFrame, ...] = Field(default_factory=tuple)
    built_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    source_query: str = Field(default="")  # human-readable description of what was replayed

    @property
    def length(self) -> int:
        return len(self.frames)

    @property
    def is_empty(self) -> bool:
        return len(self.frames) == 0

    @property
    def first_at(self) -> datetime | None:
        return self.frames[0].timestamp if self.frames else None

    @property
    def last_at(self) -> datetime | None:
        return self.frames[-1].timestamp if self.frames else None


# ── Position ──────────────────────────────────────────────────────────────────


class ReplayPosition(CyberShieldBaseModel):
    """
    Current cursor position within a replay session.

    index == 0 means at the first frame.
    index == timeline.length - 1 means at the last frame.
    index == -1 means the session has not started.
    """

    model_config = ConfigDict(frozen=True)

    session_id: str
    index: int = Field(default=-1)
    total_frames: int = Field(ge=0)
    is_started: bool = Field(default=False)
    is_finished: bool = Field(default=False)
    is_paused: bool = Field(default=False)

    @property
    def at_start(self) -> bool:
        return self.index == 0

    @property
    def at_end(self) -> bool:
        return self.total_frames > 0 and self.index == self.total_frames - 1

    @property
    def progress_pct(self) -> float:
        """Progress as a percentage 0.0-100.0."""
        if self.total_frames == 0:
            return 0.0
        return round(100.0 * (self.index + 1) / self.total_frames, 2)


# ── Step ──────────────────────────────────────────────────────────────────────


class ReplayStep(CyberShieldBaseModel):
    """
    Result of a single navigation action.

    Returned by player.next(), player.previous(), player.seek(), etc.
    """

    model_config = ConfigDict(frozen=True)

    frame: ReplayFrame | None
    position: ReplayPosition
    action: str = Field(default="")  # 'next' | 'previous' | 'seek' | 'first' | 'last'


# ── Session ───────────────────────────────────────────────────────────────────


class ReplaySession(CyberShieldBaseModel):
    """
    Named replay instance — the root object persisted per replay.

    Contains the full timeline and tracks current position.
    Immutable once created; position updates produce new sessions.
    """

    model_config = ConfigDict(frozen=True)

    session_id: str = Field(default_factory=lambda: f"rpl-{generate_id()}")
    schema_version: str = Field(default=REPLAY_SCHEMA_VERSION)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    # Descriptive metadata
    name: str = Field(default="")
    description: str = Field(default="")
    replay_type: str = Field(default="audit")  # audit | context | alert | orchestration

    # Source correlation IDs
    alert_id: str | None = Field(default=None)
    context_id: str | None = Field(default=None)
    orchestration_id: str | None = Field(default=None)

    # Timeline and position
    timeline: ReplayTimeline
    current_index: int = Field(default=-1)
    is_started: bool = Field(default=False)
    is_finished: bool = Field(default=False)
    is_paused: bool = Field(default=False)

    @property
    def total_frames(self) -> int:
        return self.timeline.length

    @property
    def current_frame(self) -> ReplayFrame | None:
        if 0 <= self.current_index < self.timeline.length:
            return self.timeline.frames[self.current_index]
        return None

    @property
    def position(self) -> ReplayPosition:
        return ReplayPosition(
            session_id=self.session_id,
            index=self.current_index,
            total_frames=self.total_frames,
            is_started=self.is_started,
            is_finished=self.is_finished,
            is_paused=self.is_paused,
        )


# ── Summary ───────────────────────────────────────────────────────────────────


class ReplaySummary(CyberShieldBaseModel):
    """Lightweight summary of a ReplaySession — no timeline frames."""

    model_config = ConfigDict(frozen=True)

    session_id: str
    name: str
    replay_type: str
    total_frames: int
    alert_id: str | None
    context_id: str | None
    orchestration_id: str | None
    created_at: datetime
    is_started: bool
    is_finished: bool
    first_event_at: datetime | None
    last_event_at: datetime | None


# ── Statistics ────────────────────────────────────────────────────────────────


class ReplayStatistics(CyberShieldBaseModel):
    """Aggregate statistics across all persisted replay sessions."""

    model_config = ConfigDict(frozen=True)

    total_sessions: int = Field(default=0, ge=0)
    total_frames_across_sessions: int = Field(default=0, ge=0)
    replay_type_counts: dict[str, int] = Field(default_factory=dict)
    sessions_started: int = Field(default=0, ge=0)
    sessions_finished: int = Field(default=0, ge=0)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
