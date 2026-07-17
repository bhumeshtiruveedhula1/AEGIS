"""
backend.replay — Forensic Replay Engine
========================================
Module 7.3 — Forensic Replay Engine for Operation AEGIS

Read-only replay of historical security incidents from the Audit Ledger.
Deterministic. Chronological. Never regenerates upstream data.

Public API
----------
    from backend.replay.service import ReplayService
    from backend.replay.models import ReplaySession, ReplayEventType
    from backend.replay.player import ReplayPlayer

    svc = ReplayService()
    session = svc.build_session_for_alert("alert-001")
    player = ReplayPlayer(session)
    step = player.start()
    while not player.session.is_finished:
        step = player.next()
        print(step.frame.description)
"""

from backend.replay.exceptions import (
    ReplayError,
    ReplayNavigationError,
    ReplaySchemaError,
    ReplaySessionNotFoundError,
    ReplaySourceError,
    ReplayStorageError,
    ReplayTimelineError,
)
from backend.replay.models import (
    REPLAY_SCHEMA_VERSION,
    ReplayEventType,
    ReplayFrame,
    ReplayPosition,
    ReplaySession,
    ReplayStatistics,
    ReplayStep,
    ReplaySummary,
    ReplayTimeline,
)
from backend.replay.player import ReplayPlayer
from backend.replay.service import ReplayService

__all__ = [
    # Service
    "ReplayService",
    "ReplayPlayer",
    # Models
    "REPLAY_SCHEMA_VERSION",
    "ReplayEventType",
    "ReplayFrame",
    "ReplayPosition",
    "ReplaySession",
    "ReplayStatistics",
    "ReplaySummary",
    "ReplayStep",
    "ReplayTimeline",
    # Exceptions
    "ReplayError",
    "ReplayNavigationError",
    "ReplaySchemaError",
    "ReplaySessionNotFoundError",
    "ReplaySourceError",
    "ReplayStorageError",
    "ReplayTimelineError",
]
