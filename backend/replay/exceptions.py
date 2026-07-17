"""backend.replay.exceptions — Forensic Replay Exception Hierarchy."""

from __future__ import annotations

from backend.core.exceptions import CyberShieldError


class ReplayError(CyberShieldError):
    """Base for all Forensic Replay errors."""

    http_status_code = 500
    error_code = "replay_error"


class ReplaySessionNotFoundError(ReplayError):
    """Raised when a requested replay session does not exist."""

    http_status_code = 404
    error_code = "replay_session_not_found"


class ReplayStorageError(ReplayError):
    """Raised on I/O failure persisting or loading replay sessions."""

    error_code = "replay_storage_error"


class ReplaySchemaError(ReplayError):
    """Raised when a persisted replay record cannot be deserialised."""

    error_code = "replay_schema_error"


class ReplayTimelineError(ReplayError):
    """Raised when timeline construction fails."""

    error_code = "replay_timeline_error"


class ReplayNavigationError(ReplayError):
    """Raised when navigation cannot be completed (e.g. out of bounds)."""

    http_status_code = 400
    error_code = "replay_navigation_error"


class ReplaySourceError(ReplayError):
    """Raised when a required source record cannot be loaded."""

    http_status_code = 404
    error_code = "replay_source_error"
