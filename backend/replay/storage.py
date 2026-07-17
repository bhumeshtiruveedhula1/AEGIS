"""
backend.replay.storage — Replay Session Persistence
====================================================
Module 7.3 — Forensic Replay Engine

Stores ReplaySession objects using the same atomic JSON index strategy
used by OrchestratorStore, ContextStore, and AuditStore.

Note: ReplaySessions are indexed by session_id only (no date-partitioned
JSONL) because sessions are large, rarely queried by date, and most
usefully retrieved by ID. A sessions.jsonl log is kept for ordered listing.

File layout
-----------
replay/
├── sessions.jsonl         ← append log of all session IDs (for ordering)
└── index/
    └── <session_id>.json  ← full ReplaySession (atomic write)
"""

from __future__ import annotations

import contextlib
import threading
from typing import TYPE_CHECKING

import structlog

from backend.replay.exceptions import (
    ReplaySchemaError,
    ReplaySessionNotFoundError,
    ReplayStorageError,
)
from backend.replay.models import REPLAY_SCHEMA_VERSION, ReplaySession

if TYPE_CHECKING:
    from pathlib import Path

logger = structlog.get_logger(__name__)

_LOG_FILE = "sessions.jsonl"
_INDEX_SUBDIR = "index"


class ReplayStore:
    """
    Thread-safe storage for ReplaySession objects.

    Each session is stored as a single atomic JSON file in the index.
    A JSONL log tracks insertion order for list_ids().

    Parameters
    ----------
    store_dir : Root storage directory.
    """

    def __init__(self, store_dir: Path) -> None:
        self._dir = store_dir
        self._index_dir = store_dir / _INDEX_SUBDIR
        self._log_path = store_dir / _LOG_FILE
        self._dir.mkdir(parents=True, exist_ok=True)
        self._index_dir.mkdir(parents=True, exist_ok=True)
        self._log_lock = threading.Lock()
        self._id_lock = threading.Lock()
        logger.debug("replay_store_initialized", store_dir=str(store_dir))

    # ── Write ──────────────────────────────────────────────────────────────────

    def save(self, session: ReplaySession) -> None:
        """Persist or update a ReplaySession atomically."""
        is_new = not (self._index_dir / f"{session.session_id}.json").exists()
        self._write_index(session)
        if is_new:
            self._append_log(session.session_id)
        logger.debug(
            "replay_session_saved",
            session_id=session.session_id,
            frames=session.total_frames,
            is_new=is_new,
        )

    # ── Read ───────────────────────────────────────────────────────────────────

    def load(self, session_id: str) -> ReplaySession:
        """Load a single ReplaySession by ID."""
        path = self._index_dir / f"{session_id}.json"
        if not path.exists():
            raise ReplaySessionNotFoundError(
                f"ReplaySession {session_id!r} not found.",
                context={"session_id": session_id},
            )
        raw = path.read_text(encoding="utf-8")
        try:
            session = ReplaySession.model_validate_json(raw)
        except Exception as exc:
            raise ReplaySchemaError(
                f"Schema error loading session {session_id}: {exc}",
                context={"session_id": session_id, "cause": str(exc)},
            ) from exc
        if session.schema_version != REPLAY_SCHEMA_VERSION:
            raise ReplaySchemaError(
                f"Schema version mismatch: got {session.schema_version!r}, "
                f"expected {REPLAY_SCHEMA_VERSION!r}.",
                context={"session_id": session_id},
            )
        return session

    def load_all(self) -> list[ReplaySession]:
        """Load every stored session, newest first by log order."""
        sessions: list[ReplaySession] = []
        for sid in self.list_ids():
            with contextlib.suppress(Exception):
                sessions.append(self.load(sid))
        return sessions

    def list_ids(self) -> list[str]:
        """Return all session IDs, newest first (reverse log order)."""
        if not self._log_path.exists():
            return []
        ids: list[str] = []
        for line in self._log_path.read_text(encoding="utf-8").splitlines():
            sid = line.strip()
            if sid:
                ids.append(sid)
        return list(reversed(ids))  # newest first

    def exists(self, session_id: str) -> bool:
        return (self._index_dir / f"{session_id}.json").exists()

    def count(self) -> int:
        return len(self.list_ids())

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _write_index(self, session: ReplaySession) -> None:
        """Atomic overwrite of the session index file."""
        path = self._index_dir / f"{session.session_id}.json"
        tmp = path.with_suffix(".tmp")
        try:
            tmp.write_text(session.model_dump_json(indent=2), encoding="utf-8")
            tmp.replace(path)
        except Exception as exc:
            tmp.unlink(missing_ok=True)
            raise ReplayStorageError(
                f"Index write failed for session {session.session_id}: {exc}",
                context={"session_id": session.session_id, "cause": str(exc)},
            ) from exc

    def _append_log(self, session_id: str) -> None:
        """Append session_id to the ordered log file."""
        with self._log_lock, self._log_path.open("a", encoding="utf-8") as fh:
            fh.write(session_id + "\n")
