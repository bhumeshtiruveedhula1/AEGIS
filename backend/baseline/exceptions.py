"""
backend.baseline.exceptions — Baseline Error Hierarchy
=======================================================
Module 2.1 — Baseline Generator

Domain-specific exceptions for the baseline computation pipeline.

Hierarchy
---------
  BaselineError              Root for all baseline errors
  ├── BaselineInputError     Normalized input is missing or unreadable
  ├── BaselineComputeError   Statistics computation failure
  ├── BaselineStorageError   Persistence read/write failure
  ├── BaselineNotFoundError  Requested entity baseline does not exist
  └── BaselineVersionError   Stored baseline schema version incompatible

Design Notes
------------
- All exceptions carry a `context` dict for structured logging.
- Never swallow BaselineInputError — it indicates a pipeline ordering
  violation (baseline must follow normalization).
- BaselineNotFoundError is expected during cold-start; callers must handle it.
"""

from __future__ import annotations

from typing import Any


class BaselineError(Exception):
    """Root exception for all baseline pipeline failures."""

    def __init__(
        self,
        message: str,
        *,
        context: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.context: dict[str, Any] = context or {}

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(message={self.message!r})"


class BaselineInputError(BaselineError):
    """
    Raised when the normalized event input cannot be read.

    Causes
    ------
    - normalized_events.jsonl does not exist (normalization not run)
    - File is empty (zero events to baseline)
    - File is not readable (permissions)

    Recovery
    --------
    Run the normalization pipeline first (Module 1.3), then retry.
    """


class BaselineComputeError(BaselineError):
    """
    Raised when statistics computation fails unexpectedly.

    Causes
    ------
    - All events for an entity have None values for a required field
    - Numerical overflow in statistics (extremely large values)

    Recovery
    --------
    Log the failing entity and continue with other entities.
    This should never propagate to the user.
    """

    def __init__(
        self,
        message: str,
        *,
        entity_key: str = "unknown",
        context: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, context=context)
        self.entity_key = entity_key


class BaselineStorageError(BaselineError):
    """
    Raised when reading or writing baseline artefacts fails.

    Causes
    ------
    - Baseline directory is not writable
    - JSON serialisation fails (custom types not handled)
    - Disk full

    Recovery
    --------
    Check permissions on the baseline directory.
    Ensure the baseline directory is on a writable filesystem.
    """

    def __init__(
        self,
        message: str,
        *,
        path: str = "",
        context: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, context=context)
        self.path = path


class BaselineNotFoundError(BaselineError):
    """
    Raised when a requested entity baseline does not exist.

    This is EXPECTED during cold-start (no baselines computed yet)
    and during initial deployment.

    Callers MUST handle this exception gracefully:
      - The Feature Engine should skip scoring when no baseline exists
      - The API should return a 404 with a helpful message

    Attributes
    ----------
    entity_type:  The type that was not found (user, host, source).
    entity_id:    The specific entity ID that was not found.
    """

    def __init__(
        self,
        message: str,
        *,
        entity_type: str = "",
        entity_id: str = "",
        context: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, context=context)
        self.entity_type = entity_type
        self.entity_id = entity_id


class BaselineVersionError(BaselineError):
    """
    Raised when a stored baseline schema version is incompatible.

    Causes
    ------
    - Baseline was built with an older schema (breaking change in models.py)
    - Baseline was built with a newer schema (downgrade scenario)

    Recovery
    --------
    Re-run the baseline builder to produce a new baseline with
    the current schema version.
    """

    def __init__(
        self,
        message: str,
        *,
        stored_version: str = "",
        current_version: str = "",
        context: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, context=context)
        self.stored_version = stored_version
        self.current_version = current_version
