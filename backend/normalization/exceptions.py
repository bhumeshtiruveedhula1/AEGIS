"""
backend.normalization.exceptions — Normalization Error Hierarchy
================================================================
Domain-specific exceptions raised during telemetry parsing and
normalization.  All exceptions extend the platform's base error
class for consistent handling by the FastAPI exception handlers.

Exception Hierarchy
-------------------
  NormalizationError          Base for all normalization errors
  ├── ParseError              Raw record is structurally unparseable
  ├── SchemaValidationError   Record parsed but fails schema rules
  ├── SourceError             Cannot read from a telemetry source
  └── MissingFieldError       Required field absent in raw record

Design Notes
------------
- All exceptions carry `source` (log source name) and `raw_record`
  (the original dict that caused the failure) for forensic logging.
- Never swallow ParseError or MissingFieldError silently.
  Route them to the dead-letter writer (error_events.jsonl).
- SchemaValidationError may be recoverable (e.g., default fills);
  document recovery strategy in the raising code.

Usage
-----
    from backend.normalization.exceptions import ParseError

    raise ParseError(
        source="hospital_server",
        raw_record=record,
        message="Missing required field 'event_type'",
    )
"""

from __future__ import annotations

from typing import Any


class NormalizationError(Exception):
    """
    Root exception for all normalization pipeline failures.

    Attributes
    ----------
    source:     Log source identifier (hospital_server, ot_node, etc.)
    raw_record: The raw dict that triggered this error (may be None
                for I/O errors before deserialization).
    message:    Human-readable description of the failure.
    """

    def __init__(
        self,
        message: str,
        *,
        source: str = "unknown",
        raw_record: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.source = source
        self.raw_record = raw_record
        self.message = message

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"source={self.source!r}, "
            f"message={self.message!r})"
        )


class ParseError(NormalizationError):
    """
    Raised when a raw JSONL line cannot be parsed into a dict.

    Causes
    ------
    - Line is not valid JSON (json.JSONDecodeError)
    - Line is valid JSON but not a dict (e.g., null, list)
    - Line is empty

    Recovery
    --------
    The pipeline writes the raw line to error_events.jsonl and
    increments the error counter.  Processing continues on the
    next record.

    Examples
    --------
    >>> raise ParseError(
    ...     source="hospital_server",
    ...     message="JSONDecodeError: line 42 — unexpected end of string",
    ... )
    """


class SchemaValidationError(NormalizationError):
    """
    Raised when a parsed dict fails CanonicalEvent schema validation.

    Causes
    ------
    - timestamp field cannot be parsed as a datetime
    - result field is not in (success, failure, unknown)
    - host is an empty string

    Recovery
    --------
    The pipeline may attempt a best-effort fill with defaults and
    record a parse_warning.  If recovery is impossible, the record
    is written to error_events.jsonl.

    Attributes
    ----------
    field:  Name of the field that failed validation.
    value:  The invalid value that was supplied.
    """

    def __init__(
        self,
        message: str,
        *,
        source: str = "unknown",
        raw_record: dict[str, Any] | None = None,
        field: str = "",
        value: Any = None,
    ) -> None:
        super().__init__(message, source=source, raw_record=raw_record)
        self.field = field
        self.value = value


class SourceError(NormalizationError):
    """
    Raised when a telemetry source cannot be reached or read.

    Causes
    ------
    - Log file does not exist
    - Log file is not readable (permissions)
    - Registry returns an invalid path

    Recovery
    --------
    The pipeline logs the error and skips this source.
    Other sources continue processing.  The error is surfaced in
    the pipeline statistics report.

    Attributes
    ----------
    path:  Filesystem path that could not be opened.
    """

    def __init__(
        self,
        message: str,
        *,
        source: str = "unknown",
        path: str = "",
    ) -> None:
        super().__init__(message, source=source)
        self.path = path

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"source={self.source!r}, "
            f"path={self.path!r}, "
            f"message={self.message!r})"
        )


class MissingFieldError(NormalizationError):
    """
    Raised when a required field is absent from a raw record.

    This is distinct from SchemaValidationError:
    - MissingFieldError   → field is not present at all
    - SchemaValidationError → field is present but invalid

    Attributes
    ----------
    field:  Name of the missing required field.
    """

    def __init__(
        self,
        message: str,
        *,
        source: str = "unknown",
        raw_record: dict[str, Any] | None = None,
        field: str = "",
    ) -> None:
        super().__init__(message, source=source, raw_record=raw_record)
        self.field = field
