"""
backend.shared.utils.json_utils — Safe JSON Serialisation Helpers
=================================================================
Provides serialisation utilities that handle types not supported
by the standard library's json module:

  - datetime  → ISO 8601 string (UTC, with 'Z' suffix)
  - Enum      → .value string
  - Path      → POSIX string
  - Pydantic models → .model_dump()
  - bytes     → base64 string

Usage
-----
    from backend.shared.utils.json_utils import (
        safe_dumps,
        safe_loads,
        pretty_dumps,
    )

    payload = {"timestamp": datetime.now(UTC), "score": 0.82}
    json_str = safe_dumps(payload)    # '{"timestamp":"2024-01-15T10:30:00.000000Z",...}'
"""

from __future__ import annotations

import base64
import json
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from backend.shared.utils.datetime_utils import format_iso8601


class _CyberShieldJSONEncoder(json.JSONEncoder):
    """
    Custom JSON encoder handling platform-specific types.

    Handles:
    - datetime  → ISO 8601 UTC string
    - Enum      → str value
    - Path      → POSIX string
    - bytes     → base64 encoded string
    - Pydantic BaseModel → model_dump()
    - Objects with __dict__ → their dict representation
    """

    def default(self, obj: Any) -> Any:  # noqa: ANN401
        if isinstance(obj, datetime):
            return format_iso8601(obj)
        if isinstance(obj, Enum):
            return obj.value
        if isinstance(obj, Path):
            return str(obj)
        if isinstance(obj, bytes):
            return base64.b64encode(obj).decode("utf-8")
        # Pydantic v2 models
        if hasattr(obj, "model_dump"):
            return obj.model_dump()
        # Fallback for objects with __dict__
        if hasattr(obj, "__dict__"):
            return obj.__dict__
        return super().default(obj)


def safe_dumps(
    obj: Any,
    *,
    indent: int | None = None,
    sort_keys: bool = False,
    ensure_ascii: bool = False,
) -> str:
    """
    Serialise obj to a JSON string, handling platform-specific types.

    Parameters
    ----------
    obj:
        The object to serialise.
    indent:
        If provided, enables pretty-printing with the given indent level.
    sort_keys:
        If True, sort dictionary keys (useful for deterministic output).
    ensure_ascii:
        If True, escape non-ASCII characters.

    Returns
    -------
    str
        JSON-encoded string.

    Raises
    ------
    TypeError
        If an object cannot be serialised even with the custom encoder.
    """
    return json.dumps(
        obj,
        cls=_CyberShieldJSONEncoder,
        indent=indent,
        sort_keys=sort_keys,
        ensure_ascii=ensure_ascii,
        separators=None if indent else (",", ":"),
    )


def pretty_dumps(obj: Any, *, sort_keys: bool = True) -> str:
    """
    Serialise obj to a pretty-printed JSON string (4-space indent).

    Use for report generation, debugging, and human-readable output.

    Parameters
    ----------
    obj:
        The object to serialise.
    sort_keys:
        Sort dict keys for deterministic output (default True).

    Returns
    -------
    str
        Pretty-printed JSON string.
    """
    return safe_dumps(obj, indent=4, sort_keys=sort_keys)


def safe_loads(json_str: str) -> Any:
    """
    Parse a JSON string, returning the decoded Python object.

    Parameters
    ----------
    json_str:
        JSON-encoded string to parse.

    Returns
    -------
    Any
        Decoded Python object (dict, list, str, int, float, bool, None).

    Raises
    ------
    json.JSONDecodeError
        If the string is not valid JSON.
    ValueError
        If json_str is empty or None.
    """
    if not json_str or not json_str.strip():
        msg = "Cannot parse empty JSON string"
        raise ValueError(msg)
    return json.loads(json_str)


def safe_loads_or_none(json_str: str | None) -> Any:
    """
    Parse a JSON string, returning None if parsing fails.

    Use when you want to gracefully handle malformed input rather than
    raising an exception.

    Parameters
    ----------
    json_str:
        JSON string to parse, or None.

    Returns
    -------
    Any | None
        Decoded object, or None if parsing fails.
    """
    if json_str is None:
        return None
    try:
        return safe_loads(json_str)
    except (json.JSONDecodeError, ValueError):
        return None


def write_jsonl(records: list[Any], filepath: str | Path) -> int:
    """
    Write a list of records to a JSON Lines file (one JSON object per line).

    JSONL is the primary log storage format for the platform.

    Parameters
    ----------
    records:
        List of serialisable objects (dicts, Pydantic models, etc.).
    filepath:
        Path to the output .jsonl file. Created if it does not exist.

    Returns
    -------
    int
        Number of records written.
    """
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for record in records:
            f.write(safe_dumps(record))
            f.write("\n")
    return len(records)


def read_jsonl(filepath: str | Path) -> list[dict[str, Any]]:
    """
    Read a JSON Lines file and return a list of dicts.

    Skips blank lines silently.

    Parameters
    ----------
    filepath:
        Path to the .jsonl file to read.

    Returns
    -------
    list[dict[str, Any]]
        Parsed records.

    Raises
    ------
    FileNotFoundError
        If the file does not exist.
    json.JSONDecodeError
        If any line contains invalid JSON (indicates data corruption).
    """
    path = Path(filepath)
    records = []
    with path.open("r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                records.append(safe_loads(stripped))
            except (json.JSONDecodeError, ValueError) as exc:
                msg = f"Invalid JSON on line {line_num} of {filepath}: {exc}"
                raise json.JSONDecodeError(msg, stripped, 0) from exc
    return records
