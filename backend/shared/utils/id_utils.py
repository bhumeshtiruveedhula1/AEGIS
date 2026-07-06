"""
backend.shared.utils.id_utils — UUID Generation and Validation
==============================================================
Centralised ID utilities for producing and validating UUID v4 identifiers.

All platform entities (alerts, actions, events, audit records) use UUID v4
strings as their primary identifiers.  Using this module ensures:
  - Consistent format (lowercase, hyphenated)
  - Collision-proof IDs (UUID v4 = 122 bits of entropy)
  - Typed return values that mypy understands

Usage
-----
    from backend.shared.utils.id_utils import generate_id, is_valid_id
    from backend.shared.types import AlertId

    alert_id = AlertId(generate_id())
    assert is_valid_id(alert_id)
"""

from __future__ import annotations

import re
import uuid

# UUID v4 pattern (lowercase, hyphenated)
_UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def generate_id() -> str:
    """
    Generate a new UUID v4 string identifier.

    Returns
    -------
    str
        Lowercase hyphenated UUID v4 string.
        Example: "550e8400-e29b-41d4-a716-446655440000"
    """
    return str(uuid.uuid4())


def is_valid_id(value: str) -> bool:
    """
    Return True if the value is a valid UUID v4 string.

    Accepts both uppercase and lowercase hex digits.

    Parameters
    ----------
    value:
        The string to validate.

    Returns
    -------
    bool
    """
    if not isinstance(value, str):
        return False
    return bool(_UUID_PATTERN.match(value))


def validate_id(value: str, field_name: str = "id") -> str:
    """
    Validate and return a UUID v4 string, raising ValueError if invalid.

    Use in Pydantic @field_validator methods:
        @field_validator("alert_id")
        @classmethod
        def check_alert_id(cls, v: str) -> str:
            return validate_id(v, "alert_id")

    Parameters
    ----------
    value:
        The string to validate.
    field_name:
        Field name included in the error message for context.

    Returns
    -------
    str
        The validated UUID string (lowercased).

    Raises
    ------
    ValueError
        If the value is not a valid UUID v4 string.
    """
    if not is_valid_id(value):
        msg = f"Invalid UUID v4 for field '{field_name}': {value!r}"
        raise ValueError(msg)
    return value.lower()


def id_prefix(prefix: str, value: str) -> str:
    """
    Return a prefixed ID string (for human-readable display, NOT storage).

    Example: id_prefix("alert", "550e8400-...") → "alert_550e8400-..."

    Do not store prefixed IDs in the database — use bare UUIDs.

    Parameters
    ----------
    prefix:
        Short descriptive prefix (e.g., "alert", "action", "chain").
    value:
        UUID v4 string.

    Returns
    -------
    str
        Prefixed display string.
    """
    return f"{prefix}_{value}"
