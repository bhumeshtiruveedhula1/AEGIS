"""
backend.shared.utils.validation_utils — Reusable Pydantic Validators
=====================================================================
Common field validators that can be reused across multiple Pydantic models.

Pattern: Use @field_validator in Pydantic models and delegate to these
functions for the actual validation logic, keeping models thin and
validators unit-testable independently.

Usage
-----
    from pydantic import field_validator
    from backend.shared.utils.validation_utils import (
        validate_nonempty_string,
        validate_hostname,
        validate_mitre_technique_id,
    )

    class LogEvent(BaseModel):
        host: str

        @field_validator("host")
        @classmethod
        def check_host(cls, v: str) -> str:
            return validate_hostname(v)
"""

from __future__ import annotations

import re
from typing import Any

# ---------------------------------------------------------------------------
# Compiled regular expressions
# ---------------------------------------------------------------------------
# Hostname: letters, digits, hyphens, dots (RFC 1123 relaxed)
_HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,253}[a-zA-Z0-9])?$")

# IPv4
_IPV4_RE = re.compile(
    r"^(25[0-5]|2[0-4]\d|[01]?\d\d?)\."
    r"(25[0-5]|2[0-4]\d|[01]?\d\d?)\."
    r"(25[0-5]|2[0-4]\d|[01]?\d\d?)\."
    r"(25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)

# IPv6 (simplified — covers common formats)
_IPV6_RE = re.compile(r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$")

# MITRE ATT&CK technique ID: T followed by 4 digits, optional sub (e.g., T1059.001)
_MITRE_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

# MITRE tactic ID: TA followed by 4 digits
_MITRE_TACTIC_RE = re.compile(r"^TA\d{4}$")

# Email (basic)
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def validate_nonempty_string(value: Any, field_name: str = "field") -> str:
    """
    Validate that a value is a non-empty, non-whitespace-only string.

    Parameters
    ----------
    value:
        The value to validate.
    field_name:
        Field name for the error message.

    Returns
    -------
    str
        Stripped string.

    Raises
    ------
    ValueError
        If the value is not a non-empty string.
    """
    if not isinstance(value, str):
        msg = f"'{field_name}' must be a string, got {type(value).__name__}"
        raise ValueError(msg)
    stripped = value.strip()
    if not stripped:
        msg = f"'{field_name}' must not be empty or whitespace"
        raise ValueError(msg)
    return stripped


def validate_hostname(value: str) -> str:
    """
    Validate a hostname or IP address string.

    Accepts:
    - RFC 1123 hostnames (e.g., "web-server-01", "dc.corp.local")
    - IPv4 addresses (e.g., "192.168.1.100")
    - IPv6 addresses (e.g., "::1")

    Parameters
    ----------
    value:
        The hostname/IP string to validate.

    Returns
    -------
    str
        The validated hostname (lowercased).

    Raises
    ------
    ValueError
        If the value does not match a valid hostname or IP pattern.
    """
    stripped = value.strip()
    if not stripped:
        msg = "hostname must not be empty"
        raise ValueError(msg)
    if _IPV4_RE.match(stripped) or _IPV6_RE.match(stripped):
        return stripped
    if _HOSTNAME_RE.match(stripped):
        return stripped.lower()
    msg = f"Invalid hostname or IP address: {value!r}"
    raise ValueError(msg)


def validate_mitre_technique_id(value: str) -> str:
    """
    Validate a MITRE ATT&CK technique ID (e.g., "T1059" or "T1059.001").

    Parameters
    ----------
    value:
        Technique ID string to validate.

    Returns
    -------
    str
        Uppercased, validated technique ID.

    Raises
    ------
    ValueError
        If the value is not a valid MITRE technique ID.
    """
    normalised = value.strip().upper()
    if not _MITRE_TECHNIQUE_RE.match(normalised):
        msg = f"Invalid MITRE ATT&CK technique ID: {value!r} (expected T####[.###])"
        raise ValueError(msg)
    return normalised


def validate_mitre_tactic_id(value: str) -> str:
    """
    Validate a MITRE ATT&CK tactic ID (e.g., "TA0002").

    Parameters
    ----------
    value:
        Tactic ID string to validate.

    Returns
    -------
    str
        Uppercased, validated tactic ID.

    Raises
    ------
    ValueError
        If the value does not match the TA#### pattern.
    """
    normalised = value.strip().upper()
    if not _MITRE_TACTIC_RE.match(normalised):
        msg = f"Invalid MITRE ATT&CK tactic ID: {value!r} (expected TA####)"
        raise ValueError(msg)
    return normalised


def validate_anomaly_score(value: Any, field_name: str = "anomaly_score") -> float:
    """
    Validate an anomaly score is within [-1.0, 1.0].

    Parameters
    ----------
    value:
        The score value (int or float).
    field_name:
        Field name for the error message.

    Returns
    -------
    float
        Validated anomaly score.

    Raises
    ------
    ValueError
        If the value is outside the valid range.
    """
    try:
        score = float(value)
    except (TypeError, ValueError) as exc:
        msg = f"'{field_name}' must be a number, got {type(value).__name__}"
        raise ValueError(msg) from exc
    if not (-1.0 <= score <= 1.0):
        msg = f"'{field_name}' must be in [-1.0, 1.0], got {score}"
        raise ValueError(msg)
    return score


def validate_confidence_score(value: Any, field_name: str = "confidence") -> float:
    """
    Validate a confidence score is within [0.0, 1.0].

    Parameters
    ----------
    value:
        The score value (int or float).
    field_name:
        Field name for the error message.

    Returns
    -------
    float
        Validated confidence score.

    Raises
    ------
    ValueError
        If the value is outside [0.0, 1.0].
    """
    try:
        score = float(value)
    except (TypeError, ValueError) as exc:
        msg = f"'{field_name}' must be a number, got {type(value).__name__}"
        raise ValueError(msg) from exc
    if not (0.0 <= score <= 1.0):
        msg = f"'{field_name}' must be in [0.0, 1.0], got {score}"
        raise ValueError(msg)
    return score


def validate_email(value: str, field_name: str = "email") -> str:
    """
    Basic email format validation.

    Parameters
    ----------
    value:
        Email string to validate.
    field_name:
        Field name for error messages.

    Returns
    -------
    str
        Lowercased, stripped email address.

    Raises
    ------
    ValueError
        If the value does not look like a valid email address.
    """
    stripped = value.strip().lower()
    if not _EMAIL_RE.match(stripped):
        msg = f"Invalid email address for '{field_name}': {value!r}"
        raise ValueError(msg)
    return stripped
