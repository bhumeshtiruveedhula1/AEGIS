"""
backend.shared.utils.datetime_utils — UTC Datetime Helpers
===========================================================
All datetime operations in the platform MUST go through these helpers.

Design Rule: Every timestamp stored, compared, or serialised by this
platform is UTC-aware.  Naive datetimes are treated as a bug.

Usage
-----
    from backend.shared.utils.datetime_utils import (
        utcnow,
        to_utc,
        parse_iso8601,
        format_iso8601,
        is_within_baseline_window,
    )
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone


def utcnow() -> datetime:
    """
    Return the current UTC datetime as a timezone-aware object.

    Always use this instead of datetime.utcnow() (which returns naive datetimes).

    Returns
    -------
    datetime
        Current UTC time with tzinfo=UTC.
    """
    return datetime.now(UTC)


def to_utc(dt: datetime) -> datetime:
    """
    Convert any datetime to UTC.

    Parameters
    ----------
    dt:
        Input datetime. If naive (no tzinfo), it is assumed to be UTC.

    Returns
    -------
    datetime
        UTC-aware datetime.

    Raises
    ------
    TypeError
        If the input is not a datetime object.
    """
    if not isinstance(dt, datetime):
        msg = f"Expected datetime, got {type(dt).__name__}"
        raise TypeError(msg)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def parse_iso8601(value: str) -> datetime:
    """
    Parse an ISO 8601 datetime string to a UTC-aware datetime.

    Handles:
    - "2024-01-15T10:30:00Z"
    - "2024-01-15T10:30:00+05:30"
    - "2024-01-15T10:30:00.123456Z"
    - "2024-01-15 10:30:00" (assumes UTC)

    Parameters
    ----------
    value:
        ISO 8601 formatted datetime string.

    Returns
    -------
    datetime
        UTC-aware datetime.

    Raises
    ------
    ValueError
        If the string cannot be parsed as a valid datetime.
    """
    # Replace 'Z' suffix with '+00:00' for fromisoformat compatibility
    normalised = value.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(normalised)
    except ValueError as exc:
        msg = f"Cannot parse datetime from string: {value!r}"
        raise ValueError(msg) from exc
    return to_utc(dt)


def format_iso8601(dt: datetime) -> str:
    """
    Format a datetime as an ISO 8601 string with UTC 'Z' suffix.

    Parameters
    ----------
    dt:
        Datetime to format. Will be converted to UTC first.

    Returns
    -------
    str
        ISO 8601 string ending in 'Z' (e.g., "2024-01-15T10:30:00.000000Z").
    """
    utc_dt = to_utc(dt)
    return utc_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def truncate_to_hour(dt: datetime) -> datetime:
    """
    Truncate a datetime to the start of its hour.

    Used for hourly feature aggregation windows.

    Parameters
    ----------
    dt:
        Input datetime.

    Returns
    -------
    datetime
        UTC-aware datetime with minutes/seconds/microseconds zeroed.
    """
    utc_dt = to_utc(dt)
    return utc_dt.replace(minute=0, second=0, microsecond=0)


def truncate_to_day(dt: datetime) -> datetime:
    """
    Truncate a datetime to the start of its day (00:00:00 UTC).

    Parameters
    ----------
    dt:
        Input datetime.

    Returns
    -------
    datetime
        UTC-aware datetime at midnight.
    """
    utc_dt = to_utc(dt)
    return utc_dt.replace(hour=0, minute=0, second=0, microsecond=0)


def is_within_window(
    event_time: datetime,
    window_start: datetime,
    window_end: datetime,
) -> bool:
    """
    Return True if event_time falls within [window_start, window_end).

    Parameters
    ----------
    event_time:
        The timestamp to check.
    window_start:
        Start of the window (inclusive).
    window_end:
        End of the window (exclusive).

    Returns
    -------
    bool
    """
    event_utc = to_utc(event_time)
    start_utc = to_utc(window_start)
    end_utc = to_utc(window_end)
    return start_utc <= event_utc < end_utc


def is_within_baseline_window(
    event_time: datetime,
    baseline_start: datetime,
    baseline_days: int = 7,
) -> bool:
    """
    Return True if event_time falls within the baseline collection window.

    Parameters
    ----------
    event_time:
        The event timestamp to check.
    baseline_start:
        Start of the baseline collection period.
    baseline_days:
        Duration of the baseline window in days (default: 7).

    Returns
    -------
    bool
    """
    baseline_end = to_utc(baseline_start) + timedelta(days=baseline_days)
    return is_within_window(event_time, baseline_start, baseline_end)


def get_hour_boundaries(dt: datetime) -> tuple[datetime, datetime]:
    """
    Return the start and end of the hour containing dt.

    Parameters
    ----------
    dt:
        Any datetime.

    Returns
    -------
    tuple[datetime, datetime]
        (hour_start, hour_end) — both UTC-aware.
    """
    hour_start = truncate_to_hour(dt)
    hour_end = hour_start + timedelta(hours=1)
    return hour_start, hour_end


def seconds_between(start: datetime, end: datetime) -> float:
    """
    Return elapsed seconds between two datetimes.

    Parameters
    ----------
    start:
        Earlier datetime.
    end:
        Later datetime.

    Returns
    -------
    float
        Number of seconds (may be negative if end < start).
    """
    return (to_utc(end) - to_utc(start)).total_seconds()
