"""
backend.core.logging — Structured Logging Foundation
=====================================================
Provides a production-ready, structured logging setup using `structlog`.

Every log record is a JSON object (in production) or pretty-printed (in dev),
always containing:
  - timestamp    : ISO 8601 UTC
  - level        : log level string
  - logger       : module path (e.g., "backend.core.config")
  - event        : the log message
  - request_id   : (if in request context) UUID for log correlation
  - Additional key=value pairs passed by the caller

Usage
-----
    from backend.core.logging import get_logger

    logger = get_logger(__name__)

    logger.info("anomaly_detected", score=0.82, host="web-server-01")
    logger.warning("llm_timeout", timeout_seconds=2, alert_id=alert_id)
    logger.error("db_connection_failed", error=str(exc))
    logger.debug("feature_vector_computed", vector_shape=(100, 7))

In FastAPI middleware, bind request context:
    import structlog
    structlog.contextvars.bind_contextvars(request_id=request_id)

Design Notes
------------
- structlog is preferred over stdlib logging for machine-readable JSON output.
- Logger instances are lightweight and cheap to create per module.
- Sensitive values (API keys, secrets) must NEVER be logged; use .get_secret_value()
  and mask before passing to logger.
- Log level is controlled by LOG_LEVEL env var at startup.
"""

from __future__ import annotations

import logging
import sys
from typing import Any

import structlog
from structlog.types import EventDict, Processor


def _add_severity_level(
    logger: logging.Logger,
    method_name: str,
    event_dict: EventDict,
) -> EventDict:
    """
    Add a 'severity' field alongside 'level' for compatibility with
    log aggregators that use the 'severity' field (e.g., Google Cloud Logging).
    """
    level = event_dict.get("level", method_name).upper()
    event_dict["severity"] = level
    return event_dict


def _drop_color_message_key(
    logger: logging.Logger,
    method_name: str,
    event_dict: EventDict,
) -> EventDict:
    """Remove uvicorn's internal color_message key from log records."""
    event_dict.pop("color_message", None)
    return event_dict


def _safe_add_logger_name(
    logger: Any,
    method_name: str,
    event_dict: EventDict,
) -> EventDict:
    """
    Safely add logger name to event_dict.

    Works with both stdlib Logger (has .name) and structlog's PrintLogger
    (which has no .name attribute). Gracefully omits the field when unavailable.
    """
    name = getattr(logger, "name", None)
    if name:
        event_dict["logger"] = name
    return event_dict


def configure_logging(
    *,
    level: str = "INFO",
    format: str = "console",  # noqa: A002  (matches config field name)
) -> None:
    """
    Configure structlog for the application.

    Must be called ONCE at application startup before any loggers are used.
    In tests, call with level="DEBUG" and format="console".

    Parameters
    ----------
    level:
        Minimum log level to emit (DEBUG | INFO | WARNING | ERROR | CRITICAL).
    format:
        Output format: "json" for production, "console" for development.
    """
    log_level = getattr(logging, level.upper(), logging.INFO)

    # --- Shared processors (applied to every log record) -------------------
    shared_processors: list[Processor] = [
        structlog.contextvars.merge_contextvars,       # inject request_id etc.
        _safe_add_logger_name,                         # add "logger" field (safe)
        structlog.stdlib.add_log_level,                # add "level" field
        _add_severity_level,                           # add "severity" field
        _drop_color_message_key,                       # clean uvicorn noise
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso", utc=True),  # UTC timestamps
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
    ]

    if format == "json":
        # Production: output compact JSON, one record per line
        structlog.configure(
            processors=[
                *shared_processors,
                structlog.processors.dict_tracebacks,
                structlog.processors.JSONRenderer(),
            ],
            wrapper_class=structlog.make_filtering_bound_logger(log_level),
            context_class=dict,
            logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
            cache_logger_on_first_use=True,
        )
    else:
        # Development: colourised, pretty-printed output
        structlog.configure(
            processors=[
                *shared_processors,
                structlog.dev.ConsoleRenderer(colors=sys.stdout.isatty()),
            ],
            wrapper_class=structlog.make_filtering_bound_logger(log_level),
            context_class=dict,
            logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
            cache_logger_on_first_use=True,
        )

    # Also configure stdlib logging to route through structlog
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=log_level,
    )

    # Suppress noisy third-party loggers
    _silence_noisy_loggers()


def _silence_noisy_loggers() -> None:
    """Suppress chatty third-party library loggers."""
    for logger_name in (
        "uvicorn.access",
        "httpx",
        "httpcore",
        "anthropic",
    ):
        logging.getLogger(logger_name).setLevel(logging.WARNING)


def get_logger(name: str) -> structlog.BoundLogger:
    """
    Return a structlog BoundLogger for the given module name.

    Parameters
    ----------
    name:
        Typically ``__name__`` of the calling module, e.g., "backend.core.config".

    Returns
    -------
    structlog.BoundLogger
        A bound logger instance. Thread-safe and cheap to create.

    Example
    -------
        logger = get_logger(__name__)
        logger.info("started", version="0.1.0")
    """
    return structlog.get_logger(name)


def get_request_logger(
    request_id: str,
    **context: Any,
) -> structlog.BoundLogger:
    """
    Return a logger pre-bound with request-scoped context.

    Use this in middleware or route handlers when you want every log line
    to automatically include the request_id and any other request context.

    Parameters
    ----------
    request_id:
        Unique identifier for the HTTP request (UUID v4 string).
    **context:
        Additional key-value pairs to bind to every log record.

    Returns
    -------
    structlog.BoundLogger
    """
    return structlog.get_logger().bind(request_id=request_id, **context)
