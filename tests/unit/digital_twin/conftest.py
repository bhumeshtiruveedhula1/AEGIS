"""
tests/unit/digital_twin/conftest.py
=====================================
Test-specific configuration for the digital_twin unit tests.

Configures structlog WITHOUT the add_logger_name processor (which requires
a stdlib logger with a .name attribute). The PrintLoggerFactory used in tests
does not provide .name, so we use a simpler processor chain here.
"""
from __future__ import annotations

import structlog


def pytest_configure(config: object) -> None:  # noqa: ARG001
    """
    Configure structlog for digital_twin unit tests.
    reset_defaults() clears cached loggers from any prior configure() call.
    Uses a minimal processor chain compatible with PrintLogger.
    """
    structlog.reset_defaults()
    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.dev.ConsoleRenderer(colors=False),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(10),  # DEBUG
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=False,
    )
