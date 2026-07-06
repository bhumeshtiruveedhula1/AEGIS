"""
tests/integration/conftest.py
================================
Structlog config for integration tests — same minimal setup as unit tests.
"""
from __future__ import annotations

import structlog


def pytest_configure(config: object) -> None:  # noqa: ARG001
    structlog.reset_defaults()
    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.dev.ConsoleRenderer(colors=False),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(10),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=False,
    )
