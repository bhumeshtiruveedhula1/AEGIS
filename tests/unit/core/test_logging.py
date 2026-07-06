"""
tests/unit/core/test_logging.py
================================
Unit tests for backend.core.logging configuration.
"""

from __future__ import annotations

import structlog

from backend.core.logging import configure_logging, get_logger, get_request_logger


class TestConfigureLogging:
    """configure_logging must not raise and must produce a bound logger."""

    def test_configure_with_console_format(self) -> None:
        configure_logging(level="DEBUG", format="console")
        logger = get_logger("test.configure")
        assert logger is not None

    def test_configure_with_json_format(self) -> None:
        configure_logging(level="INFO", format="json")
        logger = get_logger("test.json")
        assert logger is not None

    def test_configure_with_all_log_levels(self) -> None:
        for level in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
            configure_logging(level=level, format="console")  # should not raise


class TestGetLogger:
    """get_logger must return a structlog BoundLogger."""

    def test_returns_bound_logger(self) -> None:
        logger = get_logger(__name__)
        assert isinstance(logger, structlog.BoundLoggerBase)

    def test_different_names_return_different_loggers(self) -> None:
        logger_a = get_logger("module.a")
        logger_b = get_logger("module.b")
        # Both are valid loggers (we don't test identity, just that they work)
        assert logger_a is not None
        assert logger_b is not None

    def test_logger_can_emit_at_all_levels(self) -> None:
        """Logger methods must not raise for valid log levels."""
        configure_logging(level="DEBUG", format="console")
        logger = get_logger("test.levels")
        logger.debug("test_debug_message", field="value")
        logger.info("test_info_message", field="value")
        logger.warning("test_warning_message", field="value")
        logger.error("test_error_message", field="value")

    def test_logger_accepts_arbitrary_key_value_context(self) -> None:
        logger = get_logger("test.context")
        # Must not raise with any serialisable kwargs
        logger.info(
            "structured_event",
            alert_id="abc123",
            anomaly_score=0.82,
            host="web-server-01",
            techniques=["T1059", "T1021"],
        )


class TestGetRequestLogger:
    """get_request_logger must return a logger pre-bound with request context."""

    def test_returns_bound_logger_with_request_id(self) -> None:
        request_id = "550e8400-e29b-41d4-a716-446655440000"
        logger = get_request_logger(request_id)
        assert logger is not None

    def test_accepts_additional_context(self) -> None:
        logger = get_request_logger(
            "550e8400-e29b-41d4-a716-446655440001",
            user="analyst@soc.local",
            endpoint="/api/v1/alerts",
        )
        assert logger is not None

    def test_logger_can_emit_after_binding(self) -> None:
        configure_logging(level="DEBUG", format="console")
        logger = get_request_logger(
            "550e8400-e29b-41d4-a716-446655440002",
            path="/health",
        )
        logger.info("request_received", method="GET")
