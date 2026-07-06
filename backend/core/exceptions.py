"""
backend.core.exceptions — Custom Exception Hierarchy
=====================================================
All platform exceptions inherit from CyberShieldError, enabling:

  1. Precise try/except blocks at module boundaries.
  2. Structured error context for audit logging and API responses.
  3. HTTP status code mapping for FastAPI exception handlers.

Exception Hierarchy
-------------------
CyberShieldError                        Base for all platform exceptions
├── ConfigurationError                  Invalid or missing configuration
├── ValidationError                     Data validation failure
├── IngestionError                      Log ingestion failures
│   └── LogParseError                   Malformed log record
├── NormalizationError                  Log normalization failures
├── DetectionError                      Anomaly detection failures
│   └── ModelNotTrainedError            Model file missing or not loaded
├── MITREMappingError                   ATT&CK mapping failures
├── GraphReasoningError                 Attack graph construction/query failures
├── LLMError                            LLM API interaction failures
│   ├── LLMTimeoutError                 API call exceeded timeout
│   ├── LLMRateLimitError               API rate limit exceeded
│   └── LLMBudgetExceededError          Cost limit exceeded
├── ResponseEngineError                 Response action generation failures
│   └── ActionNotFoundError             Action ID does not exist
├── AuditError                          Audit log write failures
└── HealthCheckError                    Health check failure

Usage
-----
    from backend.core.exceptions import LLMTimeoutError, LogParseError

    raise LLMTimeoutError(
        message="Claude API timed out after 2s",
        context={"alert_id": alert_id, "timeout_s": 2},
    )

    # In FastAPI exception handler:
    except CyberShieldError as exc:
        return JSONResponse(
            status_code=exc.http_status_code,
            content={"error": exc.error_code, "detail": exc.message},
        )
"""

from __future__ import annotations

from typing import Any


class CyberShieldError(Exception):
    """
    Base exception for all CyberShield platform errors.

    All exceptions carry:
    - message:          Human-readable error description
    - error_code:       Machine-readable code (snake_case, module-prefixed)
    - context:          Structured dict for audit logging
    - http_status_code: Mapped HTTP response status
    """

    http_status_code: int = 500
    error_code: str = "cybershield_error"

    def __init__(
        self,
        message: str,
        *,
        context: dict[str, Any] | None = None,
        error_code: str | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.context: dict[str, Any] = context or {}
        if error_code is not None:
            self.error_code = error_code

    def to_dict(self) -> dict[str, Any]:
        """Serialise exception for API responses and audit logs."""
        return {
            "error_code": self.error_code,
            "message": self.message,
            "context": self.context,
            "http_status_code": self.http_status_code,
        }

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"error_code={self.error_code!r}, "
            f"message={self.message!r}, "
            f"context={self.context!r})"
        )


# ---------------------------------------------------------------------------
# Configuration Errors
# ---------------------------------------------------------------------------
class ConfigurationError(CyberShieldError):
    """Raised when application configuration is invalid or incomplete."""

    http_status_code = 500
    error_code = "configuration_error"


# ---------------------------------------------------------------------------
# Validation Errors
# ---------------------------------------------------------------------------
class CyberShieldValidationError(CyberShieldError):
    """Raised when input data fails schema or business rule validation."""

    http_status_code = 422
    error_code = "validation_error"


# ---------------------------------------------------------------------------
# Ingestion Errors — Module: ingestion
# ---------------------------------------------------------------------------
class IngestionError(CyberShieldError):
    """Base class for log ingestion pipeline errors."""

    http_status_code = 500
    error_code = "ingestion_error"


class LogParseError(IngestionError):
    """Raised when a raw log record cannot be parsed into a LogEvent."""

    http_status_code = 422
    error_code = "log_parse_error"


# ---------------------------------------------------------------------------
# Normalization Errors — Module: normalization
# ---------------------------------------------------------------------------
class NormalizationError(CyberShieldError):
    """Raised when log normalization fails."""

    http_status_code = 500
    error_code = "normalization_error"


# ---------------------------------------------------------------------------
# Detection Errors — Module: detection
# ---------------------------------------------------------------------------
class DetectionError(CyberShieldError):
    """Base class for anomaly detection errors."""

    http_status_code = 500
    error_code = "detection_error"


class ModelNotTrainedError(DetectionError):
    """Raised when a model file is missing or has not been trained."""

    http_status_code = 503
    error_code = "model_not_trained"


class BaselineNotFoundError(DetectionError):
    """Raised when baseline statistics cannot be located."""

    http_status_code = 503
    error_code = "baseline_not_found"


# ---------------------------------------------------------------------------
# MITRE Mapping Errors — Module: mitre
# ---------------------------------------------------------------------------
class MITREMappingError(CyberShieldError):
    """Raised when an event cannot be mapped to a MITRE ATT&CK technique."""

    http_status_code = 500
    error_code = "mitre_mapping_error"


# ---------------------------------------------------------------------------
# Graph Reasoning Errors — Module: graph
# ---------------------------------------------------------------------------
class GraphReasoningError(CyberShieldError):
    """Raised when attack graph construction or path-finding fails."""

    http_status_code = 500
    error_code = "graph_reasoning_error"


# ---------------------------------------------------------------------------
# LLM Errors — Module: llm
# ---------------------------------------------------------------------------
class LLMError(CyberShieldError):
    """Base class for LLM API interaction errors."""

    http_status_code = 500
    error_code = "llm_error"


class LLMTimeoutError(LLMError):
    """Raised when the LLM API call exceeds the configured timeout."""

    http_status_code = 504
    error_code = "llm_timeout"


class LLMRateLimitError(LLMError):
    """Raised when the LLM API rate limit is exceeded."""

    http_status_code = 429
    error_code = "llm_rate_limit"


class LLMBudgetExceededError(LLMError):
    """Raised when a call would exceed the per-alert cost budget."""

    http_status_code = 402
    error_code = "llm_budget_exceeded"


class LLMResponseParseError(LLMError):
    """Raised when the LLM response cannot be parsed into the expected schema."""

    http_status_code = 500
    error_code = "llm_response_parse_error"


# ---------------------------------------------------------------------------
# Response Engine Errors — Module: response
# ---------------------------------------------------------------------------
class ResponseEngineError(CyberShieldError):
    """Base class for response action engine errors."""

    http_status_code = 500
    error_code = "response_engine_error"


class ActionNotFoundError(ResponseEngineError):
    """Raised when an action_id does not exist in the approval queue."""

    http_status_code = 404
    error_code = "action_not_found"


class ActionAlreadyProcessedError(ResponseEngineError):
    """Raised when attempting to approve/deny an already-processed action."""

    http_status_code = 409
    error_code = "action_already_processed"


# ---------------------------------------------------------------------------
# Audit Errors — Module: audit
# ---------------------------------------------------------------------------
class AuditError(CyberShieldError):
    """Raised when an audit log write fails."""

    http_status_code = 500
    error_code = "audit_error"


# ---------------------------------------------------------------------------
# Health Check Errors — Module: api
# ---------------------------------------------------------------------------
class HealthCheckError(CyberShieldError):
    """Raised when a health check dependency is unavailable."""

    http_status_code = 503
    error_code = "health_check_failed"
