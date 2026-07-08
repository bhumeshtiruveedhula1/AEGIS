"""
backend.detection.exceptions — Detection Module Exceptions
===========================================================
Module 2.4 — Behavioral Detection Core

Re-exports the platform exceptions already defined in backend.core.exceptions
so callers can import from a single, module-local namespace.  Adds one new
exception specific to this module: SchemaCompatibilityError.

Exception Hierarchy (detection-relevant)
-----------------------------------------
CyberShieldError
└── DetectionError                  ← base for all detection failures
    ├── ModelNotTrainedError         ← model file missing / never trained
    ├── BaselineNotFoundError        ← baseline statistics unavailable
    └── SchemaCompatibilityError     ← feature schema mismatch at inference

Usage
-----
    from backend.detection.exceptions import (
        DetectionError,
        ModelNotTrainedError,
        SchemaCompatibilityError,
    )

    raise SchemaCompatibilityError(
        "Loaded model was trained on 52 features; live schema has 56.",
        context={
            "trained_dim": 52,
            "live_dim": 56,
            "model_id": model_id,
        },
    )
"""

from __future__ import annotations

from typing import Any

# Re-export platform exceptions — callers should import from here
from backend.core.exceptions import (
    BaselineNotFoundError,
    DetectionError,
    ModelNotTrainedError,
)

__all__ = [
    "DetectionError",
    "ModelNotTrainedError",
    "BaselineNotFoundError",
    "SchemaCompatibilityError",
]


class SchemaCompatibilityError(DetectionError):
    """
    Raised when the feature schema of a loaded model differs from the
    current live schema.

    This prevents silent score corruption caused by feature dimension or
    ordering mismatches between training time and inference time.

    Context keys (recommended)
    --------------------------
    trained_dim   : int   — number of features model was trained on
    live_dim      : int   — current live feature dimension
    trained_names : list  — feature names at training time
    live_names    : list  — current live feature names
    model_id      : str   — versioned model identifier
    """

    http_status_code = 409
    error_code = "schema_compatibility_error"

    def __init__(
        self,
        message: str,
        *,
        context: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, context=context)
