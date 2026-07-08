"""
backend.chain_detection.exceptions — Chain Detection Exception Hierarchy
"""

from __future__ import annotations

from backend.core.exceptions import CyberShieldError


class ChainDetectionError(CyberShieldError):
    """Base class for all chain detection errors."""


class ChainBuildError(ChainDetectionError):
    """Raised when chain construction fails."""


class ChainStorageError(ChainDetectionError):
    """Raised when ChainStore I/O fails."""


class ChainSchemaError(ChainDetectionError):
    """Raised when a loaded chain has an incompatible schema version."""


class InvalidGraphError(ChainDetectionError):
    """Raised when the supplied AttackGraph/GraphSnapshot is unusable."""


class EvaluationError(ChainDetectionError):
    """Raised when ChainEvaluator encounters an unrecoverable state."""
