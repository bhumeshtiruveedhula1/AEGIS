"""
backend.synthetic_attack.exceptions — Synthetic Attack Exception Hierarchy
"""

from __future__ import annotations

from backend.core.exceptions import CyberShieldError


class SyntheticAttackError(CyberShieldError):
    """Base class for synthetic attack generation errors."""


class TemplateNotFoundError(SyntheticAttackError):
    """Raised when a requested template ID does not exist."""


class GenerationError(SyntheticAttackError):
    """Raised when event generation fails."""


class SchedulingError(SyntheticAttackError):
    """Raised when attack scheduling encounters an unrecoverable state."""


class StorageError(SyntheticAttackError):
    """Raised when synthetic attack storage I/O fails."""


class ScenarioValidationError(SyntheticAttackError):
    """Raised when a scenario or template fails validation."""
