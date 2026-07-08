"""backend.context.exceptions — Attack Context Exception Hierarchy."""

from __future__ import annotations

from backend.core.exceptions import CyberShieldError


class ContextError(CyberShieldError):
    """Base class for attack context errors."""


class ContextBuildError(ContextError):
    """Raised when AttackContext assembly fails."""


class ContextStorageError(ContextError):
    """Raised on context storage I/O failure."""


class ContextSchemaError(ContextError):
    """Raised on schema version mismatch during load."""


class InsufficientInputError(ContextError):
    """Raised when required inputs are missing for context assembly."""
