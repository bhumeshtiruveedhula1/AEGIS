"""
backend.attack_graph.exceptions — Attack Graph Exception Hierarchy
"""

from __future__ import annotations

from backend.core.exceptions import CyberShieldError


class AttackGraphError(CyberShieldError):
    """Base class for all attack graph errors."""


class GraphBuildError(AttackGraphError):
    """Raised when the graph builder encounters an unrecoverable state."""


class NodeNotFoundError(AttackGraphError):
    """Raised when a requested node does not exist in the graph."""


class GraphStorageError(AttackGraphError):
    """Raised when GraphStore fails to read or write."""


class GraphSchemaError(AttackGraphError):
    """Raised when a loaded graph has an incompatible schema version."""


class GraphIntegrityError(AttackGraphError):
    """Raised when graph validation detects a structural violation."""
