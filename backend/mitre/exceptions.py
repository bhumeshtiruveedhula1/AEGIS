"""
backend.mitre.exceptions — MITRE Mapper Exception Hierarchy
============================================================
Module 3.3 — MITRE ATT&CK Mapper
"""

from __future__ import annotations

from backend.core.exceptions import CyberShieldError


class MitreError(CyberShieldError):
    """Base class for all MITRE ATT&CK mapping errors."""


class KnowledgeBaseError(MitreError):
    """Raised when the local ATT&CK knowledge base fails to load or validate."""


class MappingError(MitreError):
    """Raised when a mapping operation cannot complete."""


class NoTechniquesFoundError(MitreError):
    """
    Raised when no ATT&CK techniques can be mapped from the available evidence.
    Indicates either a benign event or an insufficient evidence set.
    """


class MappingStorageError(MitreError):
    """Raised when MappingStore fails to read or write a mapping file."""


class SchemaCompatibilityError(MitreError):
    """Raised when a stored mapping schema version is incompatible with current code."""
