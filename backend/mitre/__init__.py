"""
backend.mitre — MITRE ATT&CK Mapper
=====================================
Module 3.3 — Operation AEGIS / CyberShield

Primary Entry Point
-------------------
    from backend.mitre.service import MitreService

    svc = MitreService()
    mapped = svc.map_alert(alert, explanation)
    report = svc.map_detection_result(detection_result, explanations)
"""

from backend.mitre.exceptions import (
    KnowledgeBaseError,
    MappingError,
    MappingStorageError,
    MitreError,
    NoTechniquesFoundError,
    SchemaCompatibilityError,
)
from backend.mitre.knowledge_base import MitreKnowledgeBase, get_knowledge_base
from backend.mitre.models import (
    MITRE_KNOWLEDGE_VERSION,
    MITRE_SCHEMA_VERSION,
    AttackTactic,
    AttackTechnique,
    MappedAttack,
    MappingReport,
    MappingStatistics,
    TechniqueMapping,
)
from backend.mitre.service import MitreService

__all__ = [
    # Service
    "MitreService",
    # Knowledge Base
    "MitreKnowledgeBase",
    "get_knowledge_base",
    # Models
    "AttackTactic",
    "AttackTechnique",
    "TechniqueMapping",
    "MappedAttack",
    "MappingReport",
    "MappingStatistics",
    "MITRE_SCHEMA_VERSION",
    "MITRE_KNOWLEDGE_VERSION",
    # Exceptions
    "MitreError",
    "KnowledgeBaseError",
    "MappingError",
    "NoTechniquesFoundError",
    "MappingStorageError",
    "SchemaCompatibilityError",
]
