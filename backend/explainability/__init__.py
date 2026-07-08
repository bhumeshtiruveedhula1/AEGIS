"""
backend.explainability — SHAP Explainability Subsystem
=======================================================
Module 3.2 — Operation AEGIS / CyberShield

Public API surface for the behavioral anomaly explainability layer.

Primary Entry Point
-------------------
    from backend.explainability.service import ExplainabilityService
    from backend.detection.service import DetectionService

    det_svc  = DetectionService()
    expl_svc = ExplainabilityService()
    expl_svc.initialize_from_detection_service(det_svc)

    explanation = expl_svc.explain_alert(alert, feature_record)
    report      = expl_svc.explain_detection_result(detection_result, records)

Data Models
-----------
    from backend.explainability.models import (
        ExplanationResult,
        ExplainabilityReport,
        FeatureContribution,
    )

Exceptions
----------
    from backend.explainability.exceptions import (
        ExplainabilityError,
        ExplainerNotInitializedError,
        ModelVersionMismatchError,
        ExplanationComputationError,
        ExplanationStorageError,
        SchemaCompatibilityError,
    )
"""

from backend.explainability.exceptions import (
    ExplainabilityError,
    ExplainerNotInitializedError,
    ExplanationComputationError,
    ExplanationStorageError,
    ModelVersionMismatchError,
    SchemaCompatibilityError,
)
from backend.explainability.models import (
    EXPLAINABILITY_SCHEMA_VERSION,
    ExplainabilityReport,
    ExplanationResult,
    FeatureContribution,
)
from backend.explainability.service import ExplainabilityService

__all__ = [
    # Service
    "ExplainabilityService",
    # Models
    "ExplanationResult",
    "ExplainabilityReport",
    "FeatureContribution",
    "EXPLAINABILITY_SCHEMA_VERSION",
    # Exceptions
    "ExplainabilityError",
    "ExplainerNotInitializedError",
    "ExplanationComputationError",
    "ExplanationStorageError",
    "ModelVersionMismatchError",
    "SchemaCompatibilityError",
]
