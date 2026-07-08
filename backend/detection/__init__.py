"""
backend.detection — Behavioral Detection Core
=============================================
Module 2.4 — Operation AEGIS / CyberShield

Public API surface for the behavioral anomaly detection subsystem.

The Isolation Forest model is trained exclusively on normal behavioral
feature vectors.  It never learns attack signatures.

Primary Entry Point
-------------------
    from backend.detection.service import DetectionService

    service = DetectionService()
    result = service.train_from_features()
    alert = service.score_event(feature_record)

Data Models
-----------
    from backend.detection.models import (
        DetectionAlert,
        DetectionResult,
        ModelMetadata,
        TrainingResult,
    )

Exceptions
----------
    from backend.detection.exceptions import (
        DetectionError,
        ModelNotTrainedError,
        SchemaCompatibilityError,
    )

Architecture Layers
-------------------
DetectionService       ← orchestration (use this in application code)
  IsolationForestTrainer ← training only
  AnomalyScorer          ← inference only
  ModelStore             ← persistence only
  FeaturePreprocessor    ← data preparation only
"""

from backend.detection.exceptions import (
    DetectionError,
    ModelNotTrainedError,
    SchemaCompatibilityError,
)
from backend.detection.models import (
    DETECTION_SCHEMA_VERSION,
    DetectionAlert,
    DetectionResult,
    ModelMetadata,
    TrainingResult,
)
from backend.detection.service import DetectionService

__all__ = [
    # Service (primary entry point)
    "DetectionService",
    # Models
    "DetectionAlert",
    "DetectionResult",
    "ModelMetadata",
    "TrainingResult",
    "DETECTION_SCHEMA_VERSION",
    # Exceptions
    "DetectionError",
    "ModelNotTrainedError",
    "SchemaCompatibilityError",
]
