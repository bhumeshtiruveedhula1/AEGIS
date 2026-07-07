"""
backend.features — Behavioral Feature Engine
============================================
Module 2.2 — Operation AEGIS Phase 2

Public API surface for the Behavioral Feature Engine.

The Feature Engine transforms normalized telemetry (CanonicalEvent) + learned
behavioral baselines (BaselineReader) into deterministic behavioral feature
vectors for downstream ML components.

Quick Start
-----------
    # Single event
    from backend.features import FeaturePipeline, BaselineReader

    reader = BaselineReader()
    pipeline = FeaturePipeline(baseline_reader=reader)
    records = pipeline.process_event(event)

    # Full pipeline run
    from backend.features import FeatureService

    service = FeatureService()
    report = service.extract_from_normalized_output()

    # Inspect a feature vector
    from backend.features import FeatureVector, ALL_FEATURE_NAMES, FEATURE_DIMENSION

    vec = records[0].feature_vector
    print(vec.to_array())           # List of 56 floats in canonical order
    print(vec.group("temporal"))    # Just temporal features
    print(vec.novelty_count())      # How many novelty flags fired

Downstream Contract
-------------------
- FeatureRecord is the atomic output unit.
- FeatureVector.to_array() returns a list of FEATURE_DIMENSION floats.
- Feature names are stable and listed in ALL_FEATURE_NAMES.
- FEATURE_SCHEMA_VERSION must be checked before consuming stored vectors.
"""

from __future__ import annotations

# Core models
from backend.features.models import (
    FEATURE_DIMENSION,
    FEATURE_GROUPS,
    FEATURE_SCHEMA_VERSION,
    ALL_FEATURE_NAMES,
    FeaturePipelineReport,
    FeatureRecord,
    FeatureSchema,
    FeatureVector,
)

# Pipeline and writer
from backend.features.pipeline import FeaturePipeline
from backend.features.writer import FeatureVectorWriter
from backend.features.service import FeatureService

# Exceptions
from backend.features.exceptions import (
    FeatureEngineError,
    FeatureExtractionError,
    FeatureInputError,
    FeaturePipelineError,
    FeatureSchemaError,
    FeatureWriterError,
)

# Extractor utilities (for extension)
from backend.features.extractors import (
    BaseExtractor,
    binary,
    frequency_rank,
    get_all_extractors,
    get_extractor_registry,
    safe_frequency,
    safe_percentile_rank,
    safe_z_score,
)

__all__ = [
    # Schema constants
    "FEATURE_SCHEMA_VERSION",
    "FEATURE_DIMENSION",
    "FEATURE_GROUPS",
    "ALL_FEATURE_NAMES",
    # Models
    "FeatureSchema",
    "FeatureVector",
    "FeatureRecord",
    "FeaturePipelineReport",
    # Pipeline
    "FeaturePipeline",
    "FeatureVectorWriter",
    "FeatureService",
    # Exceptions
    "FeatureEngineError",
    "FeatureExtractionError",
    "FeatureInputError",
    "FeaturePipelineError",
    "FeatureSchemaError",
    "FeatureWriterError",
    # Extractor utilities
    "BaseExtractor",
    "binary",
    "frequency_rank",
    "get_all_extractors",
    "get_extractor_registry",
    "safe_frequency",
    "safe_percentile_rank",
    "safe_z_score",
]
