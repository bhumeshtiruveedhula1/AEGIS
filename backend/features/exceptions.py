"""
backend.features.exceptions — Feature Engine Exception Hierarchy
================================================================
Module 2.2 — Behavioral Feature Engine

All Feature Engine failures derive from FeatureEngineError.
Each exception is specific enough to be caught independently.

Hierarchy
---------
  FeatureEngineError
    FeatureInputError       — bad or missing input (event or baseline)
    FeatureExtractionError  — extractor failed during computation
    FeatureSchemaError      — feature vector schema violation
    FeatureWriterError      — I/O error writing feature vectors
    FeaturePipelineError    — orchestration-level failure
"""

from __future__ import annotations


class FeatureEngineError(Exception):
    """Root exception for all Feature Engine failures."""

    def __init__(self, message: str, *, context: dict | None = None) -> None:
        super().__init__(message)
        self.context: dict = context or {}

    def __str__(self) -> str:
        base = super().__str__()
        if self.context:
            ctx = ", ".join(f"{k}={v!r}" for k, v in self.context.items())
            return f"{base} [{ctx}]"
        return base


class FeatureInputError(FeatureEngineError):
    """
    Raised when input to the Feature Engine is invalid or missing.

    Examples
    --------
    - CanonicalEvent field has an unexpected type
    - Required event field is None when not permitted
    - Input file does not exist or is empty
    """


class FeatureExtractionError(FeatureEngineError):
    """
    Raised when an extractor encounters an unrecoverable computation error.

    Feature extraction errors are normally logged and skipped (per-extractor
    isolation), but this exception is raised when the failure is irrecoverable
    at the pipeline level.

    Context keys
    ------------
    extractor   — name of the extractor that failed
    event_id    — ID of the event being processed
    """


class FeatureSchemaError(FeatureEngineError):
    """
    Raised when a feature vector violates the expected schema contract.

    Examples
    --------
    - A feature returns NaN instead of a float
    - Feature name is not in the declared feature set
    - Feature count does not match the expected feature schema
    """


class FeatureWriterError(FeatureEngineError):
    """
    Raised when the FeatureVectorWriter cannot persist feature vectors.

    Examples
    --------
    - Output directory does not exist and cannot be created
    - Disk full during write
    - Serialisation failure
    """


class FeaturePipelineError(FeatureEngineError):
    """
    Raised when the FeaturePipeline encounters an unrecoverable failure.

    Context keys
    ------------
    stage       — pipeline stage where failure occurred
    events_processed — count of events processed before failure
    """
