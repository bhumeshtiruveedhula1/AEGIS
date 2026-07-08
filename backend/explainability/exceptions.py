"""
backend.explainability.exceptions — Explainability Exception Hierarchy
======================================================================
Module 3.2 — SHAP Explainability Layer

All exceptions are structured CyberShield platform errors with optional
context dicts for structured logging.
"""

from __future__ import annotations

from backend.core.exceptions import CyberShieldError


class ExplainabilityError(CyberShieldError):
    """Base class for all explainability subsystem errors."""


class ExplainerNotInitializedError(ExplainabilityError):
    """
    Raised when explain_* is called before the SHAPExplainer is initialized.
    The caller must call ExplainabilityService.initialize() first.
    """


class ExplanationComputationError(ExplainabilityError):
    """
    Raised when SHAP value computation fails for a specific record.
    Typically wraps a shap library error; the original is in context['cause'].
    """


class ModelVersionMismatchError(ExplainabilityError):
    """
    Raised when a DetectionAlert's model_id does not match the model
    currently loaded in the explainer.  Prevents silently cross-explaining
    alerts from different model versions.
    """


class ExplanationStorageError(ExplainabilityError):
    """
    Raised when ExplanationStore fails to read or write an explanation file.
    """


class SchemaCompatibilityError(ExplainabilityError):
    """
    Raised when the feature schema used to build the SHAP explainer diverges
    from the schema of the FeatureRecord being explained.
    """
