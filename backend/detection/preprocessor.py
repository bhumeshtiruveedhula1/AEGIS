"""
backend.detection.preprocessor — Feature Preprocessor
======================================================
Module 2.4 — Behavioral Detection Core

Handles all data preparation between raw FeatureRecord objects and
the sklearn Isolation Forest estimator.

Responsibilities
----------------
1. Validate feature schema compatibility (dimension + names).
2. Build ordered numpy arrays from FeatureRecord.feature_vector.to_array().
3. Filter FeatureRecords by entity dimension.
4. Fit a StandardScaler on training data.
5. Transform feature arrays using a fitted scaler for inference.
6. Provide deterministic, reproducible preprocessing (scaler persisted with model).

Design Principles
-----------------
- The scaler is always fitted at training time and reused at inference time.
  This ensures that the scale of features seen during training governs all
  future predictions — preventing data leakage from inference sets.
- Feature order is always ALL_FEATURE_NAMES from features.models.
  This is the single source of truth; never derive ordering locally.
- No feature engineering happens here — that is Feature Engine's job.
  The preprocessor only scales and validates.

Thread Safety
-------------
FeaturePreprocessor is stateless after fitting (the fitted scaler is
immutable post-fit). Safe for concurrent reads from multiple threads.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import numpy as np
import structlog
from sklearn.preprocessing import StandardScaler

from backend.detection.exceptions import SchemaCompatibilityError
from backend.features.models import ALL_FEATURE_NAMES, FEATURE_DIMENSION, FeatureRecord

if TYPE_CHECKING:
    pass

logger = structlog.get_logger(__name__)


class FeaturePreprocessor:
    """
    Data preparation layer between FeatureRecord objects and sklearn estimators.

    Lifecycle
    ---------
    Training:
        preprocessor = FeaturePreprocessor()
        records = [...]  # list[FeatureRecord]
        X = preprocessor.fit_transform(records, entity_dim="user_host")
        # X is a scaled numpy array, ready for IsolationForest.fit(X)

    Inference:
        X = preprocessor.transform([record])
        # Uses the scaler fitted during training

    Persistence:
        The preprocessor is embedded in the sklearn Pipeline alongside the
        IsolationForest.  Pickle save/load is handled by ModelStore.
    """

    def __init__(self) -> None:
        self._scaler: StandardScaler = StandardScaler()
        self._is_fitted: bool = False
        self._feature_names: list[str] = list(ALL_FEATURE_NAMES)
        self._feature_dimension: int = FEATURE_DIMENSION

    # ── Properties ───────────────────────────────────────────────────────────

    @property
    def is_fitted(self) -> bool:
        """True after fit_transform() has been called successfully."""
        return self._is_fitted

    @property
    def feature_names(self) -> list[str]:
        """Canonical feature name list (snapshot at construction)."""
        return self._feature_names

    @property
    def feature_dimension(self) -> int:
        """Expected feature vector dimension."""
        return self._feature_dimension

    # ── Public API ────────────────────────────────────────────────────────────

    def filter_records(
        self,
        records: list[FeatureRecord],
        entity_dim: str,
    ) -> list[FeatureRecord]:
        """
        Return only the FeatureRecord objects matching the target entity dimension.

        Parameters
        ----------
        records    : All FeatureRecord objects to filter.
        entity_dim : Entity dimension to keep (e.g. "user_host").

        Returns
        -------
        Filtered list — may be empty if no records match.
        """
        filtered = [r for r in records if r.entity_key.entity_type == entity_dim]
        logger.debug(
            "preprocessor_filter",
            total=len(records),
            kept=len(filtered),
            entity_dim=entity_dim,
        )
        return filtered

    def fit_transform(
        self,
        records: list[FeatureRecord],
        entity_dim: str = "user_host",
    ) -> np.ndarray:
        """
        Filter, build arrays, fit the StandardScaler, and return scaled X.

        This is the ONLY method that should be called during training.
        After this call, is_fitted is True and transform() may be used.

        Parameters
        ----------
        records    : list[FeatureRecord] — ALL feature records (will be filtered).
        entity_dim : Entity dimension to train on (default: "user_host").

        Returns
        -------
        np.ndarray of shape (n_samples, feature_dimension), dtype float64.

        Raises
        ------
        ValueError if no records match the entity dimension.
        """
        filtered = self.filter_records(records, entity_dim)
        if not filtered:
            msg = (
                f"No FeatureRecord objects found for entity_dim={entity_dim!r}. "
                "Cannot fit preprocessor on empty dataset."
            )
            raise ValueError(msg)

        X = self._build_array(filtered)
        X_scaled = self._scaler.fit_transform(X)
        self._is_fitted = True

        logger.info(
            "preprocessor_fitted",
            n_samples=X_scaled.shape[0],
            n_features=X_scaled.shape[1],
            entity_dim=entity_dim,
        )
        return X_scaled

    def transform(self, records: list[FeatureRecord]) -> np.ndarray:
        """
        Transform feature records using the already-fitted scaler.

        Parameters
        ----------
        records : list[FeatureRecord] — one or more records to transform.
                  Entity dimension filtering must be done by the caller.

        Returns
        -------
        np.ndarray of shape (n_samples, feature_dimension), dtype float64.

        Raises
        ------
        RuntimeError if called before fit_transform().
        """
        if not self._is_fitted:
            msg = (
                "FeaturePreprocessor has not been fitted. "
                "Call fit_transform() during training before using transform()."
            )
            raise RuntimeError(msg)
        X = self._build_array(records)
        return self._scaler.transform(X)

    def transform_single(self, record: FeatureRecord) -> np.ndarray:
        """
        Transform a single FeatureRecord into a (1, feature_dimension) array.

        Convenience wrapper around transform() for streaming inference.

        Returns
        -------
        np.ndarray of shape (1, feature_dimension).
        """
        return self.transform([record])

    def validate_schema(self) -> None:
        """
        Assert that ALL_FEATURE_NAMES has not changed since construction.

        Raises
        ------
        SchemaCompatibilityError if live schema diverges from construction snapshot.
        """
        live = list(ALL_FEATURE_NAMES)
        if live != self._feature_names:
            first_diff = next(
                (i for i, (a, b) in enumerate(zip(self._feature_names, live)) if a != b),
                len(live),
            )
            raise SchemaCompatibilityError(
                f"Live feature schema diverged from preprocessor snapshot at index {first_diff}.",
                context={
                    "snapshot_dim": len(self._feature_names),
                    "live_dim": len(live),
                    "first_divergence_index": first_diff,
                },
            )

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _build_array(self, records: list[FeatureRecord]) -> np.ndarray:
        """
        Convert a list of FeatureRecord objects into a 2-D numpy array.

        Uses FeatureVector.to_array() which guarantees canonical feature order
        and 0.0 fill for any missing features.  NaN/Inf are replaced by 0.0.

        Parameters
        ----------
        records : Non-empty list[FeatureRecord].

        Returns
        -------
        np.ndarray of shape (n, feature_dimension), dtype float64.
        """
        rows: list[list[float]] = []
        for rec in records:
            arr = rec.feature_vector.to_array()
            # Safety net: replace any non-finite value with 0.0
            row = [v if np.isfinite(v) else 0.0 for v in arr]
            rows.append(row)

        X = np.array(rows, dtype=np.float64)

        if X.shape[1] != self._feature_dimension:
            raise SchemaCompatibilityError(
                f"Feature array has {X.shape[1]} columns; expected {self._feature_dimension}.",
                context={
                    "actual_dim": X.shape[1],
                    "expected_dim": self._feature_dimension,
                },
            )
        return X
