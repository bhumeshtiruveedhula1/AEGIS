"""
backend.explainability.explainer — SHAP Explainer
==================================================
Module 3.2 — SHAP Explainability Layer

Wraps shap.TreeExplainer around the Isolation Forest component of the
_DetectionPipeline to produce per-feature SHAP values for anomaly scores.

SHAP Explainer Choice
---------------------
shap.TreeExplainer is the correct and efficient choice for Isolation Forest:
- O(n_features × n_trees) — not O(2^n_features) like KernelSHAP
- Exact (not approximate) for tree ensembles
- No background dataset required for TreeSHAP with IsolationForest
- Deterministic: same input always produces same SHAP values

Design
------
The SHAPExplainer is initialized ONCE from a _DetectionPipeline.
It holds the fitted shap.TreeExplainer internally (thread-read-safe).
All explain_* methods are stateless reads — safe for concurrent use.

SHAP values for Isolation Forest
---------------------------------
shap.TreeExplainer(iforest).shap_values(X) returns an array of shape
(n_samples, n_features).  Positive SHAP value → feature pushes toward
anomaly (more isolated).  Negative SHAP value → feature pushes toward
normal.

The expected_value (base rate) is shap.TreeExplainer.expected_value.
It is a scalar for Isolation Forest (not a list).

Thread Safety
-------------
SHAPExplainer is stateless after initialization.
explain_single and explain_batch may be called concurrently.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import numpy as np
import shap
import structlog

from backend.detection.models import DetectionAlert
from backend.explainability.exceptions import (
    ExplainerNotInitializedError,
    ExplanationComputationError,
    ModelVersionMismatchError,
    SchemaCompatibilityError,
)
from backend.explainability.models import ExplanationResult, FeatureContribution
from backend.features.models import ALL_FEATURE_NAMES, FeatureRecord

if TYPE_CHECKING:
    pass

logger = structlog.get_logger(__name__)

# Default number of top features to include in ExplanationResult.top_features
DEFAULT_TOP_N = 5


class SHAPExplainer:
    """
    TreeSHAP explainer for the Isolation Forest behavioral anomaly model.

    Parameters
    ----------
    pipeline  : _DetectionPipeline from IsolationForestTrainer.
    model_id  : Model version ID (for cross-checking with DetectionAlerts).
    top_n     : Number of top features to capture in top_features list.

    Lifecycle
    ---------
        explainer = SHAPExplainer(pipeline, metadata.model_id)
        result    = explainer.explain_alert(alert, feature_record)
        results   = explainer.explain_batch(alerts, records)
    """

    def __init__(
        self,
        pipeline: Any,  # _DetectionPipeline — avoid circular import
        model_id: str,
        *,
        top_n: int = DEFAULT_TOP_N,
    ) -> None:
        self._pipeline = pipeline
        self._model_id = model_id
        self._top_n = top_n
        self._feature_names: list[str] = list(ALL_FEATURE_NAMES)
        self._n_features: int = len(self._feature_names)

        # Build TreeExplainer from the IsolationForest component
        try:
            self._tree_explainer = shap.TreeExplainer(
                pipeline.isolation_forest,
                feature_perturbation="tree_path_dependent",
            )
            self._expected_value: float = float(
                self._tree_explainer.expected_value
                if np.isscalar(self._tree_explainer.expected_value)
                else float(self._tree_explainer.expected_value[0])
            )
        except Exception as exc:
            raise ExplanationComputationError(
                f"Failed to initialize TreeExplainer: {exc}",
                context={"model_id": model_id, "cause": str(exc)},
            ) from exc

        logger.info(
            "shap_explainer_initialized",
            model_id=model_id,
            n_features=self._n_features,
            expected_value=round(self._expected_value, 6),
            top_n=top_n,
        )

    # ── Properties ───────────────────────────────────────────────────────────

    @property
    def model_id(self) -> str:
        return self._model_id

    @property
    def expected_value(self) -> float:
        return self._expected_value

    @property
    def feature_names(self) -> list[str]:
        return self._feature_names

    # ── Core explain API ─────────────────────────────────────────────────────

    def explain_alert(
        self,
        alert: DetectionAlert,
        feature_record: FeatureRecord,
    ) -> ExplanationResult:
        """
        Compute SHAP explanation for a single DetectionAlert.

        Parameters
        ----------
        alert          : The DetectionAlert to explain.
        feature_record : The FeatureRecord that was scored to produce the alert.
                         Must correspond to the same event.

        Returns
        -------
        ExplanationResult — fully populated explanation.

        Raises
        ------
        ModelVersionMismatchError  — alert.model_id != self.model_id
        SchemaCompatibilityError   — feature_record dimension mismatch
        ExplanationComputationError — shap computation failure
        """
        self._validate_alert_model_id(alert)

        # Transform the feature record using the pipeline's fitted preprocessor
        try:
            X_scaled = self._pipeline.preprocessor.transform_single(feature_record)
        except Exception as exc:
            raise ExplanationComputationError(
                "Failed to transform FeatureRecord for SHAP computation.",
                context={
                    "alert_id": alert.alert_id,
                    "event_id": alert.event_id,
                    "cause": str(exc),
                },
            ) from exc

        # Compute SHAP values via TreeExplainer
        shap_values = self._compute_shap_values(X_scaled, alert.alert_id)

        # shap_values shape: (1, n_features) — take first row
        raw_shap: list[float] = shap_values[0].tolist()

        return self._build_result(alert, raw_shap)

    def explain_batch(
        self,
        alerts: list[DetectionAlert],
        feature_records: list[FeatureRecord],
    ) -> list[ExplanationResult]:
        """
        Vectorised batch explanation for multiple alerts.

        Computes SHAP values in a single TreeExplainer call for efficiency.
        Alerts and feature_records must be parallel lists (index i matches).

        Parameters
        ----------
        alerts         : List of DetectionAlert objects to explain.
        feature_records: Corresponding FeatureRecord objects (same order).

        Returns
        -------
        list[ExplanationResult] — one per alert, in input order.
        Failures are logged and skipped (empty list on total failure).

        Raises
        ------
        ValueError — if len(alerts) != len(feature_records)
        """
        if len(alerts) != len(feature_records):
            raise ValueError(
                f"alerts and feature_records must be parallel lists: "
                f"got {len(alerts)} alerts and {len(feature_records)} records."
            )

        if not alerts:
            return []

        # Validate all alerts belong to this model
        for alert in alerts:
            self._validate_alert_model_id(alert)

        # Build batch X matrix
        rows: list[np.ndarray] = []
        valid_indices: list[int] = []
        for i, (alert, record) in enumerate(zip(alerts, feature_records)):
            try:
                row = self._pipeline.preprocessor.transform_single(record)
                rows.append(row)
                valid_indices.append(i)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "batch_explain_transform_error",
                    alert_id=alert.alert_id,
                    index=i,
                    error=str(exc),
                )

        if not rows:
            return []

        X_batch = np.vstack(rows)  # (n_valid, n_features)
        shap_matrix = self._compute_shap_values(X_batch, "batch")

        results: list[ExplanationResult] = []
        for result_idx, orig_idx in enumerate(valid_indices):
            alert = alerts[orig_idx]
            raw_shap: list[float] = shap_matrix[result_idx].tolist()
            try:
                result = self._build_result(alert, raw_shap)
                results.append(result)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "batch_explain_build_error",
                    alert_id=alert.alert_id,
                    error=str(exc),
                )

        logger.info(
            "batch_explanation_complete",
            model_id=self._model_id,
            input_count=len(alerts),
            explained_count=len(results),
        )
        return results

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _validate_alert_model_id(self, alert: DetectionAlert) -> None:
        """Raise ModelVersionMismatchError if alert.model_id != self.model_id."""
        if alert.model_id != self._model_id:
            raise ModelVersionMismatchError(
                f"Alert model_id={alert.model_id!r} does not match "
                f"explainer model_id={self._model_id!r}. "
                "Reload the explainer for this model version.",
                context={
                    "alert_model_id": alert.model_id,
                    "explainer_model_id": self._model_id,
                    "alert_id": alert.alert_id,
                },
            )

    def _compute_shap_values(
        self,
        X: np.ndarray,
        context_label: str,
    ) -> np.ndarray:
        """
        Run TreeExplainer and return SHAP values of shape (n_samples, n_features).

        Raises ExplanationComputationError on shap failure.
        """
        try:
            sv = self._tree_explainer.shap_values(X)
            # shap returns ndarray for IsolationForest
            if isinstance(sv, list):
                sv = sv[0]  # some shap versions return list[ndarray]
            return np.array(sv, dtype=np.float64)
        except Exception as exc:
            raise ExplanationComputationError(
                f"TreeSHAP computation failed: {exc}",
                context={"context": context_label, "cause": str(exc)},
            ) from exc

    def _build_result(
        self,
        alert: DetectionAlert,
        raw_shap: list[float],
    ) -> ExplanationResult:
        """
        Construct an ExplanationResult from a DetectionAlert and raw SHAP list.

        Parameters
        ----------
        alert    : The DetectionAlert being explained.
        raw_shap : List of SHAP values, one per feature (same order as ALL_FEATURE_NAMES).
        """
        # Total |SHAP| for percentage calculation
        total_abs = sum(abs(v) for v in raw_shap if isinstance(v, float))
        if total_abs == 0.0:
            total_abs = 1e-10  # avoid division by zero

        # Build and sort contributions by |SHAP| descending
        raw_values = alert.raw_feature_values or {}
        contributions_unsorted = [
            FeatureContribution.build(
                feature_name=name,
                raw_value=raw_values.get(name, 0.0),
                shap_value=raw_shap[i],
                rank=1,  # placeholder — set after sort
                total_abs_shap=total_abs,
            )
            for i, name in enumerate(self._feature_names)
        ]

        # Sort by shap_value descending (positive contributions = why it's anomalous), assign ranks
        sorted_contributions = sorted(
            contributions_unsorted,
            key=lambda c: c.shap_value,
            reverse=True,
        )
        # Rebuild with correct ranks
        final_contributions = [
            c.model_copy(update={"contribution_rank": rank})
            for rank, c in enumerate(sorted_contributions, start=1)
        ]

        top_features = [
            c.feature_name for c in final_contributions[: self._top_n]
        ]

        return ExplanationResult(
            alert_id=alert.alert_id,
            model_id=self._model_id,
            entity_type=alert.entity_key.entity_type,
            entity_id=alert.entity_key.entity_id,
            event_id=alert.event_id,
            anomaly_score=alert.anomaly_score,
            expected_value=self._expected_value,
            total_abs_shap=round(total_abs, 8),
            feature_contributions=final_contributions,
            top_features=top_features,
            raw_feature_values={
                k: (v if isinstance(v, float) else float(v))
                for k, v in raw_values.items()
            },
        )
