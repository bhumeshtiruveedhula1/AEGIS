"""
backend.detection.trainer — Isolation Forest Trainer
=====================================================
Module 2.4 — Behavioral Detection Core

Trains the behavioral anomaly detection model using scikit-learn's
IsolationForest on normal-behavior-only feature vectors.

Design
------
The trainer produces a sklearn Pipeline that encapsulates:
  Step 1: FeaturePreprocessor (StandardScaler)
  Step 2: IsolationForest

This Pipeline is what gets pickled by ModelStore.  Embedding the scaler
inside the pipeline ensures that inference always uses the training-time
scale transformation — no configuration drift possible.

Key Principles
--------------
- NORMAL BEHAVIOR ONLY: The model never sees attack-labelled data.
  Anomalies are inferred purely from deviation from normal training data.
- Reproducibility: random_state is always set explicitly.
- Configurable: contamination, n_estimators, random_state all come from
  settings — no hardcoded values.
- Incremental retraining: implemented as full refit on all available data
  (old + new).  IsolationForest has no true online learning API.
- Separation of concerns: the trainer only trains.  It does not score,
  persist, or manage model versions — that is scorer.py and storage.py.

Thread Safety
-------------
IsolationForestTrainer is stateless.  Multiple threads may call train()
concurrently on independent inputs without conflict.
"""

from __future__ import annotations

import time
from typing import Any

import structlog
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline

from backend.core.config import get_settings
from backend.detection.models import (
    ModelMetadata,
    TrainingResult,
)
from backend.detection.preprocessor import FeaturePreprocessor
from backend.features.models import (
    ALL_FEATURE_NAMES,
    FEATURE_DIMENSION,
    FEATURE_SCHEMA_VERSION,
    FeatureRecord,
)
from backend.shared.utils.id_utils import generate_id

logger = structlog.get_logger(__name__)


class IsolationForestTrainer:
    """
    Trains a behavioral anomaly detection model using Isolation Forest.

    Wraps sklearn's IsolationForest in a Pipeline with StandardScaler
    preprocessing.  Configurable via application settings.

    Parameters
    ----------
    contamination : Override contamination rate (default: settings value).
    n_estimators  : Override number of isolation trees (default: settings value).
    random_state  : Override random seed (default: settings value).
    entity_dim    : Entity dimension to train on (default: "user_host").

    Usage
    -----
        trainer = IsolationForestTrainer()
        pipeline, result = trainer.train(feature_records)
        # pipeline is ready for AnomalyScorer
        # result.model_id, .sample_count, .training_duration_seconds
    """

    def __init__(
        self,
        *,
        contamination: float | None = None,
        n_estimators: int | None = None,
        random_state: int | None = None,
        max_samples: int | float | str | None = None,
        max_features: int | float | str | None = None,
        entity_dim: str = "user_host",
    ) -> None:
        settings = get_settings()
        self._contamination = (
            contamination if contamination is not None else settings.isolation_forest_contamination
        )
        self._n_estimators = (
            n_estimators if n_estimators is not None else settings.isolation_forest_n_estimators
        )
        self._random_state = (
            random_state if random_state is not None else settings.isolation_forest_random_state
        )
        self._max_samples = (
            max_samples if max_samples is not None else settings.isolation_forest_max_samples
        )
        self._max_features = (
            max_features if max_features is not None else settings.isolation_forest_max_features
        )
        self._entity_dim = entity_dim

        logger.debug(
            "trainer_initialised",
            contamination=self._contamination,
            n_estimators=self._n_estimators,
            random_state=self._random_state,
            max_samples=self._max_samples,
            max_features=self._max_features,
            entity_dim=self._entity_dim,
        )

    # ── Public API ────────────────────────────────────────────────────────────

    def train(
        self,
        feature_records: list[FeatureRecord],
        *,
        model_id: str | None = None,
        notes: str | None = None,
    ) -> tuple[Pipeline, ModelMetadata, TrainingResult]:
        """
        Train an Isolation Forest on the provided FeatureRecord objects.

        Only records matching self._entity_dim are used for training.
        Training is always normal-behavior-only — no attack labels involved.

        Parameters
        ----------
        feature_records : All available FeatureRecord objects.
                          The trainer filters by entity dimension internally.
        model_id        : Override the generated model_id (useful in tests).
        notes           : Optional annotation stored in ModelMetadata.

        Returns
        -------
        (pipeline, metadata, training_result)
          pipeline         : Fitted sklearn Pipeline (scaler + IsolationForest)
          metadata         : Complete ModelMetadata (persisted alongside pickle)
          training_result  : Summary of the training run

        Raises
        ------
        ValueError if no records match the entity dimension.
        """
        resolved_model_id = model_id or f"iforest-{generate_id()}"

        logger.info(
            "training_started",
            model_id=resolved_model_id,
            entity_dim=self._entity_dim,
            total_records=len(feature_records),
            contamination=self._contamination,
            n_estimators=self._n_estimators,
            random_state=self._random_state,
        )

        t_start = time.perf_counter()

        # Step 1: Preprocess — filter by entity dim + scale
        preprocessor = FeaturePreprocessor()
        X_scaled = preprocessor.fit_transform(feature_records, entity_dim=self._entity_dim)

        filtered_records = preprocessor.filter_records(feature_records, self._entity_dim)
        entity_ids = {r.entity_key.entity_id for r in filtered_records}
        n_samples, n_features = X_scaled.shape

        # Step 2: Build and fit IsolationForest
        isolation_forest = IsolationForest(
            n_estimators=self._n_estimators,
            contamination=self._contamination,
            random_state=self._random_state,
            max_samples=self._max_samples,
            max_features=self._max_features,
            n_jobs=-1,  # use all available CPUs during training
        )
        isolation_forest.fit(X_scaled)

        # Step 3: Assemble into a sklearn Pipeline for unified save/load
        #         Note: The preprocessor is already fitted; we store the
        #         fitted scaler directly.  The Pipeline here is a container
        #         for atomic pickle + schema metadata binding.
        pipeline = _DetectionPipeline(
            preprocessor=preprocessor,
            isolation_forest=isolation_forest,
        )

        duration = time.perf_counter() - t_start

        # Step 4: Build metadata
        # model_file is set by ModelStore after save; placeholder here.
        metadata = ModelMetadata(
            model_id=resolved_model_id,
            feature_schema_version=FEATURE_SCHEMA_VERSION,
            feature_names=list(ALL_FEATURE_NAMES),
            feature_dimension=FEATURE_DIMENSION,
            n_estimators=self._n_estimators,
            contamination=self._contamination,
            random_state=self._random_state,
            entity_dimension=self._entity_dim,
            entity_count=len(entity_ids),
            sample_count=n_samples,
            training_duration_seconds=round(duration, 4),
            scaler_fitted=True,
            model_file=f"isolation_forest_{resolved_model_id}.pkl",
            notes=notes,
        )

        # Step 5: Build training result (paths set by service after ModelStore.save)
        training_result = TrainingResult(
            model_id=resolved_model_id,
            entity_dimension=self._entity_dim,
            entity_count=len(entity_ids),
            sample_count=n_samples,
            feature_dimension=FEATURE_DIMENSION,
            contamination=self._contamination,
            n_estimators=self._n_estimators,
            random_state=self._random_state,
            training_duration_seconds=round(duration, 4),
            model_path="",  # filled by DetectionService after save
            metadata_path="",  # filled by DetectionService after save
        )

        logger.info(
            "training_complete",
            model_id=resolved_model_id,
            n_samples=n_samples,
            n_features=n_features,
            entity_count=len(entity_ids),
            duration_s=round(duration, 4),
            max_samples=self._max_samples,
            max_features=self._max_features,
        )

        return pipeline, metadata, training_result

    def retrain(
        self,
        existing_records: list[FeatureRecord],
        new_records: list[FeatureRecord],
        *,
        notes: str | None = None,
    ) -> tuple[Any, ModelMetadata, TrainingResult]:
        """
        Incremental retraining by full refit on combined dataset.

        IsolationForest has no true online learning API.  The correct
        approach is to retrain from scratch on existing + new data.

        Parameters
        ----------
        existing_records : Previously used training records.
        new_records      : Newly available records to incorporate.
        notes            : Annotation for ModelMetadata.

        Returns
        -------
        Same as train() — (pipeline, metadata, training_result).
        """
        combined = existing_records + new_records
        retrain_notes = notes or f"Incremental retrain: +{len(new_records)} new records."

        logger.info(
            "retrain_initiated",
            existing_records=len(existing_records),
            new_records=len(new_records),
            total=len(combined),
        )
        return self.train(combined, notes=retrain_notes)


# ---------------------------------------------------------------------------
# _DetectionPipeline — lightweight container for scaler + IF
# ---------------------------------------------------------------------------


class _DetectionPipeline:
    """
    Minimal container wrapping a fitted FeaturePreprocessor and IsolationForest.

    This is NOT a sklearn Pipeline subclass — it is a simple Python object
    that groups the two components for atomic serialisation.  Using a custom
    class avoids sklearn Pipeline's step-fitting machinery which would
    re-fit the already-fitted preprocessor on transform() calls.

    The AnomalyScorer uses this interface:
        pipeline.preprocessor  : FeaturePreprocessor
        pipeline.isolation_forest : IsolationForest
    """

    __slots__ = ("preprocessor", "isolation_forest", "_training_X")

    def __init__(
        self,
        preprocessor: FeaturePreprocessor,
        isolation_forest: IsolationForest,
    ) -> None:
        self.preprocessor = preprocessor
        self.isolation_forest = isolation_forest

    def __repr__(self) -> str:
        return (
            f"_DetectionPipeline("
            f"scaler_fitted={self.preprocessor.is_fitted}, "
            f"n_estimators={self.isolation_forest.n_estimators})"
        )
