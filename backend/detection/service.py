"""
backend.detection.service — Detection Service
==============================================
Module 2.4 — Behavioral Detection Core

DetectionService is the ONLY entry point for all detection operations.
Application code, API endpoints, and pipeline orchestrators call this
service exclusively — never trainer, scorer, or storage directly.

Responsibilities
----------------
1. Wire up trainer, scorer, storage, and feature reader.
2. Provide train_from_features() — full training pipeline.
3. Provide score_event() — single-record inference.
4. Provide score_batch_from_features() — batch offline inference.
5. Provide score_stream() — streaming live inference.
6. Manage model lifecycle: load on demand, reload on request.
7. Expose model status and metadata for health endpoints.

Layered Architecture (enforced separation)
------------------------------------------
  DetectionService      ← orchestration only
      ├── IsolationForestTrainer   ← training only
      ├── AnomalyScorer            ← inference only
      ├── ModelStore               ← persistence only
      └── FeaturePreprocessor      ← data prep only (owned by trainer/scorer)

Usage
-----
    from backend.detection.service import DetectionService

    service = DetectionService()

    # Train from all available feature records
    result = service.train_from_features()

    # Score a single record (streaming mode)
    alert = service.score_event(feature_record)

    # Score all available records (batch mode)
    detection_result = service.score_batch_from_features()

    # Streaming inference over an iterable
    for alert in service.score_stream(record_iterable):
        ...

    # Model info
    if service.is_model_loaded:
        print(service.current_model_id)
"""

from __future__ import annotations

import sys
from collections.abc import Iterable, Iterator
from pathlib import Path

import structlog

from backend.core.config import get_settings
from backend.detection.exceptions import ModelNotTrainedError, SchemaCompatibilityError
from backend.detection.models import (
    DetectionAlert,
    DetectionResult,
    ModelMetadata,
    TrainingResult,
)
from backend.detection.scorer import AnomalyScorer
from backend.detection.storage import ModelStore
from backend.detection.trainer import IsolationForestTrainer
from backend.features.models import FeatureRecord

_CYBERSHIELD_ROOT = Path(__file__).parent.parent.parent
_LAB_ROOT = _CYBERSHIELD_ROOT.parent / "aegis_ml_lab"
for _p in (str(_CYBERSHIELD_ROOT), str(_LAB_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

logger = structlog.get_logger(__name__)

_CALIBRATOR_SUFFIX = "_calibrator.pkl"
_CAL_THRESHOLD_SUFFIX = "_cal_threshold.json"


def _load_calibrator_for_model(
    store_dir: Path,
    model_id: str,
) -> tuple[object, float] | tuple[None, None]:
    """
    Load a calibrator + its threshold for the given model_id if present.

    Looks for:
      <store_dir>/isolation_forest_<model_id>_calibrator.pkl
      <store_dir>/isolation_forest_<model_id>_cal_threshold.json

    Returns (calibrator, calibrated_threshold) or (None, None) if not found.
    Failure is always non-fatal: logs a warning and returns (None, None).
    """
    import json
    import pickle as _pickle

    cal_path = store_dir / f"isolation_forest_{model_id}{_CALIBRATOR_SUFFIX}"
    thr_path = store_dir / f"isolation_forest_{model_id}{_CAL_THRESHOLD_SUFFIX}"
    if not cal_path.exists() or not thr_path.exists():
        return None, None
    try:
        with cal_path.open("rb") as fh:
            calibrator = _pickle.load(fh)
        threshold = float(json.loads(thr_path.read_text())["calibrated_threshold"])
        logger.info(
            "calibrator_loaded",
            model_id=model_id,
            calibrated_threshold=threshold,
            calibrator_path=str(cal_path),
        )
        return calibrator, threshold
    except Exception as exc:
        logger.warning(
            "calibrator_load_failed",
            model_id=model_id,
            error=str(exc),
            note="Falling back to uncalibrated scoring.",
        )
        return None, None


class DetectionService:
    """
    Top-level orchestrator for the behavioral detection subsystem.

    Parameters
    ----------
    features_dir  : Override the feature records source directory.
                    Defaults to settings.data_dir / "features".
    models_dir    : Override the model artifact store directory.
                    Defaults to settings.models_dir.
    threshold     : Override the anomaly score threshold.
                    Defaults to settings.anomaly_score_threshold.
    entity_dim    : Entity dimension for training and scoring.
                    Defaults to "user_host" (primary dimension).
    auto_load     : If True, attempt to load the latest model on init.
                    Defaults to True.
    """

    def __init__(
        self,
        *,
        features_dir: Path | None = None,
        models_dir: Path | None = None,
        threshold: float | None = None,
        entity_dim: str = "user_host",
        auto_load: bool = True,
    ) -> None:
        settings = get_settings()
        self._features_dir = features_dir or (settings.data_dir / "features")
        self._settings = settings
        self._entity_dim = entity_dim
        self._threshold = threshold if threshold is not None else settings.anomaly_score_threshold

        self._store = ModelStore(store_dir=models_dir)
        self._scorer: AnomalyScorer | None = None
        self._current_metadata: ModelMetadata | None = None

        if auto_load:
            self._try_load_latest()

        logger.info(
            "detection_service_initialised",
            entity_dim=self._entity_dim,
            threshold=self._threshold,
            model_loaded=self.is_model_loaded,
            features_dir=str(self._features_dir),
        )

    # ── Status properties ─────────────────────────────────────────────────────

    @property
    def is_model_loaded(self) -> bool:
        """True if a model has been loaded and is ready for inference."""
        return self._scorer is not None

    @property
    def current_model_id(self) -> str | None:
        """model_id of the currently loaded model, or None."""
        if self._current_metadata is None:
            return None
        return self._current_metadata.model_id

    @property
    def current_metadata(self) -> ModelMetadata | None:
        """Full ModelMetadata of the currently loaded model, or None."""
        return self._current_metadata

    # ── Training API ──────────────────────────────────────────────────────────

    def train_from_features(
        self,
        *,
        feature_records: list[FeatureRecord] | None = None,
        notes: str | None = None,
    ) -> TrainingResult:
        """
        Train a new Isolation Forest on available feature records.

        If feature_records is not provided, reads all JSONL files from
        self._features_dir automatically.

        After training:
        - Model is persisted to ModelStore (atomic write).
        - Service reloads the new model for immediate inference.
        - The previously loaded model is replaced in-memory.

        Parameters
        ----------
        feature_records : Pre-loaded records (optional).
                          If None, reads from features_dir.
        notes           : Annotation stored in ModelMetadata.

        Returns
        -------
        TrainingResult — complete training summary.

        Raises
        ------
        ValueError if no records are available for the target entity dimension.
        """
        records = feature_records or self._load_all_feature_records()

        logger.info(
            "training_initiated",
            entity_dim=self._entity_dim,
            total_records=len(records),
        )

        trainer = IsolationForestTrainer(entity_dim=self._entity_dim)
        pipeline, metadata, result = trainer.train(records, notes=notes)

        # Persist
        model_path, meta_path = self._store.save(pipeline, metadata)

        # Update result with actual paths
        result = result.model_copy(
            update={
                "model_path": str(model_path),
                "metadata_path": str(meta_path),
            }
        )

        # Reload into memory immediately — with calibrator if available
        calibrator, cal_threshold = _load_calibrator_for_model(self._store._dir, metadata.model_id)
        self._scorer = AnomalyScorer(
            pipeline,
            metadata,
            threshold=self._threshold,
            calibrator=calibrator,
            calibrated_threshold=cal_threshold,
        )
        self._current_metadata = metadata

        logger.info(
            "training_saved_and_loaded",
            model_id=result.model_id,
            sample_count=result.sample_count,
            entity_count=result.entity_count,
            duration_s=result.training_duration_seconds,
            model_path=str(model_path),
        )
        return result

    def retrain_incremental(
        self,
        new_records: list[FeatureRecord],
        *,
        notes: str | None = None,
        existing_records: list[FeatureRecord] | None = None,
    ) -> TrainingResult:
        """
        Retrain on existing + new feature records (full refit).

        Loads all existing records from features_dir and combines with
        new_records before training.  IsolationForest has no online
        learning API; full refit on all data is the correct approach.

        Parameters
        ----------
        new_records      : Newly available FeatureRecord objects to incorporate.
        notes            : Annotation for ModelMetadata.
        existing_records : Pre-loaded existing records (optional).
                           If None, reads from features_dir.

        Returns
        -------
        TrainingResult — same contract as train_from_features().
        """
        existing = (
            existing_records if existing_records is not None else self._load_all_feature_records()
        )

        logger.info(
            "incremental_retrain_initiated",
            existing_records=len(existing),
            new_records=len(new_records),
        )

        trainer = IsolationForestTrainer(entity_dim=self._entity_dim)
        pipeline, metadata, result = trainer.retrain(existing, new_records, notes=notes)

        model_path, meta_path = self._store.save(pipeline, metadata)
        result = result.model_copy(
            update={
                "model_path": str(model_path),
                "metadata_path": str(meta_path),
            }
        )

        calibrator, cal_threshold = _load_calibrator_for_model(self._store._dir, metadata.model_id)
        self._scorer = AnomalyScorer(
            pipeline,
            metadata,
            threshold=self._threshold,
            calibrator=calibrator,
            calibrated_threshold=cal_threshold,
        )
        self._current_metadata = metadata

        logger.info(
            "incremental_retrain_complete",
            model_id=result.model_id,
            total_samples=result.sample_count,
        )
        return result

    # ── Inference API ─────────────────────────────────────────────────────────

    def score_event(
        self,
        feature_record: FeatureRecord,
    ) -> DetectionAlert | None:
        """
        Score a single FeatureRecord for anomalous behavior.

        Parameters
        ----------
        feature_record : A FeatureRecord from the Feature Engine output.
                         Entity dimension must match the trained model.

        Returns
        -------
        DetectionAlert — if anomaly_score >= threshold.
        None           — if the record is scored as normal.

        Raises
        ------
        ModelNotTrainedError if no model is loaded.
        """
        self._require_model()
        return self._scorer.score_single(feature_record)  # type: ignore[union-attr]

    def score_batch_from_features(
        self,
        *,
        feature_records: list[FeatureRecord] | None = None,
    ) -> DetectionResult:
        """
        Score all feature records in batch mode.

        Parameters
        ----------
        feature_records : Pre-loaded records (optional).
                          If None, reads from features_dir.

        Returns
        -------
        DetectionResult — aggregate scoring outcome with all alerts.

        Raises
        ------
        ModelNotTrainedError if no model is loaded.
        """
        self._require_model()
        records = feature_records or self._load_all_feature_records()
        return self._scorer.score_batch(records, entity_dim=self._entity_dim)  # type: ignore[union-attr]

    def score_stream(
        self,
        records: Iterable[FeatureRecord],
        *,
        entity_dim: str | None = None,
    ) -> Iterator[DetectionAlert]:
        """
        Stream inference over any iterable of FeatureRecord objects.

        Yields DetectionAlert for each anomalous record above threshold.
        Normal records are silently consumed.

        Parameters
        ----------
        records    : Any iterable of FeatureRecord (file reader, queue, etc.)
        entity_dim : Override entity dimension filter.

        Yields
        ------
        DetectionAlert objects, in arrival order.

        Raises
        ------
        ModelNotTrainedError if no model is loaded.
        """
        self._require_model()
        yield from self._scorer.score_stream(  # type: ignore[union-attr]
            records,
            entity_dim=entity_dim or self._entity_dim,
        )

    # ── Model lifecycle ───────────────────────────────────────────────────────

    def reload_model(self, *, model_id: str | None = None) -> ModelMetadata:
        """
        Reload a model from disk into memory.

        Parameters
        ----------
        model_id : Specific model version to load.
                   If None, loads the most recently trained model.

        Returns
        -------
        ModelMetadata of the newly loaded model.

        Raises
        ------
        ModelNotTrainedError if no model is found.
        SchemaCompatibilityError if schema mismatch.
        """
        if model_id:
            pipeline, metadata = self._store.load_by_id(model_id)
        else:
            pipeline, metadata = self._store.load_latest()

        calibrator, cal_threshold = _load_calibrator_for_model(self._store._dir, metadata.model_id)
        self._scorer = AnomalyScorer(
            pipeline,
            metadata,
            threshold=self._threshold,
            calibrator=calibrator,
            calibrated_threshold=cal_threshold,
        )
        self._current_metadata = metadata

        logger.info(
            "model_reloaded",
            model_id=metadata.model_id,
            entity_dimension=metadata.entity_dimension,
        )
        return metadata

    def list_available_models(self) -> list[ModelMetadata]:
        """Return all available model versions from ModelStore (newest first)."""
        return self._store.list_models()

    def get_status(self) -> dict:
        """
        Return a compact dict describing current detection service state.
        Suitable for health check endpoints and MetricService integration.
        """
        status: dict = {
            "model_loaded": self.is_model_loaded,
            "entity_dimension": self._entity_dim,
            "threshold": self._threshold,
        }
        if self._current_metadata:
            status.update(
                {
                    "model_id": self._current_metadata.model_id,
                    "trained_at": self._current_metadata.trained_at.isoformat(),
                    "sample_count": self._current_metadata.sample_count,
                    "entity_count": self._current_metadata.entity_count,
                    "feature_dimension": self._current_metadata.feature_dimension,
                    "contamination": self._current_metadata.contamination,
                    "n_estimators": self._current_metadata.n_estimators,
                }
            )
        return status

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _require_model(self) -> None:
        """Raise ModelNotTrainedError if no model is loaded."""
        if self._scorer is None:
            raise ModelNotTrainedError(
                "No model is loaded. Call train_from_features() first "
                "or ensure a trained model exists in the models directory.",
                context={"entity_dim": self._entity_dim},
            )

    def _try_load_latest(self) -> None:
        """Attempt to load the latest model; log and continue if none exists."""
        try:
            pipeline, metadata = self._store.load_latest()
            calibrator, cal_threshold = _load_calibrator_for_model(
                self._store._dir, metadata.model_id
            )
            self._scorer = AnomalyScorer(
                pipeline,
                metadata,
                threshold=self._threshold,
                calibrator=calibrator,
                calibrated_threshold=cal_threshold,
            )
            self._current_metadata = metadata
            logger.info(
                "model_auto_loaded",
                model_id=metadata.model_id,
                trained_at=metadata.trained_at.isoformat(),
            )
        except ModelNotTrainedError:
            logger.info(
                "no_model_available",
                message="No trained model found. Train first with train_from_features().",
            )
        except SchemaCompatibilityError as exc:
            logger.warning(
                "model_schema_incompatible_skipped",
                error=str(exc),
                message="Latest model skipped due to schema mismatch. Retrain required.",
            )

    def _load_all_feature_records(self) -> list[FeatureRecord]:
        """
        Load all FeatureRecord objects from JSONL files in features_dir.

        Reads every *.jsonl file in the features directory.
        Malformed lines are logged and skipped (never fatal).

        Returns
        -------
        list[FeatureRecord] — may be empty if no files exist.
        """
        records: list[FeatureRecord] = []

        if not self._features_dir.exists():
            logger.warning(
                "features_dir_missing",
                path=str(self._features_dir),
            )
            return records

        jsonl_files = sorted(self._features_dir.glob("*.jsonl"))
        if not jsonl_files:
            logger.warning(
                "no_feature_files_found",
                features_dir=str(self._features_dir),
            )
            return records

        for jsonl_path in jsonl_files:
            file_records = 0
            file_errors = 0
            try:
                with jsonl_path.open("r", encoding="utf-8") as fh:
                    for line_no, line in enumerate(fh, start=1):
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            record = FeatureRecord.model_validate_json(line)
                            records.append(record)
                            file_records += 1
                        except Exception as exc:
                            file_errors += 1
                            logger.debug(
                                "feature_record_parse_error",
                                file=jsonl_path.name,
                                line=line_no,
                                error=str(exc),
                            )
            except OSError as exc:
                logger.warning(
                    "feature_file_unreadable",
                    file=str(jsonl_path),
                    error=str(exc),
                )
                continue

            logger.debug(
                "feature_file_loaded",
                file=jsonl_path.name,
                records=file_records,
                errors=file_errors,
            )

        logger.info(
            "feature_records_loaded",
            total=len(records),
            source_files=len(jsonl_files),
        )
        return records
