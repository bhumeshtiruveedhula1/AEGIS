"""
backend.detection.scorer — Anomaly Scorer
==========================================
Module 2.4 — Behavioral Detection Core

Converts raw Isolation Forest decision_function values into normalised
anomaly scores and produces structured DetectionAlert / DetectionResult
objects.

Score Normalisation
-------------------
IsolationForest.decision_function() returns:
  - Negative values  → anomalous  (further from 0 = more anomalous)
  - Positive values  → normal

We map to [0, 1] using a sigmoid inversion:

    score = 1 / (1 + exp(decision_function_value))

Properties:
  - decision_function = 0  →  score ≈ 0.5   (boundary)
  - decision_function = -∞ →  score → 1.0   (maximally anomalous)
  - decision_function = +∞ →  score → 0.0   (maximally normal)

This gives a smooth, monotonic, bounded score that:
  1. Is human-readable (higher = worse).
  2. Is compatible with future calibration (Platt scaling).
  3. Does not require knowing the min/max of the decision_function range.

Inference Modes
---------------
1. score_single(record)     → DetectionAlert | None   (for streaming)
2. score_batch(records)     → DetectionResult          (for offline jobs)
3. score_stream(iterable)   → Iterator[DetectionAlert] (for live pipelines)

Thread Safety
-------------
AnomalyScorer holds no mutable state after construction.
Multiple threads may call score_single/batch/stream concurrently.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime

import numpy as np
import structlog

from backend.core.config import get_settings
from backend.detection.models import (
    DetectionAlert,
    DetectionResult,
    ModelMetadata,
)
from backend.features.models import FeatureRecord

logger = structlog.get_logger(__name__)


def _linear_anomaly_score(raw_if_score: float) -> float:
    """
    Map an IsolationForest decision_function value to [0, 1].

    IsolationForest.decision_function() returns values roughly in [-0.5, +0.5]:
      - Negative  -> anomalous (further from 0 = more anomalous)
      - Positive  -> normal
      - 0         -> decision boundary

    The previous sigmoid transform compressed all values near 0.5 because
    real IF outputs are small (e.g. [-0.05, +0.05]) and sigmoid(x) ~= 0.5
    for any x near 0. Diagnostic confirmed brute-force attacks scored
    identically to normal traffic (0.4992 vs 0.4897).

    Linear rescale:
      score = 1.0 - (clamp(x, -0.5, 0.5) + 0.5)

    Properties:
      - x = -0.5 (maximally anomalous) -> score = 1.0
      - x =  0.0 (boundary)            -> score = 0.5
      - x = +0.5 (maximally normal)    -> score = 0.0
      - Monotonic, bounded, no squashing.

    Returns 0.0 for non-finite inputs (safety net).
    """
    if not math.isfinite(raw_if_score):
        return 0.0
    clamped = max(-0.5, min(0.5, raw_if_score))
    return round(1.0 - (clamped + 0.5), 6)


class AnomalyScorer:
    """
    Converts raw Isolation Forest outputs into structured detection results.

    Parameters
    ----------
    pipeline  : Fitted _DetectionPipeline (from IsolationForestTrainer.train()).
    metadata  : ModelMetadata for the loaded model.
    threshold : Override the anomaly score threshold from settings.
                Defaults to settings.anomaly_score_threshold.

    Usage
    -----
        scorer = AnomalyScorer(pipeline, metadata)
        alert = scorer.score_single(feature_record)
        if alert:
            print(alert.anomaly_score, alert.alert_id)

        result = scorer.score_batch(list_of_records)
        print(result.alerts_generated, result.alert_rate)
    """

    def __init__(
        self,
        pipeline: object,  # _DetectionPipeline — avoid circular import
        metadata: ModelMetadata,
        *,
        threshold: float | None = None,
    ) -> None:
        self._pipeline = pipeline
        self._metadata = metadata
        settings = get_settings()
        self._threshold = threshold if threshold is not None else settings.anomaly_score_threshold

        logger.debug(
            "scorer_initialised",
            model_id=metadata.model_id,
            threshold=self._threshold,
            entity_dimension=metadata.entity_dimension,
        )

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def model_id(self) -> str:
        return self._metadata.model_id

    @property
    def threshold(self) -> float:
        return self._threshold

    @property
    def entity_dimension(self) -> str:
        return self._metadata.entity_dimension

    # ── Single-record scoring ─────────────────────────────────────────────────

    def score_single(
        self,
        record: FeatureRecord,
    ) -> DetectionAlert | None:
        """
        Score one FeatureRecord and return a DetectionAlert if anomalous.

        Parameters
        ----------
        record : A FeatureRecord from the Feature Engine.
                 Entity dimension filtering is the caller's responsibility.

        Returns
        -------
        DetectionAlert — if anomaly_score >= threshold.
        None           — if score is below threshold (normal behaviour).

        Raises
        ------
        SchemaCompatibilityError if feature dimension mismatches.
        """
        # NEG-05 guard: reject all-zero feature vectors — they carry no
        # behavioral signal and will score near 0.5 regardless of the model,
        # producing spurious non-alerts and masking real empty-baseline issues.
        feature_array = record.feature_vector.to_array()
        if all(v == 0.0 for v in feature_array):
            logger.warning(
                "empty_feature_vector_skipped",
                entity_type=record.entity_key.entity_type,
                entity_id=record.entity_key.entity_id,
                baseline_available=record.baseline_available,
            )
            return None

        X = self._pipeline.preprocessor.transform_single(record)
        raw_score = float(self._pipeline.isolation_forest.decision_function(X)[0])
        anomaly_score = _linear_anomaly_score(raw_score)

        if anomaly_score < self._threshold:
            return None

        alert = self._build_alert(record, raw_score, anomaly_score)
        logger.info(
            "anomaly_detected",
            alert_id=alert.alert_id,
            entity_type=alert.entity_key.entity_type,
            entity_id=alert.entity_key.entity_id,
            anomaly_score=alert.anomaly_score,
            threshold=self._threshold,
            novelty_count=alert.novelty_count,
        )
        return alert

    # ── Batch scoring ─────────────────────────────────────────────────────────

    def score_batch(
        self,
        records: list[FeatureRecord],
        *,
        entity_dim: str | None = None,
    ) -> DetectionResult:
        """
        Score all matching FeatureRecord objects in one vectorised pass.

        Parameters
        ----------
        records    : All FeatureRecord objects to consider.
        entity_dim : Filter by this dimension before scoring.
                     Defaults to the trained model's entity_dimension.

        Returns
        -------
        DetectionResult with all alerts populated.
        """
        target_dim = entity_dim or self._metadata.entity_dimension
        started_at = datetime.now(UTC)
        run_id_val = _make_run_id()

        # Filter to target dimension and skip all-zero feature vectors (NEG-05)
        to_score = [
            r for r in records
            if r.entity_key.entity_type == target_dim
            and not all(v == 0.0 for v in r.feature_vector.to_array())
        ]
        empty_skipped = sum(
            1 for r in records
            if r.entity_key.entity_type == target_dim
            and all(v == 0.0 for v in r.feature_vector.to_array())
        )
        if empty_skipped:
            logger.warning("batch_empty_vectors_skipped", count=empty_skipped, entity_dim=target_dim)

        result = DetectionResult(
            run_id=run_id_val,
            model_id=self._metadata.model_id,
            started_at=started_at,
            score_threshold=self._threshold,
            entity_dimension=target_dim,
        )

        if not to_score:
            logger.warning(
                "batch_score_no_records",
                entity_dim=target_dim,
                total_input=len(records),
            )
            completed = result.model_copy(
                update={
                    "completed_at": datetime.now(UTC),
                    "records_scored": 0,
                }
            )
            return completed

        # Vectorised transform
        try:
            X = self._pipeline.preprocessor.transform(to_score)
        except Exception as exc:
            logger.error("batch_transform_failed", error=str(exc))
            completed = result.model_copy(
                update={
                    "completed_at": datetime.now(UTC),
                    "records_scored": len(to_score),
                    "errors": len(to_score),
                }
            )
            return completed

        # Vectorised decision_function — single sklearn call for efficiency
        raw_scores: np.ndarray = self._pipeline.isolation_forest.decision_function(X)

        alerts: list[DetectionAlert] = []
        errors = 0

        for i, record in enumerate(to_score):
            try:
                raw_score = float(raw_scores[i])
                anomaly_score = _linear_anomaly_score(raw_score)
                if anomaly_score >= self._threshold:
                    alert = self._build_alert(record, raw_score, anomaly_score)
                    alerts.append(alert)
            except Exception as exc:
                errors += 1
                logger.warning(
                    "record_score_error",
                    record_id=record.record_id,
                    error=str(exc),
                )

        completed_at = datetime.now(UTC)
        completed = result.model_copy(
            update={
                "completed_at": completed_at,
                "records_scored": len(to_score),
                "alerts_generated": len(alerts),
                "alerts": alerts,
                "errors": errors,
            }
        )

        logger.info(
            "batch_scoring_complete",
            run_id=run_id_val,
            records_scored=len(to_score),
            alerts_generated=len(alerts),
            alert_rate=round(completed.alert_rate, 4),
            errors=errors,
            duration_s=round(completed.duration_seconds or 0.0, 4),
        )
        return completed

    # ── Streaming scoring ─────────────────────────────────────────────────────

    def score_stream(
        self,
        records: Iterable[FeatureRecord],
        *,
        entity_dim: str | None = None,
    ) -> Iterator[DetectionAlert]:
        """
        Generator for streaming inference over an iterable of FeatureRecords.

        Yields a DetectionAlert for each record whose anomaly_score >= threshold.
        Records below threshold are silently consumed.

        Parameters
        ----------
        records    : Any iterable of FeatureRecord (file reader, queue, etc.).
        entity_dim : Only score records matching this dimension.
                     Defaults to the trained model's entity_dimension.

        Yields
        ------
        DetectionAlert — one per anomalous record, in order.

        Usage
        -----
            for alert in scorer.score_stream(reader.stream_records()):
                pipeline_sink.publish(alert)
        """
        target_dim = entity_dim or self._metadata.entity_dimension
        emitted = 0
        consumed = 0

        for record in records:
            consumed += 1
            if record.entity_key.entity_type != target_dim:
                continue
            try:
                alert = self.score_single(record)
                if alert is not None:
                    emitted += 1
                    yield alert
            except Exception as exc:
                logger.warning(
                    "stream_record_error",
                    record_id=record.record_id,
                    error=str(exc),
                )

        logger.info(
            "stream_scoring_complete",
            consumed=consumed,
            alerts_emitted=emitted,
            entity_dim=target_dim,
        )

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _build_alert(
        self,
        record: FeatureRecord,
        raw_if_score: float,
        anomaly_score: float,
    ) -> DetectionAlert:
        """Construct a DetectionAlert from a scored FeatureRecord."""
        return DetectionAlert(
            model_id=self._metadata.model_id,
            entity_key=record.entity_key,
            event_id=record.event_id,
            event_type=record.event_type,
            event_source=record.event_source,
            event_timestamp=record.event_timestamp,
            event_host=record.event_host,
            event_user=record.event_user,
            anomaly_score=anomaly_score,
            raw_if_score=raw_if_score,
            threshold_used=self._threshold,
            feature_dimension=len(record.feature_vector.values),
            raw_feature_values=dict(record.feature_vector.values),
            novelty_count=record.feature_vector.novelty_count(),
            baseline_available=record.baseline_available,
        )


def _make_run_id() -> str:
    """Generate a short scoring run identifier."""
    from backend.shared.utils.id_utils import generate_id

    return f"score-{generate_id()}"
