"""
backend.detection.models — Detection Data Models
=================================================
Module 2.4 — Behavioral Detection Core

Defines the complete output contract of the Detection Core.
Every downstream module (MITRE, LLM, Response, Dashboard) MUST consume
these models without modification.

Model Hierarchy
---------------
  ModelMetadata      — Versioned record of a trained model artifact
  TrainingResult     — Outcome of one training run
  DetectionAlert     — Single anomalous event with score + feature snapshot
  DetectionResult    — Aggregate result from one scoring pass (batch/streaming)

Design Principles
-----------------
- All models inherit CyberShieldBaseModel for consistent serialisation.
- DetectionAlert preserves raw feature values for future SHAP integration
  without implementing SHAP itself.
- anomaly_score is always in [0.0, 1.0]; higher = more anomalous.
- DetectionAlert.is_alert is True when score >= threshold at scoring time.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import ConfigDict, Field, field_validator, model_validator

from backend.baseline.models import EntityKey
from backend.shared.models import CyberShieldBaseModel
from backend.shared.utils.id_utils import generate_id

# ---------------------------------------------------------------------------
# Schema version sentinel — bump on breaking change
# ---------------------------------------------------------------------------

DETECTION_SCHEMA_VERSION = "1.0.0"


# ---------------------------------------------------------------------------
# ModelMetadata — persisted alongside each trained model artifact
# ---------------------------------------------------------------------------


class ModelMetadata(CyberShieldBaseModel):
    model_config = ConfigDict(
        validate_default=True,
        populate_by_name=True,
        use_enum_values=True,
        ser_json_timedelta="iso8601",
        protected_namespaces=(),
    )
    """
    Versioned metadata for a trained Isolation Forest model artifact.

    Serialised as a companion JSON file alongside the model pickle.
    Used to validate schema compatibility before inference and to provide
    a complete audit trail of when/how each model was trained.

    Fields
    ------
    model_id           : Unique model version identifier (UUID v4 prefixed)
    trained_at         : UTC timestamp of training completion
    schema_version     : Detection schema version
    feature_schema_version : Feature schema version at training time
    feature_names      : Ordered list of feature names (schema snapshot)
    feature_dimension  : Total feature count (must equal len(feature_names))
    n_estimators       : Number of IF trees used
    contamination      : Contamination rate used
    random_state       : Random seed for reproducibility
    entity_dimension   : Entity type trained on (e.g. "user_host")
    entity_count       : Number of distinct entities in training set
    sample_count       : Total training samples
    training_duration_seconds : Wall-clock training time
    scaler_fitted      : True if StandardScaler was fitted and persisted
    model_file         : Filename of the pickle artifact (basename only)
    notes              : Free-form annotation (optional)
    """

    model_id: str = Field(
        default_factory=lambda: f"iforest-{generate_id()}",
        description="Unique model version identifier.",
    )
    trained_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp when training completed.",
    )
    schema_version: str = Field(
        default=DETECTION_SCHEMA_VERSION,
        description="Detection schema version.",
    )
    feature_schema_version: str = Field(
        description="Feature schema version at training time.",
    )
    feature_names: list[str] = Field(
        description="Ordered list of feature names the model was trained on.",
    )
    feature_dimension: int = Field(
        description="Total number of features (must match len(feature_names)).",
        ge=1,
    )
    n_estimators: int = Field(description="Number of isolation trees.", ge=1)
    contamination: float | Literal["auto"] = Field(
        description=(
            "Expected fraction of anomalies in training data. "
            "'auto' uses sklearn's built-in threshold (contamination_=0.5/n_samples). "
            "When float, must satisfy 0.0 <= contamination <= 0.5."
        ),
    )

    @field_validator("contamination", mode="before")
    @classmethod
    def _validate_contamination(cls, v: object) -> object:
        """Accept 'auto' (sklearn literal) or a float in [0.0, 0.5]."""
        if v == "auto":
            return v
        try:
            fv = float(v)  # type: ignore[arg-type]
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"contamination must be 'auto' or a float in [0.0, 0.5], got {v!r}"
            ) from exc
        if not (0.0 <= fv <= 0.5):
            raise ValueError(f"contamination float must be in [0.0, 0.5], got {fv}")
        return fv

    random_state: int = Field(description="Random seed for reproducibility.")
    entity_dimension: str = Field(
        description="Entity type trained on (e.g. 'user_host', 'user', 'host').",
    )
    entity_count: int = Field(
        default=0,
        ge=0,
        description="Number of distinct entities in training set.",
    )
    sample_count: int = Field(
        default=0,
        ge=0,
        description="Total training samples (feature vectors).",
    )
    training_duration_seconds: float = Field(
        default=0.0,
        ge=0.0,
        description="Wall-clock time taken to train.",
    )
    scaler_fitted: bool = Field(
        default=True,
        description="True if a StandardScaler was fitted and stored with the model.",
    )
    model_file: str = Field(
        description="Basename of the model pickle file.",
    )
    notes: str | None = Field(
        default=None,
        description="Optional annotation (e.g. 'initial training', 'retrain after incident').",
    )

    @model_validator(mode="after")
    def _validate_feature_dimension(self) -> ModelMetadata:
        if len(self.feature_names) != self.feature_dimension:
            msg = (
                f"feature_dimension={self.feature_dimension} does not match "
                f"len(feature_names)={len(self.feature_names)}"
            )
            raise ValueError(msg)
        return self


# ---------------------------------------------------------------------------
# TrainingResult — returned by IsolationForestTrainer.train()
# ---------------------------------------------------------------------------


class TrainingResult(CyberShieldBaseModel):
    model_config = ConfigDict(
        validate_default=True,
        populate_by_name=True,
        use_enum_values=True,
        ser_json_timedelta="iso8601",
        protected_namespaces=(),
    )
    """
    Summary of a single training run returned by IsolationForestTrainer.

    Consumers (DetectionService, MetricService) use this to log training
    outcomes and persist model metadata.
    """

    model_id: str = Field(description="Identifier of the trained model.")
    trained_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp when training completed.",
    )
    entity_dimension: str = Field(description="Entity type trained on.")
    entity_count: int = Field(ge=0, description="Distinct entities in training set.")
    sample_count: int = Field(ge=0, description="Total training samples.")
    feature_dimension: int = Field(ge=1, description="Feature vector dimension.")
    contamination: float | Literal["auto"] = Field(
        description=(
            "Contamination rate used during training. "
            "'auto' = sklearn's built-in threshold. Float must be in [0.0, 0.5]."
        ),
    )

    @field_validator("contamination", mode="before")
    @classmethod
    def _validate_contamination(cls, v: object) -> object:
        """Accept 'auto' (sklearn literal) or a float in [0.0, 0.5]."""
        if v == "auto":
            return v
        try:
            fv = float(v)  # type: ignore[arg-type]
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"contamination must be 'auto' or a float in [0.0, 0.5], got {v!r}"
            ) from exc
        if not (0.0 <= fv <= 0.5):
            raise ValueError(f"contamination float must be in [0.0, 0.5], got {fv}")
        return fv

    n_estimators: int = Field(ge=1, description="Number of isolation trees.")
    random_state: int = Field(description="Random seed.")
    training_duration_seconds: float = Field(ge=0.0)
    model_path: str = Field(description="Absolute path to the saved model file.")
    metadata_path: str = Field(description="Absolute path to the metadata JSON file.")

    @property
    def records_per_second(self) -> float:
        """Training throughput."""
        if self.training_duration_seconds <= 0:
            return 0.0
        return self.sample_count / self.training_duration_seconds


# ---------------------------------------------------------------------------
# DetectionAlert — one anomalous event
# ---------------------------------------------------------------------------


class DetectionAlert(CyberShieldBaseModel):
    model_config = ConfigDict(
        validate_default=True,
        populate_by_name=True,
        use_enum_values=True,
        ser_json_timedelta="iso8601",
        protected_namespaces=(),
    )
    """
    A single behavioral anomaly detected by the Isolation Forest scorer.

    Emitted when anomaly_score >= configured threshold.

    Fields
    ------
    alert_id         : Unique alert identifier
    model_id         : Model version that produced this alert
    entity_key       : The entity flagged as anomalous
    event_id         : Originating event_id from the FeatureRecord
    event_type       : Event type from the FeatureRecord
    event_source     : Log source identifier
    event_timestamp  : When the original event occurred (UTC)
    event_host       : Hostname from original event
    event_user       : Username from original event
    anomaly_score    : [0.0, 1.0] — higher = more anomalous
    raw_if_score     : Raw Isolation Forest decision_function value (pre-normalisation)
                       Preserved for future SHAP / explainability integration.
    threshold_used   : Score threshold that was active at alert time
    is_alert         : Always True (alerts are only emitted when threshold exceeded)
    feature_dimension: Number of features in the vector
    raw_feature_values: {feature_name: float} — complete feature snapshot
                        Preserved for future SHAP integration without implementing it.
    novelty_count    : Number of binary 'is_novel' features that fired
    baseline_available: Whether a baseline existed for this entity at feature time
    triggered_at     : UTC timestamp when the alert was generated
    schema_version   : Detection schema version
    """

    alert_id: str = Field(
        default_factory=lambda: f"alert-{generate_id()}",
        description="Unique alert identifier.",
    )
    model_id: str = Field(description="Model version that produced this alert.")

    # Event provenance
    entity_key: EntityKey = Field(description="The entity flagged as anomalous.")
    event_id: str = Field(description="Originating event_id from FeatureRecord.")
    event_type: str = Field(description="Normalised event type.")
    event_source: str = Field(description="Log source identifier.")
    event_timestamp: datetime = Field(description="When the original event occurred (UTC).")
    event_host: str = Field(description="Hostname from original event.")
    event_user: str = Field(description="Username from original event.")

    # Score
    anomaly_score: float = Field(
        ge=0.0,
        le=1.0,
        description="Normalised anomaly score in [0, 1]. Higher = more anomalous.",
    )
    raw_if_score: float = Field(
        description="Raw Isolation Forest decision_function value (negative = anomalous).",
    )
    threshold_used: float = Field(
        ge=0.0,
        le=1.0,
        description="Score threshold that was active at alert time.",
    )
    is_alert: bool = Field(
        default=True,
        description="Always True — DetectionAlert objects are only created above threshold.",
    )

    # Feature snapshot (explainability-ready, no SHAP implemented)
    feature_dimension: int = Field(ge=1, description="Number of features in the vector.")
    raw_feature_values: dict[str, float] = Field(
        default_factory=dict,
        description=(
            "Complete feature snapshot at alert time. "
            "Preserved for future SHAP integration — not used by this module."
        ),
    )
    novelty_count: int = Field(
        default=0,
        ge=0,
        description="Number of binary is_novel features that fired.",
    )
    baseline_available: bool = Field(
        description="Whether a baseline existed for this entity at feature extraction time.",
    )

    # Lifecycle
    triggered_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp when the alert was generated.",
    )
    schema_version: str = Field(
        default=DETECTION_SCHEMA_VERSION,
        description="Detection schema version.",
    )

    @field_validator("anomaly_score")
    @classmethod
    def _validate_score(cls, v: float) -> float:
        import math

        if not math.isfinite(v):
            return 0.0
        return round(float(v), 6)

    def to_summary(self) -> dict[str, Any]:
        """
        Return a compact, human-readable summary dict.
        Suitable for logging, API responses, and MetricService integration.
        """
        return {
            "alert_id": self.alert_id,
            "model_id": self.model_id,
            "entity_type": self.entity_key.entity_type,
            "entity_id": self.entity_key.entity_id,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "event_source": self.event_source,
            "event_timestamp": self.event_timestamp.isoformat(),
            "anomaly_score": self.anomaly_score,
            "threshold_used": self.threshold_used,
            "novelty_count": self.novelty_count,
            "baseline_available": self.baseline_available,
            "triggered_at": self.triggered_at.isoformat(),
        }


# ---------------------------------------------------------------------------
# DetectionResult — aggregate result from one scoring pass
# ---------------------------------------------------------------------------


class DetectionResult(CyberShieldBaseModel):
    model_config = ConfigDict(
        validate_default=True,
        populate_by_name=True,
        use_enum_values=True,
        ser_json_timedelta="iso8601",
        protected_namespaces=(),
    )
    """
    Aggregate outcome of one complete scoring pass (batch or streaming).

    Returned by DetectionService.score_batch() and score_stream().
    Consumed by MetricService (DETECTION domain) and API endpoints.

    Fields
    ------
    run_id            : Unique identifier for this scoring run
    model_id          : Model version used
    started_at        : UTC start of scoring
    completed_at      : UTC completion (None if not yet finished)
    records_scored    : Total FeatureRecord objects processed
    alerts_generated  : Total DetectionAlert objects emitted
    score_threshold   : Threshold used during this run
    entity_dimension  : Entity dimension scored
    alerts            : List of generated DetectionAlert objects
    errors            : Count of records that failed scoring
    schema_version    : Detection schema version
    """

    run_id: str = Field(
        default_factory=generate_id,
        description="UUID identifying this scoring run.",
    )
    model_id: str = Field(description="Model version used for scoring.")
    started_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC start of the scoring run.",
    )
    completed_at: datetime | None = Field(
        default=None,
        description="UTC completion time. None while running.",
    )
    records_scored: int = Field(default=0, ge=0)
    alerts_generated: int = Field(default=0, ge=0)
    score_threshold: float = Field(ge=0.0, le=1.0)
    entity_dimension: str = Field(description="Entity dimension that was scored.")
    alerts: list[DetectionAlert] = Field(
        default_factory=list,
        description="All DetectionAlert objects generated during this run.",
    )
    errors: int = Field(
        default=0,
        ge=0,
        description="Count of records that failed scoring (logged separately).",
    )
    schema_version: str = Field(default=DETECTION_SCHEMA_VERSION)

    @property
    def duration_seconds(self) -> float | None:
        """Wall-clock duration. None if run has not completed."""
        if self.completed_at is None:
            return None
        return (self.completed_at - self.started_at).total_seconds()

    @property
    def alert_rate(self) -> float:
        """Fraction of scored records that generated alerts."""
        if self.records_scored == 0:
            return 0.0
        return self.alerts_generated / self.records_scored

    @property
    def records_per_second(self) -> float | None:
        """Scoring throughput. None if not complete."""
        dur = self.duration_seconds
        if dur is None or dur <= 0:
            return None
        return self.records_scored / dur

    def to_summary(self) -> dict[str, Any]:
        """Compact summary for logging and MetricService consumption."""
        return {
            "run_id": self.run_id,
            "model_id": self.model_id,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "records_scored": self.records_scored,
            "alerts_generated": self.alerts_generated,
            "alert_rate": round(self.alert_rate, 4),
            "score_threshold": self.score_threshold,
            "entity_dimension": self.entity_dimension,
            "errors": self.errors,
            "duration_seconds": self.duration_seconds,
        }
