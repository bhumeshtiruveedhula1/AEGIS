"""
backend.features.models — Feature Vector Data Models
====================================================
Module 2.2 — Behavioral Feature Engine

This module defines the output contract of the Feature Engine.
Every downstream ML component MUST consume these models.

Model Hierarchy
---------------
  FeatureSchema           — Ordered registry of all declared features
  FeatureGroup            — A named group of related features
  FeatureVector           — Complete feature set for one event/entity pair
  FeatureRecord           — Serialisable output record (event + vector)
  FeaturePipelineReport   — Summary of one feature extraction run

Schema Contract
---------------
- All feature values are float.
- Missing / inapplicable features default to 0.0 (never NaN).
- Binary features are exactly {0.0, 1.0}.
- Feature order within a FeatureVector is guaranteed stable.
- FEATURE_SCHEMA_VERSION is bumped on every breaking schema change.

Downstream Consumption
----------------------
The Behavioral Detection Core (Module 2.3) reads FeatureRecord objects
from the JSONL output of the FeatureVectorWriter.
"""

from __future__ import annotations

import math
from datetime import UTC, datetime
from typing import Any

from pydantic import Field, field_validator, model_validator

from backend.baseline.models import EntityKey
from backend.shared.models import CyberShieldBaseModel
from backend.shared.utils.id_utils import generate_id

# ---------------------------------------------------------------------------
# Schema version sentinel
# ---------------------------------------------------------------------------

FEATURE_SCHEMA_VERSION = "1.0.0"


# ---------------------------------------------------------------------------
# Feature group definitions — ordered catalogue of all produced features
# ---------------------------------------------------------------------------

FEATURE_GROUPS: dict[str, list[str]] = {
    "temporal": [
        "hour_of_day",
        "day_of_week",
        "is_business_hours",
        "hour_baseline_frequency",
        "hour_relative_frequency",
        "day_baseline_frequency",
        "is_peak_hour",
        "time_since_last_seen_hours",
    ],
    "frequency": [
        "event_type_frequency",
        "event_type_frequency_rank",
        "action_frequency",
        "result_failure_rate_baseline",
        "result_is_failure",
        "source_frequency",
        "entity_observation_count",
        "baseline_window_days",
        "auth_unexpected_failure",  # composite: result_is_failure × (1 - result_failure_rate_baseline)
    ],
    "network": [
        "dst_ip_is_novel",
        "src_ip_is_novel",
        "port_is_novel",
        "protocol_is_novel",
        "port_baseline_frequency",
        "protocol_baseline_frequency",
        "bytes_out_z_score",
        "bytes_out_percentile_rank",
        "unique_dst_ips_baseline",
        "connection_count_baseline",
    ],
    "process": [
        "process_is_novel",
        "parent_process_is_novel",
        "parent_child_pair_is_novel",
        "process_frequency_rank",
        "unique_processes_baseline",
        "process_event_count_baseline",
        "pid_z_score",
        "has_command_line",
    ],
    "auth": [
        "logon_type_is_novel",
        "auth_package_is_novel",
        "logon_type_baseline_frequency",
        "auth_package_baseline_frequency",
        "auth_failure_rate_baseline",
        "auth_event_count_baseline",
        "windows_event_id_is_novel",
    ],
    "ot": [
        "modbus_register_z_score",
        "modbus_value_z_score",
        "modbus_register_is_in_range",
        "modbus_value_is_in_range",
        "modbus_function_code_is_novel",
        "supervisory_host_is_novel",
        "modbus_event_count_baseline",
    ],
    "baseline_presence": [
        "has_user_baseline",
        "has_host_baseline",
        "has_source_baseline",
        "has_user_host_baseline",
    ],
    "entity_activity": [
        "entity_unique_dst_ips",
        "entity_unique_processes",
        "entity_auth_failure_count",
        "entity_modbus_event_count",
    ],
}

# Flat ordered list — the canonical feature order for all downstream consumers
ALL_FEATURE_NAMES: list[str] = [name for group in FEATURE_GROUPS.values() for name in group]

# Fast lookup set
_ALL_FEATURE_SET: frozenset[str] = frozenset(ALL_FEATURE_NAMES)

# Total feature count — must equal len(ALL_FEATURE_NAMES)
FEATURE_DIMENSION = len(ALL_FEATURE_NAMES)


# ---------------------------------------------------------------------------
# FeatureSchema — ordered registry of all declared features
# ---------------------------------------------------------------------------


class FeatureSchema(CyberShieldBaseModel):
    """
    Metadata about the feature schema produced by this module version.

    Serialised alongside each FeaturePipelineReport so that downstream
    consumers can verify schema compatibility before loading vectors.
    """

    schema_version: str = Field(
        default=FEATURE_SCHEMA_VERSION,
        description="Feature schema version string.",
    )
    feature_dimension: int = Field(
        default=FEATURE_DIMENSION,
        description="Total number of features in each vector.",
    )
    feature_groups: dict[str, list[str]] = Field(
        default_factory=lambda: dict(FEATURE_GROUPS),
        description="Mapping of group name → ordered list of feature names.",
    )
    all_feature_names: list[str] = Field(
        default_factory=lambda: list(ALL_FEATURE_NAMES),
        description="Canonical ordered list of all feature names.",
    )

    def index_of(self, feature_name: str) -> int:
        """Return the positional index of a feature name. Raises KeyError if absent."""
        try:
            return self.all_feature_names.index(feature_name)
        except ValueError:
            msg = f"Feature {feature_name!r} is not in the schema."
            raise KeyError(msg) from None

    def group_of(self, feature_name: str) -> str | None:
        """Return the group name for a given feature, or None if not found."""
        for group, names in self.feature_groups.items():
            if feature_name in names:
                return group
        return None


# ---------------------------------------------------------------------------
# FeatureVector — the output of one feature extraction pass
# ---------------------------------------------------------------------------


class FeatureVector(CyberShieldBaseModel):
    """
    Complete behavioral feature vector for one event × entity pair.

    All values are float in [0, ∞) or binary {0.0, 1.0}.
    Missing / inapplicable features are 0.0, never NaN.

    Usage
    -----
    >>> vec = FeatureVector(entity_key=key, values={"hour_of_day": 9.0, ...})
    >>> arr = vec.to_array()  # numpy-compatible list of floats in canonical order
    >>> vec.group("temporal")  # dict of just temporal features
    """

    entity_key: EntityKey = Field(
        description="The entity this feature vector describes.",
    )
    schema_version: str = Field(
        default=FEATURE_SCHEMA_VERSION,
        description="Feature schema version these values conform to.",
    )
    values: dict[str, float] = Field(
        default_factory=dict,
        description="Feature name → float value mapping.",
    )
    extraction_warnings: list[str] = Field(
        default_factory=list,
        description="Non-fatal issues during feature extraction.",
    )
    extracted_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp of feature extraction.",
    )

    @field_validator("values", mode="after")
    @classmethod
    def _validate_values(cls, v: dict[str, float]) -> dict[str, float]:
        """Replace any NaN/Inf with 0.0 to guarantee downstream safety."""
        cleaned: dict[str, float] = {}
        for name, val in v.items():
            if not math.isfinite(val):
                cleaned[name] = 0.0
            else:
                cleaned[name] = float(val)
        return cleaned

    @model_validator(mode="after")
    def _fill_missing_features(self) -> FeatureVector:
        """
        Ensure every declared feature has a value.
        Features absent from `values` are set to 0.0.
        """
        for feature_name in ALL_FEATURE_NAMES:
            if feature_name not in self.values:
                self.values[feature_name] = 0.0
        return self

    def to_array(self) -> list[float]:
        """
        Return feature values as an ordered list in canonical schema order.
        This is the format expected by numpy / scikit-learn / torch.
        """
        return [self.values.get(name, 0.0) for name in ALL_FEATURE_NAMES]

    def group(self, group_name: str) -> dict[str, float]:
        """
        Return only the features belonging to a named group.

        Parameters
        ----------
        group_name : str
            One of the keys in FEATURE_GROUPS.

        Returns
        -------
        dict[str, float] — feature name → value for this group only.

        Raises
        ------
        KeyError if group_name is not a valid group.
        """
        if group_name not in FEATURE_GROUPS:
            msg = f"Unknown feature group {group_name!r}. Valid: {sorted(FEATURE_GROUPS)}"
            raise KeyError(msg)
        return {name: self.values.get(name, 0.0) for name in FEATURE_GROUPS[group_name]}

    def get(self, feature_name: str, default: float = 0.0) -> float:
        """Safe accessor — returns default if feature is missing."""
        return self.values.get(feature_name, default)

    def is_valid(self) -> bool:
        """
        Return True if all feature values are finite floats.
        A valid vector has no NaN, no Inf.
        """
        return all(math.isfinite(v) for v in self.values.values())

    def novelty_flags(self) -> dict[str, float]:
        """Return all binary features whose name ends with '_is_novel'."""
        return {k: v for k, v in self.values.items() if k.endswith("_is_novel")}

    def novelty_count(self) -> int:
        """Return count of binary 'is_novel' features that fired (value == 1.0)."""
        return sum(1 for v in self.novelty_flags().values() if v == 1.0)

    def __repr__(self) -> str:
        return (
            f"FeatureVector("
            f"entity={self.entity_key.entity_type}:{self.entity_key.entity_id}, "
            f"dim={len(self.values)}, "
            f"novelty={self.novelty_count()})"
        )


# ---------------------------------------------------------------------------
# FeatureRecord — one serialisable output record written to JSONL
# ---------------------------------------------------------------------------


class FeatureRecord(CyberShieldBaseModel):
    """
    Complete output record joining event metadata with its feature vector.

    This is the atomic unit written to the feature JSONL output file
    and consumed by the Behavioral Detection Core.

    Every FeatureRecord is uniquely keyed by (event_id, entity_key).
    Multiple records may exist for one event_id if multiple entity
    dimensions are enabled (user, host, source, user_host).
    """

    record_id: str = Field(
        default_factory=generate_id,
        description="Unique ID for this feature record.",
    )

    # Event provenance
    event_id: str = Field(description="event_id from the originating CanonicalEvent.")
    event_type: str = Field(description="Normalised event type.")
    event_source: str = Field(description="Log source identifier.")
    event_timestamp: datetime = Field(description="UTC timestamp of the original event.")
    event_host: str = Field(description="Hostname from the original event.")
    event_user: str = Field(description="Username from the original event.")

    # Entity dimension context
    entity_key: EntityKey = Field(
        description="The entity dimension this feature vector was computed for.",
    )
    baseline_available: bool = Field(
        description="True if a baseline was available for this entity during extraction.",
    )

    # The feature vector itself
    feature_vector: FeatureVector = Field(
        description="The complete behavioral feature vector.",
    )

    # Metadata
    schema_version: str = Field(
        default=FEATURE_SCHEMA_VERSION,
        description="Feature schema version.",
    )
    extracted_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
    )

    def to_flat_dict(self) -> dict[str, Any]:
        """
        Return a flat dict merging record metadata with feature values.
        Useful for tabular analysis (pandas DataFrame construction).
        """
        return {
            "record_id": self.record_id,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "event_source": self.event_source,
            "event_timestamp": self.event_timestamp.isoformat(),
            "event_host": self.event_host,
            "event_user": self.event_user,
            "entity_type": self.entity_key.entity_type,
            "entity_id": self.entity_key.entity_id,
            "baseline_available": self.baseline_available,
            "schema_version": self.schema_version,
            **{f"feat_{k}": v for k, v in self.feature_vector.values.items()},
        }


# ---------------------------------------------------------------------------
# FeaturePipelineReport — summary of one feature extraction run
# ---------------------------------------------------------------------------


class FeaturePipelineReport(CyberShieldBaseModel):
    """
    Statistics from one complete feature extraction pipeline run.

    Emitted at the end of each run. Consumed by monitoring and the API.
    """

    run_id: str = Field(
        default_factory=generate_id,
        description="UUID v4 identifying this feature extraction run.",
    )
    started_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
    )
    completed_at: datetime | None = Field(default=None)

    # Input statistics
    events_read: int = Field(default=0, ge=0)
    events_skipped: int = Field(default=0, ge=0)

    # Output statistics
    feature_records_written: int = Field(default=0, ge=0)
    entities_extracted: int = Field(default=0, ge=0)

    # Baseline statistics
    baseline_available: bool = Field(
        default=False,
        description="Whether a baseline was loaded during this run.",
    )
    baseline_profile_id: str | None = Field(default=None)

    # Quality statistics
    extraction_errors: int = Field(default=0, ge=0)
    extraction_warnings: int = Field(default=0, ge=0)

    # Schema
    feature_schema_version: str = Field(default=FEATURE_SCHEMA_VERSION)
    feature_dimension: int = Field(default=FEATURE_DIMENSION)

    # I/O
    output_file: str | None = Field(default=None)

    @property
    def duration_seconds(self) -> float | None:
        """Wall-clock duration. None if run has not completed."""
        if self.completed_at is None:
            return None
        return (self.completed_at - self.started_at).total_seconds()

    @property
    def cold_start(self) -> bool:
        """True if no baseline was available during this run."""
        return not self.baseline_available

    @property
    def records_per_second(self) -> float | None:
        """Throughput in records/second. None if not yet complete."""
        dur = self.duration_seconds
        if dur is None or dur == 0:
            return None
        return self.feature_records_written / dur
