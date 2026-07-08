"""
backend.baseline.models — Baseline Data Models
===============================================
Module 2.1 — Baseline Generator

All Pydantic models representing behavioral baseline data.
These are the single source of truth for what a "baseline" is across
the entire platform.

Model Hierarchy
---------------
  EntityKey           — identifies one behavioral entity
  NumericStats        — descriptive statistics for a numeric field
  CategoricalStats    — frequency distribution for a categorical field
  TimePattern         — hourly + daily activity distribution
  NetworkBaseline     — aggregated network behavior per entity
  ProcessBaseline     — aggregated process behavior (hospital/DC)
  ModbusBaseline      — OT register/value range baseline
  AuthBaseline        — authentication behavior baseline (DC)
  EntityBaseline      — complete behavioral profile for ONE entity
  BaselineProfile     — full collection: all entity baselines + metadata
  BaselineManifest    — index of all stored profiles (fast lookup)
  BaselineBuildReport — statistics from one baseline build run

Schema Version
--------------
BASELINE_SCHEMA_VERSION = "1.0.0"
Bump on breaking changes (removing fields, changing types).
Non-breaking additions (new Optional fields) do not require a bump.

Consumption Contract
--------------------
The Feature Engine (Module 2.2) MUST:
  1. Check baseline_version before consuming any EntityBaseline.
  2. Treat all Optional fields as "not available for this entity type".
  3. Never modify baseline models — they are read-only downstream.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog
from pydantic import Field, field_validator

from backend.shared.models import CyberShieldBaseModel

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Schema version sentinel
# ---------------------------------------------------------------------------

BASELINE_SCHEMA_VERSION = "1.0.0"

# Entity dimensions supported by this module
ENTITY_TYPES = frozenset({"user", "host", "source", "user_host"})


# ---------------------------------------------------------------------------
# EntityKey — the fundamental grouping identifier
# ---------------------------------------------------------------------------

class EntityKey(CyberShieldBaseModel):
    """
    Uniquely identifies one behavioral entity in the baseline system.

    Entity Types
    ------------
    user       — a service account or user (e.g., "svc-iis", "SCADA")
    host       — a machine (e.g., "hospital-server-01", "ot-node-01")
    source     — a telemetry source (e.g., "hospital_server", "ot_node")
    user_host  — user on a specific host ("svc-iis::hospital-server-01")

    The `entity_id` is always lowercase and stripped of whitespace.

    Usage
    -----
    >>> key = EntityKey(entity_type="user", entity_id="svc-iis")
    >>> key.storage_key  # "user__svc-iis"
    """

    entity_type: str = Field(
        description="Dimension of this entity: user | host | source | user_host.",
    )
    entity_id: str = Field(
        description="Canonical identifier for this entity (lowercased).",
    )

    @field_validator("entity_type")
    @classmethod
    def validate_entity_type(cls, v: str) -> str:
        v = v.lower().strip()
        if v not in ENTITY_TYPES:
            msg = f"entity_type must be one of {sorted(ENTITY_TYPES)}, got: {v!r}"
            raise ValueError(msg)
        return v

    @field_validator("entity_id")
    @classmethod
    def normalise_entity_id(cls, v: str) -> str:
        v = v.lower().strip()
        if not v:
            msg = "entity_id must not be empty."
            raise ValueError(msg)
        return v

    @property
    def storage_key(self) -> str:
        """Filesystem-safe key: '<type>__<id>' (double underscore separator)."""
        safe_id = self.entity_id.replace("/", "_").replace("\\", "_")
        return f"{self.entity_type}__{safe_id}"

    def __hash__(self) -> int:
        return hash((self.entity_type, self.entity_id))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, EntityKey):
            return NotImplemented
        return self.entity_type == other.entity_type and self.entity_id == other.entity_id

    def __repr__(self) -> str:
        return f"EntityKey({self.entity_type!r}, {self.entity_id!r})"


# ---------------------------------------------------------------------------
# NumericStats — descriptive statistics for a numeric field
# ---------------------------------------------------------------------------

class NumericStats(CyberShieldBaseModel):
    """
    Descriptive statistics for a single numeric field across observations.

    Computed using Welford's online algorithm for mean and variance,
    enabling incremental updates without re-reading all observations.

    The Feature Engine uses these to assess how far a new value deviates
    from the established baseline (z-score, percentile lookup).

    Fields with zero observations have count=0 and all other fields None.
    """

    field_name: str = Field(description="Name of the CanonicalEvent field.")
    count: int = Field(default=0, ge=0, description="Number of non-None observations.")

    # Descriptive stats — None when count == 0
    mean: float | None = Field(default=None, description="Arithmetic mean.")
    std: float | None = Field(default=None, description="Sample standard deviation.")
    minimum: float | None = Field(default=None, description="Observed minimum value.")
    maximum: float | None = Field(default=None, description="Observed maximum value.")
    p25: float | None = Field(default=None, description="25th percentile.")
    p50: float | None = Field(default=None, description="Median (50th percentile).")
    p75: float | None = Field(default=None, description="75th percentile.")
    p95: float | None = Field(default=None, description="95th percentile.")
    p99: float | None = Field(default=None, description="99th percentile.")

    # Welford state — used by BaselineUpdater for incremental updates.
    # This is a proper Pydantic field so it survives JSON round-trips.
    # Without this, incremental std becomes wrong after every save/load cycle.
    welford_m2: float = Field(
        default=0.0,
        description=(
            "Welford running sum of squared deviations (M2). "
            "Used by BaselineUpdater to compute correct incremental std. "
            "Preserved across save/load cycles."
        ),
    )

    # Percentile staleness flag — set to True by BaselineUpdater after
    # an incremental update, since exact percentiles require all observations.
    percentiles_approximate: bool = Field(
        default=False,
        description=(
            "True after an incremental update — percentiles (p25..p99) are "
            "approximations kept from the last full build. "
            "Trigger a full rebuild to restore exact percentiles."
        ),
    )

    @property
    def is_populated(self) -> bool:
        """True if at least one observation was recorded."""
        return self.count > 0


# ---------------------------------------------------------------------------
# CategoricalStats — frequency distribution for categorical fields
# ---------------------------------------------------------------------------

class CategoricalStats(CyberShieldBaseModel):
    """
    Frequency distribution for a categorical (string-valued) field.

    Only the top `max_values` most frequent values are retained.
    High-cardinality fields (command_line, file_path) may produce many
    unique values; keeping only top-N prevents unbounded memory growth.

    The Feature Engine uses `value_frequencies` to detect:
    - Values never seen in baseline (new process, new IP)
    - Shifts in the most common values

    The `seen_values` set is stored for exact membership queries.
    For large cardinality (> max_values unique), use `total_unique_values`
    instead of `seen_values` length.
    """

    field_name: str = Field(description="Name of the CanonicalEvent field.")
    count: int = Field(default=0, ge=0, description="Total non-None observations.")
    total_unique_values: int = Field(
        default=0, ge=0,
        description="Total unique values observed (may exceed max_values).",
    )
    value_frequencies: dict[str, int] = Field(
        default_factory=dict,
        description="Top-N value → observation count mapping.",
    )
    seen_values: set[str] = Field(
        default_factory=set,
        description="Complete set of unique values observed (capped at max_values).",
    )
    max_values: int = Field(
        default=100, ge=1,
        description="Maximum unique values to store in seen_values.",
    )

    @property
    def is_populated(self) -> bool:
        """True if at least one observation was recorded."""
        return self.count > 0

    def top_values(self, n: int = 10) -> list[tuple[str, int]]:
        """Return the n most frequent values as (value, count) tuples."""
        return sorted(
            self.value_frequencies.items(),
            key=lambda x: x[1],
            reverse=True,
        )[:n]


# ---------------------------------------------------------------------------
# TimePattern — activity distribution over time
# ---------------------------------------------------------------------------

class TimePattern(CyberShieldBaseModel):
    """
    Temporal activity distribution for an entity.

    Captures WHEN this entity is normally active, enabling the Feature
    Engine to flag activity at unusual times (e.g., 3 AM activity from
    a service account that normally runs 9–5).

    hourly_buckets:  24-element list — index = hour (0–23 UTC)
    daily_buckets:   7-element list  — index = weekday (0=Mon, 6=Sun)
    Each bucket holds the count of events in that time slot.
    """

    hourly_buckets: list[int] = Field(
        default_factory=lambda: [0] * 24,
        description="24-bucket hourly activity count (index = UTC hour 0–23).",
    )
    daily_buckets: list[int] = Field(
        default_factory=lambda: [0] * 7,
        description="7-bucket daily activity count (index = weekday, 0=Monday).",
    )
    total_events: int = Field(
        default=0, ge=0,
        description="Total events contributing to this time pattern.",
    )

    @field_validator("hourly_buckets")
    @classmethod
    def validate_hourly(cls, v: list[int]) -> list[int]:
        if len(v) != 24:  # noqa: PLR2004
            msg = f"hourly_buckets must have 24 elements, got {len(v)}"
            raise ValueError(msg)
        return v

    @field_validator("daily_buckets")
    @classmethod
    def validate_daily(cls, v: list[int]) -> list[int]:
        if len(v) != 7:  # noqa: PLR2004
            msg = f"daily_buckets must have 7 elements, got {len(v)}"
            raise ValueError(msg)
        return v

    @property
    def peak_hour(self) -> int | None:
        """UTC hour with the highest event count. None if no events."""
        if self.total_events == 0:
            return None
        return self.hourly_buckets.index(max(self.hourly_buckets))

    @property
    def active_hours(self) -> list[int]:
        """UTC hours with at least one event."""
        return [h for h, count in enumerate(self.hourly_buckets) if count > 0]


# ---------------------------------------------------------------------------
# Specialized sub-baselines per domain context
# ---------------------------------------------------------------------------

class NetworkBaseline(CyberShieldBaseModel):
    """
    Aggregated network behavior for one entity.

    Populated for: hospital_server, domain_controller, ot_node, attacker.

    The Feature Engine uses this to detect:
    - Connections to new destination IPs (not in unique_dst_ips)
    - Unusual ports (not in port_distribution)
    - Protocol switches (e.g., OT node suddenly using tcp)
    - Excessive outbound bytes (bytes_out_stats.p99 exceeded)
    """

    unique_src_ips: set[str] = Field(
        default_factory=set,
        description="All source IPs observed for this entity.",
    )
    unique_dst_ips: set[str] = Field(
        default_factory=set,
        description="All destination IPs observed for this entity.",
    )
    port_distribution: dict[str, int] = Field(
        default_factory=dict,
        description="Port (as string) → event count. Supports non-numeric protocols.",
    )
    protocol_distribution: dict[str, int] = Field(
        default_factory=dict,
        description="Protocol → event count (tcp, udp, modbus, etc.).",
    )
    bytes_out_stats: NumericStats | None = Field(
        default=None,
        description="Bytes outbound statistics. None if no bytes_out observations.",
    )
    connection_count: int = Field(
        default=0, ge=0,
        description="Total network connection events observed.",
    )


class ProcessBaseline(CyberShieldBaseModel):
    """
    Aggregated process behavior for one entity.

    Populated for: hospital_server, domain_controller (where process fields exist).

    The Feature Engine uses this to detect:
    - Execution of processes never seen in baseline (new/unknown binary)
    - New parent-child process relationships
    - Processes spawning from unusual parents
    """

    unique_processes: set[str] = Field(
        default_factory=set,
        description="All unique process names (executables) observed.",
    )
    unique_parent_processes: set[str] = Field(
        default_factory=set,
        description="All unique parent process names observed.",
    )
    process_frequency: dict[str, int] = Field(
        default_factory=dict,
        description="Process name → execution count.",
    )
    parent_child_pairs: set[str] = Field(
        default_factory=set,
        description="Observed parent::child pairs (parent__child format).",
    )
    pid_stats: NumericStats | None = Field(
        default=None,
        description="PID distribution statistics. None if no pid observations.",
    )
    process_event_count: int = Field(
        default=0, ge=0,
        description="Total process events (ProcessCreate, ProcessTerminate) observed.",
    )


class ModbusBaseline(CyberShieldBaseModel):
    """
    Modbus/OT behavioral baseline for ot_node entities.

    Populated for: ot_node ONLY.

    The Feature Engine uses this to detect:
    - Reads/writes to register addresses outside the normal range
    - Values outside the normal range (potential PLC manipulation)
    - Unexpected function codes (FC06 write when only FC03 reads expected)
    - Unusual supervisory host IPs (unauthorized SCADA access)
    """

    register_stats: NumericStats | None = Field(
        default=None,
        description="Modbus register address statistics. None if no OT events.",
    )
    value_stats: NumericStats | None = Field(
        default=None,
        description="Modbus register value statistics. None if no OT events.",
    )
    function_code_distribution: dict[str, int] = Field(
        default_factory=dict,
        description="Function code → event count (FC03, FC06, etc.).",
    )
    known_supervisory_hosts: set[str] = Field(
        default_factory=set,
        description="All supervisory host IPs that have issued commands.",
    )
    modbus_event_count: int = Field(
        default=0, ge=0,
        description="Total Modbus events observed.",
    )


class AuthBaseline(CyberShieldBaseModel):
    """
    Authentication behavioral baseline for domain_controller entities.

    Populated for: domain_controller ONLY.

    The Feature Engine uses this to detect:
    - Unusual logon types (interactive logon from a service account)
    - Auth package switches (NTLM used by normally-Kerberos account)
    - Rising failure rates (credential stuffing, brute force)
    - New domain logon activity
    """

    logon_type_distribution: dict[str, int] = Field(
        default_factory=dict,
        description="Logon type → event count (network, interactive, service).",
    )
    auth_package_distribution: dict[str, int] = Field(
        default_factory=dict,
        description="Auth package → event count (Kerberos, NTLM, negotiate).",
    )
    failure_count: int = Field(
        default=0, ge=0,
        description="Total authentication failures observed in baseline.",
    )
    success_count: int = Field(
        default=0, ge=0,
        description="Total authentication successes observed in baseline.",
    )
    windows_event_id_distribution: dict[str, int] = Field(
        default_factory=dict,
        description="Windows Event ID (as string) → count.",
    )
    auth_event_count: int = Field(
        default=0, ge=0,
        description="Total authentication events observed.",
    )

    @property
    def failure_rate(self) -> float:
        """Authentication failure rate. 0.0 if no auth events."""
        total = self.failure_count + self.success_count
        if total == 0:
            return 0.0
        return self.failure_count / total


# ---------------------------------------------------------------------------
# EntityBaseline — complete behavioral profile for ONE entity
# ---------------------------------------------------------------------------

class EntityBaseline(CyberShieldBaseModel):
    """
    Complete behavioral baseline profile for a single entity.

    An entity is identified by its EntityKey (type + id).
    All statistics fields may be None if no observations for that domain
    were present in the baseline data for this entity.

    Built by: StatisticsComputer (given a list of CanonicalEvent for one entity).
    Consumed by: Feature Engine (Module 2.2+).

    Schema Contract
    ---------------
    - Callers MUST check baseline_version before consuming.
    - None fields mean "not applicable for this entity type" — not "missing data".
    - observation_count must be > 0 for any statistics to be valid.
    """

    # ── Identity ─────────────────────────────────────────────────────────
    entity_key: EntityKey = Field(description="Entity this baseline describes.")
    baseline_version: str = Field(
        default=BASELINE_SCHEMA_VERSION,
        description="Schema version — must match current BASELINE_SCHEMA_VERSION.",
    )

    # ── Observation window ───────────────────────────────────────────────
    observation_count: int = Field(
        default=0, ge=0,
        description="Total CanonicalEvents that contributed to this baseline.",
    )
    first_seen: datetime | None = Field(
        default=None,
        description="Earliest event timestamp in baseline data.",
    )
    last_seen: datetime | None = Field(
        default=None,
        description="Most recent event timestamp in baseline data.",
    )
    computed_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp when this EntityBaseline was computed.",
    )

    # ── Universal distributions (all entity types) ───────────────────────
    event_type_distribution: dict[str, int] = Field(
        default_factory=dict,
        description="EventType → count across all observed events.",
    )
    action_distribution: dict[str, int] = Field(
        default_factory=dict,
        description="Action → count (execute, read, write, authenticate).",
    )
    result_distribution: dict[str, int] = Field(
        default_factory=dict,
        description="Result → count (success, failure, unknown).",
    )
    source_distribution: dict[str, int] = Field(
        default_factory=dict,
        description="Source → count (which telemetry sources emitted events for this entity).",
    )

    # ── Temporal pattern ─────────────────────────────────────────────────
    time_pattern: TimePattern = Field(
        default_factory=TimePattern,
        description="Hourly and daily activity distribution.",
    )

    # ── Domain-specific baselines (None if not applicable) ───────────────
    network: NetworkBaseline | None = Field(
        default=None,
        description="Network behavior baseline. None if no network events observed.",
    )
    process: ProcessBaseline | None = Field(
        default=None,
        description="Process behavior baseline. None if no process events observed.",
    )
    modbus: ModbusBaseline | None = Field(
        default=None,
        description="OT/Modbus behavior baseline. None if not an OT entity.",
    )
    auth: AuthBaseline | None = Field(
        default=None,
        description="Authentication baseline. None if not an auth entity.",
    )

    # ── Resource access stats (all types where resource is meaningful) ────
    resource_stats: CategoricalStats | None = Field(
        default=None,
        description="Frequency distribution of resource field values.",
    )

    @property
    def failure_rate(self) -> float:
        """Overall result failure rate across all events."""
        total = sum(self.result_distribution.values())
        if total == 0:
            return 0.0
        return self.result_distribution.get("failure", 0) / total

    @property
    def observation_window_days(self) -> float | None:
        """Duration of the baseline observation window in days. None if no data."""
        if self.first_seen is None or self.last_seen is None:
            return None
        delta = self.last_seen - self.first_seen
        return delta.total_seconds() / 86400.0


# ---------------------------------------------------------------------------
# BaselineProfile — the complete baseline artifact for a full run
# ---------------------------------------------------------------------------

class BaselineProfile(CyberShieldBaseModel):
    """
    Complete baseline artifact produced by one BaselineBuilder run.

    Contains all EntityBaseline objects computed from one JSONL input,
    plus metadata describing the build.

    This is the primary artifact stored by BaselineStore and consumed
    by BaselineReader. One profile per build run.

    Integration
    -----------
    - BaselineStore.save(profile) → data/baseline/profiles/<profile_id>.json
    - BaselineReader.load_latest_profile() → returns the most recent BaselineProfile
    - Feature Engine calls profile.get_entity(key) for per-entity lookup
    """

    profile_id: str = Field(
        description="UUID v4 identifying this baseline build run.",
    )
    baseline_version: str = Field(
        default=BASELINE_SCHEMA_VERSION,
        description="Schema version. All contained EntityBaselines share this version.",
    )
    built_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp when this profile was built.",
    )
    source_file: str | None = Field(
        default=None,
        description="Path to the normalized_events.jsonl file used as input.",
    )
    total_events_processed: int = Field(
        default=0, ge=0,
        description="Total CanonicalEvents read from the input file.",
    )
    entities: dict[str, EntityBaseline] = Field(
        default_factory=dict,
        description="storage_key → EntityBaseline for each computed entity.",
    )
    entity_type_counts: dict[str, int] = Field(
        default_factory=dict,
        description="entity_type → count of distinct entities computed.",
    )

    def get_entity(self, key: EntityKey) -> EntityBaseline | None:
        """Return the EntityBaseline for a given key, or None if not found."""
        return self.entities.get(key.storage_key)

    def all_entity_keys(self) -> list[EntityKey]:
        """Return all EntityKey objects in this profile."""
        keys = []
        for storage_key in self.entities:
            parts = storage_key.split("__", 1)
            if len(parts) == 2:  # noqa: PLR2004
                keys.append(EntityKey(entity_type=parts[0], entity_id=parts[1]))
            else:
                logger.warning(
                    "baseline_profile_malformed_storage_key",
                    key=storage_key,
                    detail="Expected 'type__id' format; key will be skipped.",
                )
        return keys

    @property
    def entity_count(self) -> int:
        """Total number of distinct entities profiled."""
        return len(self.entities)


# ---------------------------------------------------------------------------
# BaselineManifest — index of all stored profiles
# ---------------------------------------------------------------------------

class ManifestEntry(CyberShieldBaseModel):
    """Single entry in the baseline manifest."""

    profile_id: str
    built_at: datetime
    total_events: int
    entity_count: int
    baseline_version: str
    source_file: str | None = None


class BaselineManifest(CyberShieldBaseModel):
    """
    Index of all baseline profiles stored on disk.

    Written to data/baseline/manifest.json after every build.
    The Feature Engine reads this to discover available profiles
    without loading the full profile data.

    latest_profile_id always points to the most recently built profile.
    """

    last_updated: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="When this manifest was last updated.",
    )
    latest_profile_id: str | None = Field(
        default=None,
        description="Profile ID of the most recently built baseline.",
    )
    profiles: list[ManifestEntry] = Field(
        default_factory=list,
        description="All profiles in reverse-chronological order (newest first).",
    )

    def add_entry(self, profile: "BaselineProfile") -> None:
        """Insert a new profile entry at the front of the list."""
        entry = ManifestEntry(
            profile_id=profile.profile_id,
            built_at=profile.built_at,
            total_events=profile.total_events_processed,
            entity_count=profile.entity_count,
            baseline_version=profile.baseline_version,
            source_file=profile.source_file,
        )
        self.profiles.insert(0, entry)
        self.latest_profile_id = profile.profile_id
        object.__setattr__(self, "last_updated", datetime.now(UTC))


# ---------------------------------------------------------------------------
# BaselineBuildReport — summary of a build run
# ---------------------------------------------------------------------------

class BaselineBuildReport(CyberShieldBaseModel):
    """
    Summary statistics from one BaselineBuilder.build() run.

    Emitted at the end of every build. Useful for monitoring and diagnostics.
    Does NOT contain the actual baseline data (that is in BaselineProfile).
    """

    profile_id: str
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None
    input_file: str | None = None
    total_events_read: int = Field(default=0, ge=0)
    total_entities_computed: int = Field(default=0, ge=0)
    entities_by_type: dict[str, int] = Field(default_factory=dict)
    compute_errors: int = Field(default=0, ge=0)
    profile_saved_to: str | None = None

    @property
    def duration_seconds(self) -> float | None:
        """Wall-clock duration of this build run."""
        if self.completed_at is None:
            return None
        return (self.completed_at - self.started_at).total_seconds()
