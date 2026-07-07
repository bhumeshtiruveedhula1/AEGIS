"""
backend.baseline — Behavioral Baseline Generator
=================================================
Module 2.1 — Operation AEGIS Phase 2

This package implements the behavioral baseline engine for the
AI-Driven Cyber Resilience Platform.

Responsibilities
----------------
- Load normalized CanonicalEvent telemetry (from Module 1.3)
- Group behavior by entity dimension (user, host, source, user_host)
- Compute statistical behavioral profiles from normal telemetry
- Persist reusable baseline profiles in human-readable JSON
- Support incremental updates via Welford's online algorithm
- Expose a clean query interface for the Feature Engine (Module 2.2+)

Public API
----------
Models:
    EntityKey, EntityBaseline, BaselineProfile
    NumericStats, CategoricalStats, TimePattern
    NetworkBaseline, ProcessBaseline, ModbusBaseline, AuthBaseline
    BaselineManifest, BaselineBuildReport

Builder:
    BaselineBuilder           — build_from_file(), build_from_events()

Storage:
    BaselineStore             — save(), load(), save_entity(), load_entity()

Updater:
    BaselineUpdater           — update(existing, new_events)

Reader (Feature Engine interface):
    BaselineReader            — get_entity(), get_network(), process_was_seen()

Service (application entry point):
    BaselineService           — build_from_normalized_output()

Usage
-----
    # Full build from Module 1.3 output
    from backend.baseline import BaselineService
    service = BaselineService()
    report = service.build_from_normalized_output()

    # Feature Engine consumption
    from backend.baseline import BaselineReader, EntityKey
    reader = BaselineReader()
    baseline = reader.get_entity(EntityKey("user", "svc-iis"))

Architecture Contract
---------------------
ONLY BaselineReader is the sanctioned interface for downstream modules.
The Feature Engine MUST NOT access BaselineStore, BaselineProfile, or
raw JSON files directly.

This module is EXCLUSIVELY a behavioral foundation.
It does NOT:
- Score anomalies
- Classify events as attacks
- Generate alerts
- Make security decisions
"""

from __future__ import annotations

# Models
from backend.baseline.models import (
    BASELINE_SCHEMA_VERSION,
    ENTITY_TYPES,
    AuthBaseline,
    BaselineBuildReport,
    BaselineManifest,
    BaselineProfile,
    CategoricalStats,
    EntityBaseline,
    EntityKey,
    ManifestEntry,
    ModbusBaseline,
    NetworkBaseline,
    NumericStats,
    ProcessBaseline,
    TimePattern,
)

# Components
from backend.baseline.aggregator import EventAggregator
from backend.baseline.builder import BaselineBuilder
from backend.baseline.exceptions import (
    BaselineComputeError,
    BaselineError,
    BaselineInputError,
    BaselineNotFoundError,
    BaselineStorageError,
    BaselineVersionError,
)
from backend.baseline.reader import NormalizedEventReader
from backend.baseline.reader_api import BaselineReader
from backend.baseline.service import BaselineService
from backend.baseline.statistics import (
    compute_auth_baseline,
    compute_categorical_stats,
    compute_entity_baseline,
    compute_modbus_baseline,
    compute_network_baseline,
    compute_numeric_stats,
    compute_process_baseline,
    compute_time_pattern,
)
from backend.baseline.storage import BaselineStore
from backend.baseline.updater import BaselineUpdater

__all__ = [
    # Schema version
    "BASELINE_SCHEMA_VERSION",
    "ENTITY_TYPES",
    # Models
    "AuthBaseline",
    "BaselineBuildReport",
    "BaselineManifest",
    "BaselineProfile",
    "CategoricalStats",
    "EntityBaseline",
    "EntityKey",
    "ManifestEntry",
    "ModbusBaseline",
    "NetworkBaseline",
    "NumericStats",
    "ProcessBaseline",
    "TimePattern",
    # Components
    "EventAggregator",
    "BaselineBuilder",
    "BaselineReader",
    "BaselineService",
    "BaselineStore",
    "BaselineUpdater",
    "NormalizedEventReader",
    # Exceptions
    "BaselineError",
    "BaselineComputeError",
    "BaselineInputError",
    "BaselineNotFoundError",
    "BaselineStorageError",
    "BaselineVersionError",
    # Pure computation functions (for direct use in Feature Engine)
    "compute_entity_baseline",
    "compute_numeric_stats",
    "compute_categorical_stats",
    "compute_time_pattern",
    "compute_network_baseline",
    "compute_process_baseline",
    "compute_modbus_baseline",
    "compute_auth_baseline",
]
