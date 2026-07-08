"""
tests/unit/detection/conftest.py — Shared Detection Test Fixtures
=================================================================
Provides reusable FeatureRecord factories and entity fixtures for all
detection test modules.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from backend.baseline.models import EntityKey
from backend.features.models import (
    ALL_FEATURE_NAMES,
    FeatureRecord,
    FeatureVector,
)


def make_feature_record(
    entity_type: str = "user_host",
    entity_id: str = "alice::workstation-01",
    event_id: str | None = None,
    anomaly_hint: float = 0.0,
    baseline_available: bool = True,
) -> FeatureRecord:
    """
    Build a FeatureRecord with all feature values set to anomaly_hint.

    anomaly_hint = 0.0 → completely normal (no novel features)
    anomaly_hint = 1.0 → all binary features active (maximally novel)
    """
    import uuid

    eid = event_id or str(uuid.uuid4())
    entity_key = EntityKey(entity_type=entity_type, entity_id=entity_id)

    # All values set to anomaly_hint; binary features capped to {0, 1}
    values = {name: min(anomaly_hint, 1.0) for name in ALL_FEATURE_NAMES}
    fv = FeatureVector(entity_key=entity_key, values=values)

    return FeatureRecord(
        event_id=eid,
        event_type="ProcessCreate",
        event_source="domain_controller",
        event_timestamp=datetime(2024, 1, 15, 10, 30, tzinfo=UTC),
        event_host="workstation-01",
        event_user="alice",
        entity_key=entity_key,
        baseline_available=baseline_available,
        feature_vector=fv,
    )


def make_normal_records(n: int = 100, entity_type: str = "user_host") -> list[FeatureRecord]:
    """Return n perfectly normal FeatureRecords (all features = 0.0)."""
    return [
        make_feature_record(
            entity_type=entity_type,
            entity_id=f"user_{i}::host_{i % 10}",
            anomaly_hint=0.0,
        )
        for i in range(n)
    ]


def make_anomalous_record(entity_type: str = "user_host") -> FeatureRecord:
    """Return one highly anomalous FeatureRecord (all features = 1.0)."""
    return make_feature_record(
        entity_type=entity_type,
        entity_id="attacker::evil-host",
        anomaly_hint=1.0,
    )


# ---------------------------------------------------------------------------
# Pytest fixtures exported from this conftest
# ---------------------------------------------------------------------------


@pytest.fixture()
def normal_records() -> list[FeatureRecord]:
    """100 normal FeatureRecords for training."""
    return make_normal_records(100)


@pytest.fixture()
def anomalous_record() -> FeatureRecord:
    """One highly anomalous FeatureRecord."""
    return make_anomalous_record()


@pytest.fixture()
def mixed_records() -> list[FeatureRecord]:
    """80 normal + 1 anomalous FeatureRecord (for scoring tests)."""
    records = make_normal_records(80)
    records.append(make_anomalous_record())
    return records
