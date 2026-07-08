"""
tests/unit/baseline/conftest.py
================================
Shared fixtures and factory functions for Module 2.1 baseline tests.

All synthetic CanonicalEvent objects produced here match the exact
format of events produced by Module 1.3 parsers.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from backend.normalization.models import CanonicalEvent

# ---------------------------------------------------------------------------
# Fixed timestamps for deterministic tests
# ---------------------------------------------------------------------------

FIXED_DT = datetime(2024, 1, 15, 9, 30, 0, tzinfo=UTC)   # Monday 09:30 UTC
FIXED_DT_NIGHT = datetime(2024, 1, 15, 2, 0, 0, tzinfo=UTC)   # Monday 02:00 UTC
FIXED_DT_TUESDAY = datetime(2024, 1, 16, 10, 0, 0, tzinfo=UTC)  # Tuesday 10:00 UTC


# ---------------------------------------------------------------------------
# CanonicalEvent factory helpers
# ---------------------------------------------------------------------------

def make_hospital_event(overrides: dict[str, Any] | None = None) -> CanonicalEvent:
    """Build a minimal valid hospital_server CanonicalEvent."""
    defaults: dict[str, Any] = {
        "timestamp": FIXED_DT.isoformat(),
        "source": "hospital_server",
        "event_type": "ProcessCreate",
        "host": "hospital-server-01",
        "user": "svc-iis",
        "resource": "w3wp.exe",
        "action": "execute",
        "result": "success",
        "process": "w3wp.exe",
        "pid": 4812,
        "parent_process": "svchost.exe",
        "command_line": "w3wp.exe -ap DefaultAppPool",
        "src_ip": "10.0.1.10",
        "dst_ip": "10.0.1.20",
        "port": 443,
        "protocol": "tcp",
        "bytes_out": 1024,
        "windows_event_id": 4688,
        "normalizer_version": "1.0.0",
        "parse_warnings": [],
    }
    if overrides:
        defaults.update(overrides)
    return CanonicalEvent(**defaults)


def make_dc_event(overrides: dict[str, Any] | None = None) -> CanonicalEvent:
    """Build a minimal valid domain_controller CanonicalEvent."""
    defaults: dict[str, Any] = {
        "timestamp": FIXED_DT.isoformat(),
        "source": "domain_controller",
        "event_type": "UserLogon",
        "host": "dc01",
        "user": "HOSPITAL\\\\svc-iis",
        "resource": "dc01",
        "action": "authenticate",
        "result": "success",
        "logon_type": "network",
        "auth_package": "Kerberos",
        "domain": "HOSPITAL",
        "windows_event_id": 4624,
        "src_ip": "10.0.1.10",
        "dst_ip": "10.0.1.2",
        "normalizer_version": "1.0.0",
        "parse_warnings": [],
    }
    if overrides:
        defaults.update(overrides)
    return CanonicalEvent(**defaults)


def make_ot_event(overrides: dict[str, Any] | None = None) -> CanonicalEvent:
    """Build a minimal valid ot_node CanonicalEvent."""
    defaults: dict[str, Any] = {
        "timestamp": FIXED_DT.isoformat(),
        "source": "ot_node",
        "event_type": "ModbusRead",
        "host": "ot-node-01",
        "user": "SCADA",
        "resource": "register:15",
        "action": "read",
        "result": "success",
        "modbus_register": 15,
        "modbus_value": 1500,
        "modbus_function_code": "FC03",
        "supervisory_host": "192.168.10.5",
        "src_ip": "192.168.10.5",
        "dst_ip": "192.168.10.10",
        "port": 502,
        "protocol": "modbus",
        "normalizer_version": "1.0.0",
        "parse_warnings": [],
    }
    if overrides:
        defaults.update(overrides)
    return CanonicalEvent(**defaults)


def make_attacker_event(overrides: dict[str, Any] | None = None) -> CanonicalEvent:
    """Build a minimal valid attacker CanonicalEvent."""
    defaults: dict[str, Any] = {
        "timestamp": FIXED_DT.isoformat(),
        "source": "attacker",
        "event_type": "AttackerHeartbeat",
        "host": "attacker-node-01",
        "user": "attacker",
        "resource": "10.0.1.10",
        "action": "connect",
        "result": "success",
        "src_ip": "192.168.100.50",
        "dst_ip": "10.0.1.10",
        "port": 4444,
        "protocol": "tcp",
        "bytes_out": 512,
        "normalizer_version": "1.0.0",
        "parse_warnings": [],
    }
    if overrides:
        defaults.update(overrides)
    return CanonicalEvent(**defaults)


# ---------------------------------------------------------------------------
# Bulk factory helpers
# ---------------------------------------------------------------------------

def make_hospital_batch(
    n: int,
    *,
    user: str = "svc-iis",
    host: str = "hospital-server-01",
    start_dt: datetime | None = None,
    interval_minutes: int = 5,
) -> list[CanonicalEvent]:
    """
    Generate n hospital events with sequential timestamps.
    Useful for time-pattern testing.
    """
    dt = start_dt or FIXED_DT
    events = []
    for i in range(n):
        ts = dt + timedelta(minutes=i * interval_minutes)
        events.append(make_hospital_event({
            "user": user,
            "host": host,
            "timestamp": ts.isoformat(),
            "pid": 4000 + i,
        }))
    return events


def make_ot_batch(
    n: int,
    *,
    host: str = "ot-node-01",
    register_start: int = 10,
) -> list[CanonicalEvent]:
    """Generate n OT events with varying registers."""
    return [
        make_ot_event({
            "host": host,
            "modbus_register": register_start + i,
            "modbus_value": 1000 + i * 10,
        })
        for i in range(n)
    ]


def make_mixed_events(
    hospital: int = 10,
    dc: int = 5,
    ot: int = 3,
    attacker: int = 2,
) -> list[CanonicalEvent]:
    """Generate a mixed batch of events from all 4 sources."""
    events: list[CanonicalEvent] = []
    events.extend(make_hospital_batch(hospital))
    events.extend([make_dc_event() for _ in range(dc)])
    events.extend(make_ot_batch(ot))
    events.extend([make_attacker_event() for _ in range(attacker)])
    return events


# ---------------------------------------------------------------------------
# JSONL file helpers
# ---------------------------------------------------------------------------

def write_events_jsonl(path: Path, events: list[CanonicalEvent]) -> None:
    """Write CanonicalEvent objects to a JSONL file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for event in events:
            fh.write(event.model_dump_json() + "\n")


# ---------------------------------------------------------------------------
# pytest fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def hospital_event() -> CanonicalEvent:
    return make_hospital_event()


@pytest.fixture()
def dc_event() -> CanonicalEvent:
    return make_dc_event()


@pytest.fixture()
def ot_event() -> CanonicalEvent:
    return make_ot_event()


@pytest.fixture()
def attacker_event() -> CanonicalEvent:
    return make_attacker_event()


@pytest.fixture()
def hospital_batch_20() -> list[CanonicalEvent]:
    return make_hospital_batch(20)


@pytest.fixture()
def mixed_events_50() -> list[CanonicalEvent]:
    """50 events from all 4 sources."""
    return make_mixed_events(hospital=20, dc=15, ot=10, attacker=5)


@pytest.fixture()
def normalized_jsonl(tmp_path: Path) -> Path:
    """A tmp normalized_events.jsonl with 30 hospital events."""
    out = tmp_path / "data" / "normalized" / "normalized_events.jsonl"
    write_events_jsonl(out, make_hospital_batch(30))
    return out


@pytest.fixture()
def full_normalized_jsonl(tmp_path: Path) -> Path:
    """A tmp normalized_events.jsonl with all 4 source types."""
    out = tmp_path / "data" / "normalized" / "normalized_events.jsonl"
    write_events_jsonl(out, make_mixed_events(hospital=30, dc=20, ot=15, attacker=5))
    return out
