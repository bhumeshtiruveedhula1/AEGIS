"""
tests/unit/features/conftest.py
================================
Shared fixtures and factory functions for Module 2.2 tests.

Reuses Module 2.1 conftest patterns — does NOT duplicate test infrastructure.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from backend.baseline.models import (
    AuthBaseline,
    EntityBaseline,
    EntityKey,
    ModbusBaseline,
    NetworkBaseline,
    NumericStats,
    ProcessBaseline,
    TimePattern,
)
from backend.normalization.models import CanonicalEvent

# ---------------------------------------------------------------------------
# Fixed timestamps for deterministic tests
# ---------------------------------------------------------------------------

FIXED_TS = datetime(2024, 1, 15, 9, 30, 0, tzinfo=UTC)   # Monday 09:30 UTC
FIXED_TS_NIGHT = datetime(2024, 1, 15, 2, 0, 0, tzinfo=UTC)  # Monday 02:00 UTC (off-hours)
FIXED_TS_WEEKEND = datetime(2024, 1, 13, 10, 0, 0, tzinfo=UTC)  # Saturday 10:00 UTC


# ---------------------------------------------------------------------------
# CanonicalEvent factories
# ---------------------------------------------------------------------------

def make_hospital_event(overrides: dict[str, Any] | None = None) -> CanonicalEvent:
    """Hospital server event (has process, network, windows context)."""
    defaults: dict[str, Any] = {
        "timestamp": FIXED_TS,
        "source": "hospital_server",
        "event_type": "ProcessCreate",
        "host": "hospital-server-01",
        "user": "svc-iis",
        "resource": "w3wp.exe",
        "action": "execute",
        "result": "success",
        "process": "w3wp.exe",
        "pid": 1234,
        "parent_process": "svchost.exe",
        "command_line": "w3wp.exe -ap DefaultAppPool",
        "src_ip": "10.0.1.1",
        "dst_ip": "10.0.1.20",
        "port": 443,
        "protocol": "tcp",
        "bytes_out": 512,
        "windows_event_id": 4688,
    }
    if overrides:
        defaults.update(overrides)
    return CanonicalEvent(**defaults)


def make_dc_event(overrides: dict[str, Any] | None = None) -> CanonicalEvent:
    """Domain controller event (has auth context)."""
    defaults: dict[str, Any] = {
        "timestamp": FIXED_TS,
        "source": "domain_controller",
        "event_type": "UserLogin",
        "host": "dc01",
        "user": "jdoe",
        "resource": "dc01",
        "action": "authenticate",
        "result": "success",
        "src_ip": "10.0.1.5",
        "dst_ip": "10.0.0.10",
        "port": 389,
        "protocol": "tcp",
        "logon_type": "network",
        "auth_package": "Kerberos",
        "domain": "CORP",
        "windows_event_id": 4624,
    }
    if overrides:
        defaults.update(overrides)
    return CanonicalEvent(**defaults)


def make_ot_event(overrides: dict[str, Any] | None = None) -> CanonicalEvent:
    """OT node event (has Modbus context)."""
    defaults: dict[str, Any] = {
        "timestamp": FIXED_TS,
        "source": "ot_node",
        "event_type": "ModbusRead",
        "host": "ot-node-01",
        "user": "SCADA",
        "resource": "register_10",
        "action": "read",
        "result": "success",
        "src_ip": "192.168.10.1",
        "dst_ip": "192.168.10.50",
        "port": 502,
        "protocol": "modbus",
        "modbus_register": 10,
        "modbus_value": 100,
        "modbus_function_code": "FC03",
        "supervisory_host": "192.168.10.1",
    }
    if overrides:
        defaults.update(overrides)
    return CanonicalEvent(**defaults)


def make_attacker_event(overrides: dict[str, Any] | None = None) -> CanonicalEvent:
    """Attacker/network scanner event."""
    defaults: dict[str, Any] = {
        "timestamp": FIXED_TS,
        "source": "attacker",
        "event_type": "NetworkConnect",
        "host": "external-host",
        "user": "unknown",
        "resource": "10.0.1.1",
        "action": "connect",
        "result": "failure",
        "src_ip": "203.0.113.1",
        "dst_ip": "10.0.1.1",
        "port": 22,
        "protocol": "tcp",
    }
    if overrides:
        defaults.update(overrides)
    return CanonicalEvent(**defaults)


# ---------------------------------------------------------------------------
# NumericStats factories
# ---------------------------------------------------------------------------

def make_numeric_stats(
    mean: float = 100.0,
    std: float = 10.0,
    minimum: float = 50.0,
    maximum: float = 200.0,
    count: int = 100,
) -> NumericStats:
    return NumericStats(
        field_name="test",
        count=count,
        mean=mean,
        std=std,
        minimum=minimum,
        maximum=maximum,
        p25=mean - std,
        p50=mean,
        p75=mean + std,
        p95=mean + 2 * std,
        p99=mean + 3 * std,
    )


# ---------------------------------------------------------------------------
# TimePattern factory
# ---------------------------------------------------------------------------

def make_time_pattern(
    peak_hour: int = 9,
    peak_day: int = 0,
    total: int = 100,
) -> TimePattern:
    hourly = [0] * 24
    hourly[peak_hour] = total
    daily = [0] * 7
    daily[peak_day] = total
    return TimePattern(
        hourly_buckets=hourly,
        daily_buckets=daily,
        total_events=total,
    )


# ---------------------------------------------------------------------------
# EntityBaseline factories
# ---------------------------------------------------------------------------

def make_hospital_baseline(entity_id: str = "svc-iis") -> EntityBaseline:
    """Full hospital server entity baseline."""
    key = EntityKey(entity_type="user", entity_id=entity_id)
    return EntityBaseline(
        entity_key=key,
        observation_count=100,
        first_seen=datetime(2024, 1, 1, 9, 0, tzinfo=UTC),
        last_seen=datetime(2024, 1, 14, 9, 0, tzinfo=UTC),
        event_type_distribution={"ProcessCreate": 80, "NetworkConnect": 20},
        action_distribution={"execute": 80, "connect": 20},
        result_distribution={"success": 95, "failure": 5},
        source_distribution={"hospital_server": 100},
        time_pattern=make_time_pattern(peak_hour=9),
        network=NetworkBaseline(
            unique_src_ips={"10.0.1.1", "10.0.1.2"},
            unique_dst_ips={"10.0.1.20", "10.0.1.21"},
            port_distribution={"443": 70, "80": 30},
            protocol_distribution={"tcp": 100},
            bytes_out_stats=make_numeric_stats(mean=512.0, std=100.0),
            connection_count=100,
        ),
        process=ProcessBaseline(
            unique_processes={"w3wp.exe", "sqlservr.exe"},
            unique_parent_processes={"svchost.exe"},
            process_frequency={"w3wp.exe": 80, "sqlservr.exe": 20},
            parent_child_pairs={"svchost.exe__w3wp.exe", "svchost.exe__sqlservr.exe"},
            pid_stats=make_numeric_stats(mean=1200.0, std=200.0, minimum=100.0, maximum=9999.0),
            process_event_count=100,
        ),
    )


def make_dc_baseline(entity_id: str = "jdoe") -> EntityBaseline:
    """Domain controller user entity baseline."""
    key = EntityKey(entity_type="user", entity_id=entity_id)
    return EntityBaseline(
        entity_key=key,
        observation_count=50,
        first_seen=datetime(2024, 1, 1, 8, 0, tzinfo=UTC),
        last_seen=datetime(2024, 1, 14, 18, 0, tzinfo=UTC),
        event_type_distribution={"UserLogin": 50},
        action_distribution={"authenticate": 50},
        result_distribution={"success": 45, "failure": 5},
        source_distribution={"domain_controller": 50},
        time_pattern=make_time_pattern(peak_hour=9),
        network=NetworkBaseline(
            unique_src_ips={"10.0.1.5"},
            unique_dst_ips={"10.0.0.10"},
            port_distribution={"389": 50},
            protocol_distribution={"tcp": 50},
            connection_count=50,
        ),
        auth=AuthBaseline(
            logon_type_distribution={"network": 45, "interactive": 5},
            auth_package_distribution={"Kerberos": 45, "NTLM": 5},
            failure_count=5,
            success_count=45,
            windows_event_id_distribution={"4624": 45, "4625": 5},
            auth_event_count=50,
        ),
    )


def make_ot_baseline(entity_id: str = "ot-node-01") -> EntityBaseline:
    """OT node host entity baseline."""
    key = EntityKey(entity_type="host", entity_id=entity_id)
    return EntityBaseline(
        entity_key=key,
        observation_count=200,
        first_seen=datetime(2024, 1, 1, 0, 0, tzinfo=UTC),
        last_seen=datetime(2024, 1, 14, 23, 59, tzinfo=UTC),
        event_type_distribution={"ModbusRead": 180, "ModbusWrite": 20},
        action_distribution={"read": 180, "write": 20},
        result_distribution={"success": 200},
        source_distribution={"ot_node": 200},
        time_pattern=make_time_pattern(peak_hour=12),
        network=NetworkBaseline(
            unique_src_ips={"192.168.10.1"},
            unique_dst_ips={"192.168.10.50"},
            port_distribution={"502": 200},
            protocol_distribution={"modbus": 200},
            connection_count=200,
        ),
        modbus=ModbusBaseline(
            register_stats=make_numeric_stats(mean=15.0, std=5.0, minimum=5.0, maximum=30.0),
            value_stats=make_numeric_stats(mean=100.0, std=20.0, minimum=0.0, maximum=255.0),
            function_code_distribution={"FC03": 180, "FC06": 20},
            known_supervisory_hosts={"192.168.10.1"},
            modbus_event_count=200,
        ),
    )


# ---------------------------------------------------------------------------
# pytest fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def hospital_event() -> CanonicalEvent:
    return make_hospital_event()


@pytest.fixture
def dc_event() -> CanonicalEvent:
    return make_dc_event()


@pytest.fixture
def ot_event() -> CanonicalEvent:
    return make_ot_event()


@pytest.fixture
def attacker_event() -> CanonicalEvent:
    return make_attacker_event()


@pytest.fixture
def hospital_baseline() -> EntityBaseline:
    return make_hospital_baseline()


@pytest.fixture
def dc_baseline() -> EntityBaseline:
    return make_dc_baseline()


@pytest.fixture
def ot_baseline() -> EntityBaseline:
    return make_ot_baseline()
