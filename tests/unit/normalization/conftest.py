"""
tests/unit/normalization/conftest.py
=====================================
Shared fixtures for normalization unit tests.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from backend.normalization.models import CanonicalEvent, RawRecord


# ---------------------------------------------------------------------------
# Fixed timestamp for deterministic tests
# ---------------------------------------------------------------------------
FIXED_TS = "2024-01-15T10:30:00.000000Z"
FIXED_DT = datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Raw event factories
# ---------------------------------------------------------------------------

def make_hospital_raw(overrides: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return a minimal valid hospital_server raw event dict."""
    base: dict[str, Any] = {
        "event_id": "aabb1122-0000-0000-0000-000000000001",
        "timestamp": FIXED_TS,
        "source": "hospital_server",
        "event_type": "ProcessCreate",
        "host": "hospital-server-01",
        "user": "svc-iis",
        "resource": "w3wp.exe",
        "action": "execute",
        "result": "success",
        "raw_log": '{"detail": "iis worker spawn"}',
        "process_name": "w3wp.exe",
        "pid": 4812,
        "parent_process": "svchost.exe",
        "command_line": "c:\\windows\\system32\\inetsrv\\w3wp.exe -ap DefaultAppPool",
        "windows_event_id": 4688,
    }
    if overrides:
        base.update(overrides)
    return base


def make_dc_raw(overrides: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return a minimal valid domain_controller raw event dict."""
    base: dict[str, Any] = {
        "event_id": "aabb1122-0000-0000-0000-000000000002",
        "timestamp": FIXED_TS,
        "source": "domain_controller",
        "event_type": "UserLogon",
        "host": "domain-controller-01",
        "user": "svc-iis",
        "resource": "hospital-server-01",
        "action": "authenticate",
        "result": "success",
        "logon_type": "network",
        "auth_package": "Kerberos",
        "domain": "HOSPITAL",
        "ip_address": "172.20.1.10",
        "windows_event_id": 4624,
    }
    if overrides:
        base.update(overrides)
    return base


def make_ot_raw(overrides: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return a minimal valid ot_node raw event dict."""
    base: dict[str, Any] = {
        "event_id": "aabb1122-0000-0000-0000-000000000003",
        "timestamp": FIXED_TS,
        "source": "ot_node",
        "event_type": "ModbusRead",
        "host": "ot-node-01",
        "user": "SCADA",
        "resource": "register_15",
        "action": "read",
        "result": "success",
        "modbus_register": 15,
        "modbus_value": 2847,
        "modbus_function_code": "FC03",
        "supervisory_host": "192.168.1.100",
    }
    if overrides:
        base.update(overrides)
    return base


def make_attacker_raw(overrides: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return a minimal valid attacker raw event dict."""
    base: dict[str, Any] = {
        "event_id": "aabb1122-0000-0000-0000-000000000004",
        "timestamp": FIXED_TS,
        "source": "attacker",
        "event_type": "AttackerHeartbeat",
        "host": "attacker-01",
        "user": "root",
        "resource": "attacker_keepalive",
        "action": "heartbeat",
        "result": "success",
        "src_ip": "172.20.3.10",
    }
    if overrides:
        base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# RawRecord factory
# ---------------------------------------------------------------------------

def make_raw_record(
    source: str,
    raw_dict: dict[str, Any],
    *,
    line_number: int = 1,
    source_file: str = "/tmp/test.jsonl",
) -> RawRecord:
    """Build a RawRecord for tests."""
    return RawRecord(
        source=source,
        source_file=source_file,
        line_number=line_number,
        raw_dict=raw_dict,
        raw_line=json.dumps(raw_dict),
    )


# ---------------------------------------------------------------------------
# JSONL file writer helper
# ---------------------------------------------------------------------------

def write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    """Write a list of dicts as JSONL to path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record) + "\n")


# ---------------------------------------------------------------------------
# Pytest fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def hospital_raw() -> dict[str, Any]:
    return make_hospital_raw()


@pytest.fixture()
def dc_raw() -> dict[str, Any]:
    return make_dc_raw()


@pytest.fixture()
def ot_raw() -> dict[str, Any]:
    return make_ot_raw()


@pytest.fixture()
def attacker_raw() -> dict[str, Any]:
    return make_attacker_raw()
