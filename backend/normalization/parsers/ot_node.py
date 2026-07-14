"""
backend.normalization.parsers.ot_node — OT Node Parser
======================================================
Module 1.3 — Unified Log Collection & Normalization

Converts raw telemetry events from the Digital Twin ot-node container
into CanonicalEvent records.

Source Context
--------------
The ot-node simulates a SCADA/PLC device communicating via Modbus TCP.
Normal baseline:
  - Reads  registers 10–20 every 5 seconds  (FC03)
  - Writes registers 30–40 every 60 seconds (FC06)
  - Heartbeats every 30 seconds
  - PLC status every 60 seconds
All legitimate traffic originates from supervisory_host = 192.168.1.100.

Expected Event Types
--------------------
  ModbusRead       — register read operation (FC03)
  ModbusWrite      — register write operation (FC06)
  ModbusHeartbeat  — keepalive check
  PLCStatus        — periodic status report

Field Mapping (raw → CanonicalEvent)
-------------------------------------
Raw field            Canonical field       Notes
-------------------  --------------------  ---------------------------------
modbus_register      modbus_register       int — register address
modbus_value         modbus_value          int — value read/written
modbus_function_code modbus_function_code  FC03|FC06|etc.
supervisory_host     supervisory_host      IP of the controlling SCADA host
                     src_ip                same as supervisory_host
                     dst_ip                PLC IP (host field)
                     port                  502 (Modbus TCP standard)
                     protocol              "modbus"

Missing Field Strategy
----------------------
- OT events never have process/command_line/file/DB/auth fields → None
- port is always 502 (Modbus TCP) unless raw supplies it
- protocol is always "modbus"
- supervisory_host maps to src_ip for consistent anomaly detection

OT Anomaly Signals (for future Feature Engine)
-----------------------------------------------
These fields enable detection of:
  - Rapid write frequency  (ModbusWrite at 10x normal rate)
  - Unexpected source IP   (src_ip != 192.168.1.100)
  - Unusual register range (modbus_register > 40 in write)
  - Large read sequences   (many consecutive FC03s)

Sample Raw Records
------------------
ModbusRead:
  {
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
    "raw_log": "{...}"
  }

PLCStatus:
  {
    "event_type": "PLCStatus",
    "host": "ot-node-01",
    "user": "SCADA",
    "resource": "plc_status_report",
    "action": "read",
    "result": "success",
    "cpu_load": 12.4,
    "memory_free_kb": 8192
  }
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from backend.normalization.exceptions import ParseError
from backend.normalization.models import CanonicalEvent
from backend.normalization.parsers import BaseParser

_KNOWN_EVENT_TYPES = frozenset(
    {
        "ModbusRead",
        "ModbusWrite",
        "ModbusHeartbeat",
        "PLCStatus",
        "AttackerHeartbeat",
    }
)

# Modbus TCP always uses port 502
_MODBUS_TCP_PORT = 502


class OTNodeParser(BaseParser):
    """
    Parser for ot-node Digital Twin telemetry.

    Maps raw JSONL records from /logs/ot_node.jsonl to CanonicalEvent.
    All Modbus-specific fields are preserved and mapped to the canonical OT fields.
    """

    SOURCE = "ot_node"

    def parse(self, raw: dict[str, Any]) -> CanonicalEvent:
        """
        Parse an ot-node raw record into a CanonicalEvent.

        Parameters
        ----------
        raw:  Parsed JSON dict from the ot_node JSONL file.

        Returns
        -------
        CanonicalEvent with Modbus fields populated; all process/auth fields None.

        Raises
        ------
        ParseError if required fields are absent.
        """
        warnings: list[str] = []

        # ── Required fields ──────────────────────────────────────────────
        try:
            timestamp_raw = self._get_required(raw, "timestamp")
            event_type = self._get_required(raw, "event_type")
            # Digital twin data uses 'hostname'; canonical name is 'host'
            host = raw.get("host") or raw.get("hostname") or ""
            if not host:
                from backend.normalization.exceptions import MissingFieldError

                raise MissingFieldError(
                    f"Required field 'host'/'hostname' is absent in raw record from source '{self.SOURCE}'.",
                    source=self.SOURCE,
                    raw_record=raw,
                    field="host",
                )
        except Exception as exc:
            raise ParseError(
                str(exc),
                source=self.SOURCE,
                raw_record=raw,
            ) from exc

        timestamp = self._parse_timestamp(timestamp_raw, warnings)

        if event_type not in _KNOWN_EVENT_TYPES:
            self._warn(warnings, f"Unknown event_type '{event_type}' — preserving.")

        # ── Core fields ───────────────────────────────────────────────────
        user = self._get_optional(raw, "user", default="SCADA")
        resource = self._get_optional(raw, "resource", default="unknown")
        action = self._get_optional(raw, "action", default="unknown")
        result = self._get_optional(raw, "result", default="unknown")
        raw_log = self._get_optional(raw, "raw_log", default="")
        event_id = self._get_optional(raw, "event_id")

        # ── Modbus / OT fields ────────────────────────────────────────────
        supervisory_host = self._get_optional(raw, "supervisory_host")
        mod_reg_raw = self._get_optional(raw, "modbus_register")
        modbus_register = self._safe_int(mod_reg_raw, "modbus_register", warnings)

        mod_val_raw = self._get_optional(raw, "modbus_value")
        modbus_value = self._safe_int(mod_val_raw, "modbus_value", warnings)

        modbus_function_code = self._get_optional(raw, "modbus_function_code")

        # ── Network context (derived from OT semantics) ───────────────────
        # Modbus TCP: supervisory_host → ot_node via port 502
        src_ip = supervisory_host  # where the command came FROM
        dst_ip = self._get_optional(raw, "dst_ip")  # normally the PLC IP
        port_raw = self._get_optional(raw, "port")
        port = self._safe_int(port_raw, "port", warnings) or _MODBUS_TCP_PORT
        protocol = "modbus"

        # ── Extra fields (cpu_load, memory_free_kb, etc.) ─────────────────
        known_keys = {
            "event_id",
            "timestamp",
            "source",
            "event_type",
            "host",
            "user",
            "resource",
            "action",
            "result",
            "raw_log",
            "supervisory_host",
            "modbus_register",
            "modbus_value",
            "modbus_function_code",
            "dst_ip",
            "port",
        }
        extra_fields = {k: v for k, v in raw.items() if k not in known_keys}

        return CanonicalEvent(
            **({"event_id": event_id} if event_id else {}),
            timestamp=timestamp,
            source=self.SOURCE,
            event_type=event_type,
            host=host.lower(),
            user=str(user),
            resource=str(resource),
            action=str(action),
            result=str(result),
            raw_log=str(raw_log) if raw_log else None,
            # OT/ICS
            modbus_register=modbus_register,
            modbus_value=modbus_value,
            modbus_function_code=modbus_function_code,
            supervisory_host=supervisory_host,
            # Network (derived)
            src_ip=src_ip,
            dst_ip=dst_ip,
            port=port,
            protocol=protocol,
            # Pipeline metadata
            parse_warnings=warnings,
            extra_fields=extra_fields,
        )

    # ── Private helpers ────────────────────────────────────────────────────

    def _parse_timestamp(self, raw_ts: Any, warnings: list[str]) -> datetime:
        if isinstance(raw_ts, datetime):
            return raw_ts if raw_ts.tzinfo else raw_ts.replace(tzinfo=UTC)
        try:
            ts_str = str(raw_ts).rstrip("Z")
            return datetime.fromisoformat(ts_str).replace(tzinfo=UTC)
        except ValueError:
            self._warn(warnings, f"Cannot parse timestamp '{raw_ts}' — using now().")
            return datetime.now(UTC)

    def _safe_int(self, value: Any, field_name: str, warnings: list[str]) -> int | None:
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            self._warn(warnings, f"'{field_name}' is not int: {value!r}")
            return None
