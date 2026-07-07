"""
backend.normalization.parsers.attacker — Attacker Parser
=========================================================
Module 1.3 — Unified Log Collection & Normalization

Converts raw telemetry events from the Digital Twin attacker container
into CanonicalEvent records.

Source Context
--------------
The attacker container in Module 1.2 is an INFRASTRUCTURE SCAFFOLD.
In the current phase it emits only keepalive heartbeats.

Future modules (2.x, 3.x) will inject additional event types:
  ReconScan       — network reconnaissance (nmap-style)
  ExploitAttempt  — specific vulnerability exploitation
  LateralMove     — pivot to a new host
  DataExfil       — data exfiltration attempt

This parser is designed to handle future attacker events gracefully.
All unknown event types are preserved with a parse_warning rather
than rejected, ensuring future modules can inject new scenarios
without modifying this parser.

Expected Event Types (current)
-------------------------------
  AttackerHeartbeat  — keepalive pulse (every 60 seconds)

Expected Event Types (future, Module 2.x+)
------------------------------------------
  ReconScan
  ExploitAttempt
  LateralMove
  DataExfil

Field Mapping (raw → CanonicalEvent)
-------------------------------------
Raw field            Canonical field       Notes
-------------------  --------------------  ---------------------------------
src_ip               src_ip               attacker's IP
dst_ip               dst_ip               target IP
dst_port             port                 target port
scan_type            extra_fields         TCP SYN|UDP|etc.
target_host          resource             what was targeted
payload_size         bytes_out            int

Missing Field Strategy
----------------------
- Attacker events typically lack process, file, auth, OT fields → None
- src_ip is typically 172.20.3.10 (attacker segment)
- Heartbeats have no dst_ip or port → None

Sample Raw Records
------------------
AttackerHeartbeat:
  {
    "event_type": "AttackerHeartbeat",
    "host": "attacker-01",
    "user": "root",
    "resource": "attacker_keepalive",
    "action": "heartbeat",
    "result": "success",
    "src_ip": "172.20.3.10"
  }
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from backend.normalization.exceptions import ParseError
from backend.normalization.models import CanonicalEvent
from backend.normalization.parsers import BaseParser


# Known current types — future types are accepted with a warning
_KNOWN_EVENT_TYPES = frozenset({
    "AttackerHeartbeat",
    "ReconScan",
    "ExploitAttempt",
    "LateralMove",
    "DataExfil",
})


class AttackerParser(BaseParser):
    """
    Parser for attacker Digital Twin telemetry.

    Currently handles keepalive heartbeats.  Designed to accept and
    normalise future attack scenario events without modification.
    Unknown event types are preserved with a parse_warning.
    """

    SOURCE = "attacker"

    def parse(self, raw: dict[str, Any]) -> CanonicalEvent:
        """
        Parse an attacker raw record into a CanonicalEvent.

        Parameters
        ----------
        raw:  Parsed JSON dict from the attacker JSONL file.

        Returns
        -------
        CanonicalEvent. Unknown future event types accepted with a warning.

        Raises
        ------
        ParseError if required fields (timestamp, event_type, host) are absent.
        """
        warnings: list[str] = []

        # ── Required fields ──────────────────────────────────────────────
        try:
            timestamp_raw = self._get_required(raw, "timestamp")
            event_type = self._get_required(raw, "event_type")
            host = self._get_required(raw, "host")
        except Exception as exc:
            raise ParseError(
                str(exc),
                source=self.SOURCE,
                raw_record=raw,
            ) from exc

        timestamp = self._parse_timestamp(timestamp_raw, warnings)

        # Accept unknown future event types gracefully
        if event_type not in _KNOWN_EVENT_TYPES:
            self._warn(
                warnings,
                f"Unknown event_type '{event_type}' from attacker — preserving. "
                "If this is a new attack scenario, register it in _KNOWN_EVENT_TYPES.",
            )

        # ── Core fields ───────────────────────────────────────────────────
        user = self._get_optional(raw, "user", default="root")
        resource = self._get_optional(raw, "resource", default="unknown")
        action = self._get_optional(raw, "action", default="unknown")
        result = self._get_optional(raw, "result", default="unknown")
        raw_log = self._get_optional(raw, "raw_log", default="")
        event_id = self._get_optional(raw, "event_id")

        # ── Network context ───────────────────────────────────────────────
        src_ip = self._get_optional(raw, "src_ip")
        dst_ip = self._get_optional(raw, "dst_ip")
        port_raw = self._get_optional(raw, "dst_port")
        port = self._safe_int(port_raw, "dst_port", warnings)
        protocol = self._get_optional(raw, "protocol")
        bytes_raw = self._get_optional(raw, "payload_size")
        bytes_out = self._safe_int(bytes_raw, "payload_size", warnings)

        # ── All other fields go to extra_fields ──────────────────────────
        known_keys = {
            "event_id", "timestamp", "source", "event_type", "host",
            "user", "resource", "action", "result", "raw_log",
            "src_ip", "dst_ip", "dst_port", "protocol", "payload_size",
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
            # Network
            src_ip=src_ip,
            dst_ip=dst_ip,
            port=port,
            protocol=protocol,
            bytes_out=bytes_out,
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

    def _safe_int(
        self, value: Any, field_name: str, warnings: list[str]
    ) -> int | None:
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            self._warn(warnings, f"'{field_name}' is not int: {value!r}")
            return None
