"""
backend.normalization.parsers.domain_controller — Domain Controller Parser
==========================================================================
Module 1.3 — Unified Log Collection & Normalization

Converts raw telemetry events from the Digital Twin domain-controller
container into CanonicalEvent records.

Source Context
--------------
The domain-controller simulates Active Directory authentication events.
It generates Windows Security Event IDs:
  4624 — An account was successfully logged on
  4625 — An account failed to log on
  4634 — An account was logged off
  4672 — Special privileges assigned to new logon
  4720 — A user account was created
  4728 — A member was added to a security-enabled global group
  4769 — A Kerberos service ticket was requested

Expected Event Types
--------------------
  UserLogon               — successful logon (EID 4624)
  UserLogonFailed         — failed logon (EID 4625)
  UserLogoff              — account logged off (EID 4634)
  PrivilegeAssigned       — elevated token (EID 4672)
  UserCreated             — new account (EID 4720)
  GroupMembershipChanged  — group membership (EID 4728)
  KerberosTicketRequest   — TGS/TGT request (EID 4769)

Field Mapping (raw → CanonicalEvent)
-------------------------------------
Raw field            Canonical field       Notes
-------------------  --------------------  ---------------------------------
logon_type           logon_type            interactive|network|service|batch
auth_package         auth_package          NTLM|Kerberos|negotiate
domain               domain                Windows domain name
ip_address           src_ip               workstation IP making request
dst_ip               dst_ip               DC IP (constant in DT)
windows_event_id     windows_event_id      4624|4625|4634|4672|4720|4728|4769
logon_id             extra_fields          Windows logon session ID
group_name           extra_fields          affected group name

Missing Field Strategy
----------------------
- DC events do not have process/file/DB fields → all None
- src_ip is the workstation; dst_ip is the DC
- logon_type and auth_package are present only for logon events

Sample Raw Records
------------------
UserLogon:
  {
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
    "windows_event_id": 4624
  }

KerberosTicketRequest:
  {
    "event_type": "KerberosTicketRequest",
    "user": "svc-iis",
    "resource": "krbtgt/HOSPITAL",
    "action": "query",
    "result": "success",
    "windows_event_id": 4769,
    "domain": "HOSPITAL"
  }
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from backend.normalization.exceptions import ParseError
from backend.normalization.models import CanonicalEvent
from backend.normalization.parsers import BaseParser


_KNOWN_EVENT_TYPES = frozenset({
    "UserLogon",
    "UserLogonFailed",
    "UserLogoff",
    "PrivilegeAssigned",
    "UserCreated",
    "UserDeleted",
    "GroupMembershipChanged",
    "KerberosTicketRequest",
    "AttackerHeartbeat",
})

# Windows logon type integers → human-readable strings
_LOGON_TYPE_MAP: dict[int, str] = {
    2:  "interactive",
    3:  "network",
    4:  "batch",
    5:  "service",
    7:  "unlock",
    8:  "network_cleartext",
    9:  "new_credentials",
    10: "remote_interactive",
    11: "cached_interactive",
}


class DomainControllerParser(BaseParser):
    """
    Parser for domain-controller Digital Twin telemetry.

    Maps raw JSONL records from /logs/domain_controller.jsonl to CanonicalEvent.
    All auth context fields (logon_type, auth_package, domain) are preserved.
    """

    SOURCE = "domain_controller"

    def parse(self, raw: dict[str, Any]) -> CanonicalEvent:
        """
        Parse a domain-controller raw record into a CanonicalEvent.

        Parameters
        ----------
        raw:  Parsed JSON dict from the domain_controller JSONL file.

        Returns
        -------
        CanonicalEvent with auth context fully populated.

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

        timestamp = self._parse_timestamp(timestamp_raw, raw, warnings)

        if event_type not in _KNOWN_EVENT_TYPES:
            self._warn(warnings, f"Unknown event_type '{event_type}' — preserving.")

        # ── Core fields ───────────────────────────────────────────────────
        user = self._get_optional(raw, "user", default="SYSTEM")
        resource = self._get_optional(raw, "resource", default="unknown")
        action = self._get_optional(raw, "action", default="authenticate")
        result = self._get_optional(raw, "result", default="unknown")
        raw_log = self._get_optional(raw, "raw_log", default="")
        event_id = self._get_optional(raw, "event_id")

        # ── Auth / identity context ────────────────────────────────────────
        logon_type_raw = self._get_optional(raw, "logon_type")
        logon_type = self._normalise_logon_type(logon_type_raw, warnings)
        auth_package = self._get_optional(raw, "auth_package")
        domain = self._get_optional(raw, "domain")

        # ── Network context ───────────────────────────────────────────────
        src_ip = self._get_optional(raw, "ip_address")  # workstation IP
        dst_ip = self._get_optional(raw, "dst_ip")

        # ── Windows context ───────────────────────────────────────────────
        win_id_raw = self._get_optional(raw, "windows_event_id")
        windows_event_id = self._safe_int(win_id_raw, "windows_event_id", warnings)

        # ── Extra fields ──────────────────────────────────────────────────
        known_keys = {
            "event_id", "timestamp", "source", "event_type", "host",
            "user", "resource", "action", "result", "raw_log",
            "logon_type", "auth_package", "domain", "ip_address",
            "dst_ip", "windows_event_id",
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
            # Auth context
            logon_type=logon_type,
            auth_package=auth_package,
            domain=domain,
            # Network context
            src_ip=src_ip,
            dst_ip=dst_ip,
            # Windows context
            windows_event_id=windows_event_id,
            # Pipeline metadata
            parse_warnings=warnings,
            extra_fields=extra_fields,
        )

    # ── Private helpers ────────────────────────────────────────────────────

    def _parse_timestamp(
        self,
        raw_ts: Any,
        raw: dict[str, Any],
        warnings: list[str],
    ) -> datetime:
        """Parse timestamp to UTC-aware datetime."""
        if isinstance(raw_ts, datetime):
            return raw_ts if raw_ts.tzinfo else raw_ts.replace(tzinfo=UTC)
        try:
            ts_str = str(raw_ts).rstrip("Z")
            return datetime.fromisoformat(ts_str).replace(tzinfo=UTC)
        except ValueError:
            self._warn(warnings, f"Could not parse timestamp '{raw_ts}' — using now().")
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

    def _normalise_logon_type(
        self, value: Any, warnings: list[str]
    ) -> str | None:
        """
        Normalise logon_type: accept int (Windows EID style) or string.

        Windows stores logon type as an integer.  The generator may emit
        either an integer or the human-readable string.
        """
        if value is None:
            return None
        if isinstance(value, int):
            mapped = _LOGON_TYPE_MAP.get(value)
            if mapped is None:
                self._warn(warnings, f"Unknown logon_type integer {value}.")
            return mapped or str(value)
        if isinstance(value, str):
            return value.lower().replace(" ", "_")
        return str(value)
