"""
backend.normalization.parsers.hospital_server — Hospital Server Parser
=======================================================================
Module 1.3 — Unified Log Collection & Normalization

Converts raw telemetry events from the Digital Twin hospital-server
container into CanonicalEvent records.

Source Context
--------------
The hospital-server generates events from:
  - IIS web tier (w3wp.exe)     → ProcessCreate, NetworkConnect
  - SQL Server (sqlservr.exe)   → DatabaseQuery, ProcessCreate
  - Windows services             → ProcessCreate, ProcessTerminate
  - Patient record storage       → FileAccess, FileCreate
  - AD client authentication     → UserLogon (to domain-controller)

Expected Event Types
--------------------
  ProcessCreate       — new process spawned
  ProcessTerminate    — process exited
  NetworkConnect      — outbound TCP connection established
  FileAccess          — file read by a process
  FileCreate          — file written/created
  DatabaseQuery       — SQL operation performed
  UserLogon           — service account authentication

Field Mapping (raw → CanonicalEvent)
-------------------------------------
Raw field            Canonical field       Notes
-------------------  --------------------  ---------------------------------
event_id             event_id              direct carry
timestamp            timestamp             UTC-normalised
source               source                always "hospital_server"
event_type           event_type            validated against known types
host                 host                  lowercased
user                 user                  service account name
resource             resource              process name, file path, etc.
action               action                execute|read|write|authenticate
result               result                success|failure
raw_log              raw_log               verbatim JSONL payload
process_name         process               executable name
pid                  pid                   int
parent_process       parent_process        parent exe
command_line         command_line          full command string
dst_ip               dst_ip               outbound connection target
dst_port             port                  TCP port
src_ip               src_ip               local IP
bytes_sent           bytes_out             int
file_path            file_path             full path
query_type           db_query              SELECT|INSERT|EXEC etc.
table_name           db_table              target table
windows_event_id     windows_event_id      4688|4689|4624|4625|Sysmon 3|11

Missing Field Strategy
----------------------
All optional fields default to None.  FileAccess events do not have
network fields — they are None, not "".  DatabaseQuery events do not
have process fields — they are None.  The Feature Engine must treat
None as "not applicable" for this source+event_type combination.

Sample Raw Records
------------------
ProcessCreate:
  {
    "event_id": "uuid",
    "timestamp": "2024-01-01T00:00:00.123456Z",
    "source": "hospital_server",
    "event_type": "ProcessCreate",
    "host": "hospital-server-01",
    "user": "svc-iis",
    "resource": "w3wp.exe",
    "action": "execute",
    "result": "success",
    "raw_log": "...",
    "process_name": "w3wp.exe",
    "pid": 4812,
    "parent_process": "svchost.exe",
    "command_line": "c:\\windows\\system32\\inetsrv\\w3wp.exe -ap DefaultAppPool",
    "windows_event_id": 4688
  }

NetworkConnect:
  {
    "event_type": "NetworkConnect",
    "src_ip": "172.20.1.10",
    "dst_ip": "172.20.1.20",
    "dst_port": 1433,
    "protocol": "tcp",
    "bytes_sent": 1024
  }

DatabaseQuery:
  {
    "event_type": "DatabaseQuery",
    "resource": "PatientRecords",
    "user": "svc-mssql",
    "query_type": "SELECT",
    "table_name": "patients"
  }
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from backend.normalization.exceptions import ParseError
from backend.normalization.models import CanonicalEvent
from backend.normalization.parsers import BaseParser


# Event types this source can produce
_KNOWN_EVENT_TYPES = frozenset({
    "ProcessCreate",
    "ProcessTerminate",
    "NetworkConnect",
    "NetworkDisconnect",
    "FileAccess",
    "FileCreate",
    "DatabaseQuery",
    "UserLogon",
    "AttackerHeartbeat",  # also possible when attacker pings hospital
})


class HospitalServerParser(BaseParser):
    """
    Parser for hospital-server Digital Twin telemetry.

    Maps raw JSONL records from /logs/hospital_server.jsonl to CanonicalEvent.
    See module docstring for full field mapping and sample records.
    """

    SOURCE = "hospital_server"

    def parse(self, raw: dict[str, Any]) -> CanonicalEvent:
        """
        Parse a hospital-server raw record into a CanonicalEvent.

        Parameters
        ----------
        raw:  Parsed JSON dict from the hospital_server JSONL file.

        Returns
        -------
        CanonicalEvent with all available fields populated.

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

        # ── Timestamp normalisation ───────────────────────────────────────
        timestamp = self._parse_timestamp(timestamp_raw, raw, warnings)

        # ── Event type validation ─────────────────────────────────────────
        if event_type not in _KNOWN_EVENT_TYPES:
            self._warn(
                warnings,
                f"Unknown event_type '{event_type}' — preserving as-is.",
            )

        # ── Core fields ───────────────────────────────────────────────────
        user = self._get_optional(raw, "user", default="SYSTEM")
        resource = self._get_optional(raw, "resource", default="unknown")
        action = self._get_optional(raw, "action", default="unknown")
        result = self._get_optional(raw, "result", default="unknown")
        raw_log = self._get_optional(raw, "raw_log", default="")
        event_id = self._get_optional(raw, "event_id")

        # ── Process context ───────────────────────────────────────────────
        process = self._get_optional(raw, "process_name")
        pid_raw = self._get_optional(raw, "pid")
        pid = self._safe_int(pid_raw, "pid", warnings)
        parent_process = self._get_optional(raw, "parent_process")
        command_line = self._get_optional(raw, "command_line")

        # ── Network context ───────────────────────────────────────────────
        src_ip = self._get_optional(raw, "src_ip")
        dst_ip = self._get_optional(raw, "dst_ip")
        port_raw = self._get_optional(raw, "dst_port")
        port = self._safe_int(port_raw, "dst_port", warnings)
        protocol = self._get_optional(raw, "protocol")
        bytes_raw = self._get_optional(raw, "bytes_sent")
        bytes_out = self._safe_int(bytes_raw, "bytes_sent", warnings)

        # ── File context ──────────────────────────────────────────────────
        file_path = self._get_optional(raw, "file_path")

        # ── Database context ──────────────────────────────────────────────
        db_query = self._get_optional(raw, "query_type")
        db_table = self._get_optional(raw, "table_name")

        # ── Windows context ───────────────────────────────────────────────
        win_id_raw = self._get_optional(raw, "windows_event_id")
        windows_event_id = self._safe_int(win_id_raw, "windows_event_id", warnings)

        # ── Collect unrecognised keys as extra_fields ─────────────────────
        known_keys = {
            "event_id", "timestamp", "source", "event_type", "host",
            "user", "resource", "action", "result", "raw_log",
            "process_name", "pid", "parent_process", "command_line",
            "src_ip", "dst_ip", "dst_port", "protocol", "bytes_sent",
            "file_path", "query_type", "table_name", "windows_event_id",
        }
        extra_fields = {k: v for k, v in raw.items() if k not in known_keys}

        return CanonicalEvent(
            # BaseEvent fields
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
            # Process
            process=process,
            pid=pid,
            parent_process=parent_process,
            command_line=command_line,
            # Network
            src_ip=src_ip,
            dst_ip=dst_ip,
            port=port,
            protocol=protocol,
            bytes_out=bytes_out,
            # File
            file_path=file_path,
            # Database
            db_query=db_query,
            db_table=db_table,
            # Windows
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
        """Parse a timestamp string to UTC-aware datetime."""
        if isinstance(raw_ts, datetime):
            return raw_ts if raw_ts.tzinfo else raw_ts.replace(tzinfo=UTC)
        try:
            # Handle trailing 'Z' (not valid ISO in older Python)
            ts_str = str(raw_ts).rstrip("Z")
            dt = datetime.fromisoformat(ts_str).replace(tzinfo=UTC)
            return dt
        except ValueError:
            self._warn(warnings, f"Could not parse timestamp '{raw_ts}' — using now().")
            return datetime.now(UTC)

    def _safe_int(
        self,
        value: Any,
        field_name: str,
        warnings: list[str],
    ) -> int | None:
        """Convert to int or return None with a warning on failure."""
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            self._warn(warnings, f"Field '{field_name}' is not an integer: {value!r}")
            return None
