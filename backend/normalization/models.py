"""
backend.normalization.models — Canonical Event Schema & Pipeline Models
=======================================================================
Module 1.3 — Unified Log Collection & Normalization

This module defines the SINGLE authoritative data model that all future
platform modules MUST consume.  Every telemetry event — regardless of
origin — is normalized into a CanonicalEvent before downstream processing.

Model Hierarchy
---------------
  CanonicalEvent      The unified event schema (extends BaseEvent)
  RawRecord           A single JSONL line with source metadata attached
  ParseStats          Per-run normalization statistics
  ParseReport         Full pipeline run report (emitted at completion)

Canonical Schema Contract
--------------------------
All fields marked Optional/None are explicitly absent for a given source.
The downstream Feature Engine MUST treat None as "not applicable",
never as "unknown value" or "zero".

Field Presence Matrix
---------------------
Field                   | Hospital | DC   | OT   | Attacker
------------------------|----------|------|------|----------
process / pid           |  ✓       |  ✓   |  —   |  —
command_line            |  ✓       |  —   |  —   |  —
parent_process          |  ✓       |  —   |  —   |  —
src_ip / dst_ip / port  |  ✓       |  ✓   |  ✓   |  ✓
bytes_out               |  ✓       |  —   |  —   |  —
modbus_*                |  —       |  —   |  ✓   |  —
supervisory_host        |  —       |  —   |  ✓   |  —
logon_type              |  —       |  ✓   |  —   |  —
auth_package / domain   |  —       |  ✓   |  —   |  —
windows_event_id        |  ✓       |  ✓   |  —   |  —
file_path               |  ✓       |  —   |  —   |  —
db_query / db_table     |  ✓       |  —   |  —   |  —

Extension Pattern
-----------------
To add a new source:
  1. Create backend/normalization/parsers/<source>.py
  2. Extend BaseParser, implement parse(raw: dict) → CanonicalEvent
  3. Register in parsers/__init__.py PARSER_REGISTRY
  4. Add tests in tests/unit/normalization/test_<source>_parser.py
  DO NOT modify CanonicalEvent for source-specific fields; use
  the `extra_fields` dict for one-off source metadata.

Schema Evolution
----------------
normalizer_version is bumped on every breaking change.
Downstream consumers check this field for compatibility.
Breaking = removing a field or changing its type.
Non-breaking = adding Optional fields (allowed without version bump).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import Field, field_validator

from backend.shared.models import BaseEvent, CyberShieldBaseModel


# ---------------------------------------------------------------------------
# Canonical Event — the unified output schema for all normalised events
# ---------------------------------------------------------------------------

class CanonicalEvent(BaseEvent):
    """
    The single source of truth for all platform telemetry.

    Extends BaseEvent with:
    - Process context    (process, pid, parent_process, command_line)
    - Network context   (src_ip, dst_ip, port, protocol, bytes_out)
    - OT/ICS fields     (modbus_register, modbus_value, supervisory_host)
    - Auth context      (logon_type, auth_package, domain)
    - Windows context   (windows_event_id, file_path, db_query, db_table)
    - Pipeline metadata (normalizer_version, parse_warnings, normalized_at)

    All source-specific optional fields default to None.
    See the Field Presence Matrix in this module's docstring.
    """

    # ─── Process context ──────────────────────────────────────────────────
    process: str | None = Field(
        default=None,
        description="Executable name (e.g., w3wp.exe, sqlservr.exe). "
                    "None for non-process events.",
    )
    pid: int | None = Field(
        default=None,
        description="Process ID on the source system. None if not applicable.",
    )
    parent_process: str | None = Field(
        default=None,
        description="Parent executable name. None for root processes.",
    )
    command_line: str | None = Field(
        default=None,
        description="Full command line string including arguments. "
                    "None if not captured.",
    )

    # ─── Network context ──────────────────────────────────────────────────
    src_ip: str | None = Field(
        default=None,
        description="Source IP address of the connection. "
                    "None for non-network events.",
    )
    dst_ip: str | None = Field(
        default=None,
        description="Destination IP address of the connection.",
    )
    port: int | None = Field(
        default=None,
        ge=0,
        le=65535,
        description="Destination port number. None for non-network events.",
    )
    protocol: str | None = Field(
        default=None,
        description="Network protocol: tcp | udp | modbus | icmp.",
    )
    bytes_out: int | None = Field(
        default=None,
        ge=0,
        description="Bytes sent outbound. None if not measured.",
    )

    # ─── OT / ICS fields ──────────────────────────────────────────────────
    modbus_register: int | None = Field(
        default=None,
        description="Modbus register address accessed. OT events only.",
    )
    modbus_value: int | None = Field(
        default=None,
        description="Modbus register value (read or written). OT events only.",
    )
    modbus_function_code: str | None = Field(
        default=None,
        description="Modbus function code (FC03=read, FC06=write). OT only.",
    )
    supervisory_host: str | None = Field(
        default=None,
        description="IP of the SCADA/supervisory host initiating the request.",
    )

    # ─── Auth / identity context ───────────────────────────────────────────
    logon_type: str | None = Field(
        default=None,
        description="Windows logon type: interactive | network | service | batch.",
    )
    auth_package: str | None = Field(
        default=None,
        description="Authentication package: NTLM | Kerberos | negotiate.",
    )
    domain: str | None = Field(
        default=None,
        description="Windows domain name. None for local accounts.",
    )
    windows_event_id: int | None = Field(
        default=None,
        description="Windows Security Event ID (4624, 4625, 4688, etc.).",
    )

    # ─── File / database context ───────────────────────────────────────────
    file_path: str | None = Field(
        default=None,
        description="Full filesystem path of the file accessed or created.",
    )
    db_query: str | None = Field(
        default=None,
        description="SQL query type (SELECT, INSERT, EXEC). "
                    "Not the full query text (PII risk).",
    )
    db_table: str | None = Field(
        default=None,
        description="Database table name accessed.",
    )

    # ─── Pipeline metadata ─────────────────────────────────────────────────
    normalizer_version: str = Field(
        default="1.0.0",
        description="Schema version of the normalizer that produced this event. "
                    "Bump on breaking changes.",
    )
    parse_warnings: list[str] = Field(
        default_factory=list,
        description="Non-fatal issues encountered during parsing. "
                    "Empty list = clean parse.",
    )
    source_file: str | None = Field(
        default=None,
        description="Filesystem path of the JSONL file this event was read from.",
    )
    normalized_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp when this event was normalized. "
                    "Distinct from event timestamp.",
    )

    # ─── Flexible extension bag ────────────────────────────────────────────
    extra_fields: dict[str, Any] = Field(
        default_factory=dict,
        description="Source-specific fields that do not fit the canonical schema. "
                    "Preserved for forensic use. Not used by the Feature Engine.",
    )

    @field_validator("normalizer_version")
    @classmethod
    def validate_version(cls, v: str) -> str:
        """Enforce semantic version format."""
        parts = v.split(".")
        if len(parts) != 3 or not all(p.isdigit() for p in parts):  # noqa: PLR2004
            msg = f"normalizer_version must be 'MAJOR.MINOR.PATCH', got: {v!r}"
            raise ValueError(msg)
        return v


# ---------------------------------------------------------------------------
# Raw Record — a single JSONL line with source metadata attached
# ---------------------------------------------------------------------------

class RawRecord(CyberShieldBaseModel):
    """
    A single unparsed telemetry record as read from a JSONL file.

    The collector produces RawRecords; the parser consumes them.
    Keeping source metadata attached ensures errors are traceable
    back to the exact file and line that caused them.
    """

    source: str = Field(
        description="Log source identifier (hospital_server, ot_node, etc.).",
    )
    source_file: str = Field(
        description="Absolute path to the JSONL file this record was read from.",
    )
    line_number: int = Field(
        ge=1,
        description="1-indexed line number within the source file.",
    )
    received_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp when this record was read by the collector.",
    )
    raw_dict: dict[str, Any] = Field(
        description="The parsed JSON dict. Preserved verbatim for forensic use.",
    )
    raw_line: str = Field(
        description="Original unparsed JSON string. Used in error reporting.",
    )


# ---------------------------------------------------------------------------
# Parse Statistics — counters per normalization run
# ---------------------------------------------------------------------------

class ParseStats(CyberShieldBaseModel):
    """
    Normalization statistics for a single telemetry source in one pipeline run.

    Used to detect degraded sources (rising error_count), monitor throughput,
    and confirm ordering guarantees held.
    """

    source: str = Field(description="Log source these stats relate to.")
    total_lines_read: int = Field(default=0, ge=0)
    events_normalized: int = Field(default=0, ge=0)
    parse_errors: int = Field(default=0, ge=0)
    validation_errors: int = Field(default=0, ge=0)
    warnings_emitted: int = Field(default=0, ge=0)
    first_event_timestamp: datetime | None = Field(
        default=None,
        description="Timestamp of the earliest event successfully normalized.",
    )
    last_event_timestamp: datetime | None = Field(
        default=None,
        description="Timestamp of the most recent event successfully normalized.",
    )

    @property
    def error_rate(self) -> float:
        """Fraction of lines that could not be normalized."""
        total = self.total_lines_read
        if total == 0:
            return 0.0
        return (self.parse_errors + self.validation_errors) / total

    @property
    def success_rate(self) -> float:
        """Fraction of lines successfully normalized."""
        return 1.0 - self.error_rate


class ParseReport(CyberShieldBaseModel):
    """
    Complete summary of one full pipeline run across all sources.

    Emitted at the end of each pipeline run and written to
    data/normalized/pipeline_report.json.  Consumed by the API
    health endpoint and future monitoring modules.
    """

    run_id: str = Field(description="UUID v4 identifying this pipeline run.")
    started_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp when the pipeline run started.",
    )
    completed_at: datetime | None = Field(
        default=None,
        description="UTC timestamp when the run finished. None if still running.",
    )
    sources_processed: list[str] = Field(
        default_factory=list,
        description="List of source names that were processed in this run.",
    )
    per_source_stats: list[ParseStats] = Field(
        default_factory=list,
        description="Detailed statistics for each source.",
    )
    total_events_normalized: int = Field(default=0, ge=0)
    total_parse_errors: int = Field(default=0, ge=0)
    output_file: str | None = Field(
        default=None,
        description="Path to the normalized JSONL output file.",
    )
    error_file: str | None = Field(
        default=None,
        description="Path to the dead-letter JSONL file for failed records.",
    )

    @property
    def duration_seconds(self) -> float | None:
        """Wall-clock duration of this run in seconds. None if still running."""
        if self.completed_at is None:
            return None
        return (self.completed_at - self.started_at).total_seconds()

    @property
    def overall_error_rate(self) -> float:
        """Error rate across all sources combined."""
        total_lines = sum(s.total_lines_read for s in self.per_source_stats)
        total_errors = sum(
            s.parse_errors + s.validation_errors for s in self.per_source_stats
        )
        if total_lines == 0:
            return 0.0
        return total_errors / total_lines
