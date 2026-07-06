"""
backend.normalization — Log Normalization & Parsing Module
==========================================================
[Module 1.3 — Week 1, Phase 1A]

RESPONSIBILITY
--------------
Parse raw log strings from every supported source into a unified
LogEvent schema. The normalised event is the universal data structure
flowing through all downstream modules.

DATA FLOW
---------
RawLogRecord (from Ingestion)
    → Source-specific parser (SysmonParser, WindowsEventParser, etc.)
    → LogEvent (unified schema)
    → Feature Engineering Module

FUTURE CONTENTS
---------------
- models/           LogEvent (extends BaseEvent), NormalizedLogWriter
- parsers/
    sysmon.py       SysmonParser (XML → LogEvent)
    windows_event.py WindowsEventParser (Event ID → LogEvent)
    auditd.py       AuditdParser
    iptables.py     IptablesParser
    dns.py          DnsParser
    netflow.py      NetflowParser
    modbus.py       ModbusParser
- normalizer.py     LogNormalizer — dispatches to correct parser
- writer.py         NormalizedLogWriter — JSONL output

INTEGRATION CONTRACT
--------------------
Input:  RawLogRecord { source, raw_log, received_at }
Output: LogEvent (full schema, all fields populated)

Output type: LogEvent (extends backend.shared.models.BaseEvent)
  Additional fields:
    - severity_baseline: int (0–10, computed from baseline stats later)
    - metadata: dict (source-specific extra fields, for forensic use)

NORMALISATION GUARANTEES
------------------------
1. All timestamps converted to UTC
2. All event_type values use canonical EventType strings
3. All hostnames lowercased
4. Missing optional fields default to empty string (never None)
5. raw_log preserved verbatim (immutable)

DEPENDENCIES
------------
- backend.core.exceptions  LogParseError, NormalizationError
- backend.shared.models    BaseEvent
- backend.shared.types     LogSourceLiteral, EventTypeLiteral
- backend.shared.utils     datetime_utils, id_utils

FEATURE FLAG
------------
settings.feature_normalization_enabled = True to activate
"""
