"""
backend.ingestion — Log Collection & Ingestion Module
======================================================
[Module 1.2 — Week 1, Phase 1A]

RESPONSIBILITY
--------------
Accept raw logs from all supported sources and hand them to the
normalization module as raw strings with source metadata.

DATA FLOW
---------
Raw Logs (Sysmon, Windows Event, auditd, iptables, DNS, Netflow, Modbus)
    → LogIngestionService
    → RawLogRecord (source-tagged, timestamped, unmodified)
    → NormalizationModule

FUTURE CONTENTS
---------------
- models/           LogSource enum, RawLogRecord schema
- parsers/          Source-specific raw readers (file tail, Kafka, TCP)
- service.py        LogIngestionService — orchestrates ingestion + routing
- router.py         POST /api/v1/ingest — raw log submission API
- health.py         Component health check (is ingestion pipeline live?)

INTEGRATION CONTRACT
--------------------
Output type: backend.shared.models.BaseEvent
  Fields guaranteed by this module:
    - event_id:    UUID v4
    - timestamp:   UTC datetime (from source log)
    - source:      LogSource literal
    - raw_log:     Original log string (for forensic replay)

All other fields (event_type, host, user, resource, action, result)
are populated by the Normalization module.

DEPENDENCIES
------------
- backend.core.config      Settings
- backend.core.logging     Structured logging
- backend.core.exceptions  IngestionError, LogParseError
- backend.shared.models    BaseEvent
- backend.shared.types     LogSource

FEATURE FLAG
------------
settings.feature_ingestion_enabled = True to activate
"""
