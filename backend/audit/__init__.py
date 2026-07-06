"""
backend.audit — Audit Logging & Forensics Module
=================================================
[Module 3.3 — Week 3, Phase 3A]

RESPONSIBILITY
--------------
Record an immutable audit trail for every consequential platform action:
  - Alert detections (with anomaly score and SHAP explanation)
  - LLM enrichment calls (with cost and latency)
  - Approval decisions (with approver identity and timestamp)
  - Action executions (with outcome and side-effects)
  - Human overrides and denials (with reasoning)

Every record is IMMUTABLE once written. No updates, only inserts.

DATA FLOW
---------
Any Module (Detection, LLM, Response)
    → AuditLogger.log()
    → AuditRecord (BaseAuditRecord subclass)
    → SQLite / PostgreSQL audit_log table
    → GET /api/v1/audit (queryable by time range, alert_id, actor)

FUTURE CONTENTS
---------------
- logger.py     AuditLogger — core logging service
- models/       AuditRecord, AlertAuditRecord, ActionAuditRecord, LLMAuditRecord
- storage.py    SQLAlchemy ORM models + migrations (Alembic)
- router.py     GET  /api/v1/audit?alert_id=...&start=...&end=...
                GET  /api/v1/audit/{record_id}

DATABASE SCHEMA (planned)
--------------------------
Table: audit_log
  id               SERIAL PRIMARY KEY
  record_id        UUID NOT NULL UNIQUE
  timestamp        DATETIME NOT NULL (UTC)
  event_type       VARCHAR  (detection | enrichment | approval | execution)
  alert_id         UUID     (nullable for non-alert events)
  actor            VARCHAR  ('system' or analyst email)
  action_description TEXT
  outcome          VARCHAR  (success | failure | pending)
  anomaly_score    FLOAT    (nullable)
  recommended_action VARCHAR (nullable)
  approver         VARCHAR  (nullable)
  approval_time    DATETIME (nullable)
  execution_status VARCHAR
  side_effects     TEXT     (JSON blob)
  created_at       DATETIME NOT NULL

RETENTION POLICY
----------------
Rolling 30-day window (configurable via settings.audit_log_retention_days).
Older records archived to flat JSONL files in data/audit_archive/.

METRICS COMPUTED FROM AUDIT LOG
--------------------------------
- MTTD (Mean Time To Detection)  = detection_timestamp - event_timestamp
- MTTR (Mean Time To Response)   = execution_timestamp - detection_timestamp
- FPR  (False Positive Rate)     = denied_actions / total_actions
- Chain Detection Rate           = alerts_with_chains / total_alerts
- LLM Cost Hourly                = sum(llm_cost_usd) per hour

INTEGRATION CONTRACT
--------------------
Input:  Any event via AuditLogger.log(record: BaseAuditRecord)
Output: Persisted to DB + emitted as structured log (dual write)

DEPENDENCIES
------------
- sqlalchemy                ORM
- backend.shared.models     BaseAuditRecord
- backend.core.config       Settings (DB URL, retention period)
- backend.core.exceptions   AuditError

FEATURE FLAG
------------
settings.feature_audit_enabled = True to activate
"""
