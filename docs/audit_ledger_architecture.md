# Audit Ledger Architecture
## CyberShield — Module 7.2

> **Immutable forensic record** of every consequential platform action.
> Append-only. Deterministic. Queryable. Verifiable.

---

## 1. Module Responsibilities

The Audit Ledger is responsible **only** for recording and querying audit information.

It is **not** responsible for:
- Detection logic
- Response decisions
- Replay (Module 7.3)
- Dashboard rendering
- Metrics computation
- Business logic of any kind

---

## 2. Module Structure

```
backend/audit/
├── __init__.py          Public API re-exports
├── exceptions.py        Exception hierarchy (AuditLedgerError → AuditError)
├── models.py            Immutable Pydantic data models
├── storage.py           JSONL append-only persistence (AuditStore)
├── ledger.py            Write gateway + sequence numbering (AuditLedger)
├── query.py             Filter engine with pagination (AuditQueryEngine)
├── integrity.py         7-check integrity verifier (AuditIntegrityChecker)
└── service.py           Single public facade (AuditService)

tests/unit/audit/
├── conftest.py          Shared fixtures
├── test_models.py       Model immutability and validation
├── test_storage.py      JSONL persistence and append-only contract
├── test_ledger.py       Sequence numbering and write gateway
├── test_query.py        Filter, pagination, ordering, shortcuts
├── test_integrity.py    Integrity checks on clean/corrupt ledgers
└── test_service.py      Full integration tests via AuditService
```

---

## 3. Data Flow

```
Upstream Module (detection, orchestrator, context, …)
    │
    │  AuditService.record_event(event_type, source_module, **kwargs)
    │  or: AuditService.record_detection(…) / record_approval_decision(…) etc.
    ▼
AuditService
    │
    │  builds AuditMetadata (correlation IDs)
    │  calls AuditLedger.record(event_type, metadata, …)
    ▼
AuditLedger
    │
    │  assigns next monotonic sequence_number (thread-safe)
    │  builds AuditEntry (frozen Pydantic model)
    │  calls AuditStore.save(entry)
    ▼
AuditStore
    │
    │  appends entry JSON → entries_YYYY-MM-DD.jsonl
    │  atomically writes → index/<audit_id>.json
    ▼
Filesystem (data/audit/)
```

---

## 4. Audit Models

| Model | Purpose |
|-------|---------|
| `AuditEventType` | Enum of 21 canonical event types |
| `AuditActor` | Who/what performed the action (system/operator/scheduler) |
| `AuditMetadata` | Correlation IDs + source module |
| `AuditEntry` | Single immutable ledger record (core model) |
| `AuditQuery` | Filter criteria for queries |
| `AuditResult` | Paginated query response |
| `LedgerStatistics` | Summary counts across all stored entries |

All models inherit `CyberShieldBaseModel`. All are `frozen=True` — immutable after creation.

### AuditEntry Fields

| Field | Type | Description |
|-------|------|-------------|
| `audit_id` | str | `aud-<uuid>` — unique identifier |
| `sequence_number` | int | Monotonically increasing within ledger |
| `event_type` | AuditEventType | Event classification |
| `timestamp` | datetime | UTC event time (caller-provided) |
| `recorded_at` | datetime | UTC time entry written to ledger |
| `actor` | AuditActor | Who triggered the event |
| `metadata` | AuditMetadata | Source module + correlation IDs |
| `severity` | str\|None | critical/high/medium/low/info |
| `outcome` | str\|None | success/failure/pending/unknown |
| `description` | str | Human-readable summary |
| `payload` | dict | Module-specific structured data |
| `schema_version` | str | For forward-compatibility |

---

## 5. Storage Strategy

Identical to OrchestratorStore and ContextStore — no new persistence technology:

```
data/audit/
├── entries_2026-07-16.jsonl   ← one AuditEntry per line, append-only
├── entries_2026-07-15.jsonl
└── index/
    ├── aud-<uuid-1>.json      ← atomic index for fast single-ID lookup
    └── aud-<uuid-2>.json
```

**Guarantees:**
- Append-only: `open("a")` mode — existing lines are never modified
- Atomic index: write to `.tmp` then `os.replace()` — no partial writes
- Date-partitioned: one file per UTC day — supports range queries
- Thread-safe: per-file `threading.Lock` prevents concurrent corruption

---

## 6. Ledger Lifecycle

```
AuditLedger.__init__(store_dir)
  → AuditStore(store_dir)           ← initialise storage
  → _next_seq = store.count_all()   ← resume sequence from persisted count

AuditLedger.record(event_type, metadata, ...)
  → acquire _seq_lock
  → seq = _next_seq; _next_seq += 1
  → release _seq_lock
  → build AuditEntry(sequence_number=seq, ...)
  → AuditStore.save(entry)
  → return entry

AuditLedger.append(pre_built_entry)
  → overwrites entry.sequence_number with next monotonic value
  → AuditStore.save(entry)
```

The sequence counter is initialised from `count_all()` on startup, so it
survives process restarts. Under concurrent writes, it is protected by `threading.Lock`.

---

## 7. Query Flow

```
AuditService.query(AuditQuery(...))
  → AuditQueryEngine.query(q)
      → if q.audit_id: load single entry via index
        else:          load all entries via AuditLedger.get_all()
      → filter: _matches(entry, q) — AND of all non-None filters
      → sort by timestamp (ascending or descending)
      → paginate: entries[offset : offset + limit]
      → return AuditResult(entries, total_matched, offset, limit, query)
```

**Filter types:** exact-match only. No fuzzy matching.
**Filters:** audit_id, alert_id, context_id, orchestration_id, entity_id, host, user, event_type, severity, outcome, actor_id, source_module, after (datetime), before (datetime).

---

## 8. Integrity Verification

`AuditIntegrityChecker.verify()` runs 7 checks in order:

| # | Check | Severity | What it detects |
|---|-------|----------|-----------------|
| 1 | structural | error | Lines that cannot be deserialised |
| 2 | schema | error | Unexpected `schema_version` values |
| 3 | duplicate | error | Two entries with the same `audit_id` |
| 4 | sequence | warning | Duplicate `sequence_number` values |
| 5 | timestamp | warning | `recorded_at < timestamp` by > 1 second |
| 6 | ordering | warning | Non-monotone `recorded_at` within a partition |
| 7 | index_sync | warning | Entry in JSONL but missing from index |

Returns an `IntegrityReport` with:
- `passed: bool` — True iff zero error-severity violations
- `error_count`, `warning_count`
- `violations: list[IntegrityViolation]` — one per problem found
- `summary() → str` — one-line status string

The checker **never repairs**. It reports.

---

## 9. Audit Event Types

| Event Type | Module | Trigger |
|-----------|--------|---------|
| `detection_alert` | detection | Alert generated |
| `detection_scored` | detection | Anomaly scored |
| `shap_explanation` | shap | SHAP computed |
| `mitre_mapped` | mitre | ATT&CK mapped |
| `attack_graph_built` | graph | Graph constructed |
| `attack_chain_detected` | chain | Chain found |
| `context_created` | context | AttackContext assembled |
| `orchestration_created` | orchestrator | Playbook selected |
| `approval_pending` | orchestrator | Waiting for human |
| `approval_approved` | orchestrator | Approved |
| `approval_rejected` | orchestrator | Rejected |
| `approval_expired` | orchestrator | TTL expired |
| `execution_simulated` | orchestrator | Mock execution done |
| `dashboard_accessed` | dashboard | UI access |
| `platform_started` | platform | Service startup |
| `platform_stopped` | platform | Service shutdown |
| `metric_collected` | metrics | Snapshot taken |
| `integrity_checked` | audit | Verification run |
| `custom` | any | Escape hatch |

---

## 10. Integration Points

Upstream modules write to the ledger via `AuditService`:

```python
from backend.audit.service import AuditService
svc = AuditService()

# Detection module
svc.record_detection(alert_id, entity_id, severity, anomaly_score, host=host)

# Orchestrator — creation
svc.record_orchestration_created(orchestration_id, context_id, playbook_id)

# Orchestrator — approval decision
svc.record_approval_decision(orchestration_id, "APPROVED", decided_by)

# Generic event from any module
svc.record_event(AuditEventType.CONTEXT_CREATED, source_module="context",
                 context_id=ctx_id, alert_id=alert_id)
```

**No upstream module was modified** to implement the Audit Ledger.

---

## 11. Public API (backend.audit)

```python
from backend.audit import (
    AuditService,        # facade — use this
    AuditEventType,      # enum for event classification
    AuditEntry,          # immutable record model
    AuditQuery,          # filter criteria
    AuditResult,         # paginated response
    AuditActor,          # actor model
    AuditMetadata,       # metadata model
    LedgerStatistics,    # summary stats
    AuditLedgerError,    # base exception
    AuditStorageError,   # I/O failure
    AuditRecordNotFoundError,  # 404
    AuditIntegrityError, # integrity problem
    AuditQueryError,     # invalid query
)
```

---

## 12. Extension Guidelines

### Adding a new event type
1. Add the new value to `AuditEventType` enum in `models.py`
2. Optionally add a convenience method to `AuditService` (e.g., `record_mitre_mapped()`)
3. Add a test in `test_service.py`

### Adding a new query filter
1. Add a field to `AuditQuery` in `models.py`
2. Add a matching branch in `AuditQueryEngine._matches()` in `query.py`
3. Add a test in `test_query.py`

### Adding a new integrity check
1. Add a numbered section to `AuditIntegrityChecker.verify()` in `integrity.py`
2. Use `report.add(IntegrityViolation(...))` to record findings
3. Add a test in `test_integrity.py`

### Connecting a new upstream module
1. Inject `AuditService` into the module's service class
2. Call `svc.record_event(...)` after each significant action
3. No changes to existing modules required
