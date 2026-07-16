# Response Orchestrator Architecture

## Module: 6.1 — Response Orchestrator
**Package:** `backend/orchestrator/`
**Status:** Complete — deterministic, no LLM, no real infrastructure actions.

---

## Architecture Overview

The Response Orchestrator is the deterministic response layer of the CyberShield platform. It receives an `AttackContext` (the complete intelligence package produced by Modules 1–4) and orchestrates a structured response workflow: playbook selection, blast radius analysis, human approval, and mock execution.

```
AttackContext (from Module 4.1)
         │
         ▼
 ┌─────────────────────────────────────────────────┐
 │             OrchestratorService                  │
 │                                                  │
 │  ┌──────────────┐   ┌──────────────────────────┐│
 │  │PlaybookRegistry│  │  BlastRadiusComputer     ││
 │  │              │   │  (compute_blast_radius)  ││
 │  │ select(ctx)  │   │                          ││
 │  └──────┬───────┘   └──────────┬───────────────┘│
 │         │                      │                 │
 │         ▼                      ▼                 │
 │  ResponsePlaybook      BlastRadiusReport         │
 │         │                      │                 │
 │         └──────────┬───────────┘                 │
 │                    ▼                             │
 │           OrchestratorRecord                     │
 │           (status: PENDING)                      │
 │                    │                             │
 │         ┌──────────▼──────────┐                  │
 │         │   ApprovalManager   │                  │
 │         │ PENDING → APPROVED  │                  │
 │         │         REJECTED    │                  │
 │         │         EXPIRED     │                  │
 │         └──────────┬──────────┘                  │
 │                    │ (if APPROVED)               │
 │                    ▼                             │
 │           ┌──────────────┐                       │
 │           │ MockExecutor │                       │
 │           │  (simulated) │                       │
 │           └──────┬───────┘                       │
 │                  ▼                               │
 │           ExecutionResult                        │
 │                  │                               │
 │         ┌────────▼────────┐                      │
 │         │OrchestratorStore│  OrchestratorAudit  │
 │         │  (persist)      │  Logger (JSONL)      │
 │         └─────────────────┘                      │
 └─────────────────────────────────────────────────┘
```

---

## Data Flow

```
1. AttackContext → OrchestratorService.orchestrate()
2. PlaybookRegistry.select(context) → ResponsePlaybook
3. compute_blast_radius(context) → BlastRadiusReport
4. ApprovalManager.create_pending() → ApprovalRecord (status=PENDING)
5. OrchestratorRecord assembled and persisted
6. Audit events: "playbook_selected", "approval_requested"

7. (async) Analyst calls OrchestratorService.approve() or .reject()
8. ApprovalManager transitions PENDING → APPROVED | REJECTED | EXPIRED
9. Audit event: "approved" | "rejected" | "approval_expired"

10. (if APPROVED) OrchestratorService.execute()
11. MockExecutor.execute() → ExecutionResult (simulated=True)
12. Audit events: "execution_started", "execution_complete"
13. Final OrchestratorRecord persisted with execution populated
```

---

## Component Responsibilities

### `exceptions.py`
Extends `ResponseEngineError` from `backend.core.exceptions`. Defines:
- `OrchestratorError` — base
- `PlaybookNotFoundError` (404) — no matching playbook
- `ApprovalExpiredError` (410) — TTL elapsed
- `ApprovalAlreadyProcessedError` (409) — double-decision
- `ExecutionError` (500) — mock execution failure
- `OrchestratorStorageError` (500) — I/O failure
- `OrchestratorSchemaError` (500) — schema version mismatch on load

### `models.py`
Pure immutable Pydantic models. No logic.

| Model | Purpose |
|---|---|
| `PlaybookAction` | One action step (action_type, parameters, rollback) |
| `ResponsePlaybook` | Full playbook definition with trigger conditions and actions |
| `BlastRadiusReport` | Affected assets derived from AttackContext |
| `ApprovalRecord` | PENDING→APPROVED/REJECTED/EXPIRED lifecycle |
| `SimulatedActionResult` | Output of one simulated action |
| `ExecutionResult` | Aggregate simulated execution output |
| `OrchestratorAuditEvent` | Immutable per-step audit event |
| `OrchestratorRecord` | Root object — one per orchestration run |

### `playbooks.py`
**PlaybookRegistry** — deterministic playbook definitions and selector.

Five built-in playbooks (ordered by specificity):

| ID | Trigger | Severity | Requires Chain |
|---|---|:---:|:---:|
| `ot_containment` | OT indicators present | 0.50 | No |
| `isolate_host` | TA0008/TA0003 + T1021/T1059/T1078 | 0.60 | **Yes** |
| `block_account` | TA0006/TA0001 + T1110/T1003/T1078/T1098 | 0.55 | No |
| `investigate_lateral` | TA0008/TA0007 + T1021/T1018/T1049/T1135 | 0.45 | **Yes** |
| `observe_only` | Fallback — always available | 0.0 | No |

**Selection algorithm:**
1. If OT indicators present → `ot_containment` (threshold-gated, immediate)
2. For all others: filter by `severity_threshold`, chain requirement, then require ≥1 tactic or technique match
3. Score by tactic_hits × 2 + technique_hits; pick highest match score
4. Tie-break: higher severity_threshold wins
5. Zero matches → `observe_only` fallback

### `blast_radius.py`
Read-only extraction from AttackContext. No graph construction. Sources:
- `context.evidence` → hosts, users, OT indicators
- `context.identity` → primary entity (always included)
- `context.chain` → matched alert IDs
- `context.graph` → node count (for scope estimate only)
- `context.behavioral` → baseline_available

Scope classification rules (deterministic):

| Condition | Scope |
|---|---|
| `has_ot_indicators=True` | `OT` |
| node_count ≥ 5 or alert_ids > 3 | `MULTI_ENTITY` |
| node_count ≥ 3 or hosts > 1 | `LATERAL` |
| node_count > 0 or hosts == 1 | `SINGLE_HOST` |
| otherwise | `UNKNOWN` |

### `approval.py`
**ApprovalManager** — stateless. All transitions return new `ApprovalRecord` (immutable pattern via `model_copy`).

```
PENDING ──approve()──→ APPROVED
        ──reject()───→ REJECTED
        ──check_expiry()─→ EXPIRED (when TTL elapsed)
```

Guards prevent double-processing (`ApprovalAlreadyProcessedError`).
TTL check is passive — triggered at read time, no background task.

### `executor.py`
**MockExecutor** — simulation only.
- Requires `approval.status == "APPROVED"` — raises `ExecutionError` otherwise
- Simulates each playbook action in order
- All `SimulatedActionResult.simulated = True`
- Outcome: `SIMULATED_SUCCESS` / `SIMULATED_PARTIAL` / `SIMULATED_FAILURE`
- No external calls, no side effects, deterministic

### `audit.py`
**OrchestratorAuditLogger** — JSONL append-only audit log.
- Date-partitioned files: `audit/audit_YYYY-MM-DD.jsonl`
- Thread-safe via per-file locks
- Query: `load_for_orchestration(id)`, `load_for_date()`
- Events recorded: `playbook_selected`, `approval_requested`, `approved`, `rejected`, `approval_expired`, `execution_started`, `execution_complete`

### `storage.py`
**OrchestratorStore** — identical pattern to `ContextStore`:
- JSONL date-partitioned: `records/records_YYYY-MM-DD.jsonl`
- Atomic JSON index: `records/index/<orchestration_id>.json`
- Thread-safe via per-file locks
- Index is overwritten on every save (reflects latest state)

### `service.py`
**OrchestratorService** — single entry point.

```python
svc = OrchestratorService()

# Full orchestration (returns PENDING record)
record = svc.orchestrate(context)

# Approval decision
record = svc.approve(orchestration_id, decided_by="analyst@soc.com")
record = svc.reject(orchestration_id, decided_by="analyst@soc.com", reason="FP")

# Execution (APPROVED only)
record = svc.execute(orchestration_id)

# Query
record = svc.get(orchestration_id)
ids    = svc.list_ids()
records = svc.list_by_alert(alert_id)
```

---

## Approval Workflow

```
┌─────────────────────────────────────────────────────────────┐
│                   Approval Lifecycle                         │
│                                                              │
│   orchestrate()                                              │
│       │                                                      │
│       ▼                                                      │
│   PENDING ──────────── TTL expires ──────────→ EXPIRED      │
│     │                                                        │
│     ├── approve(decided_by) ──────────────→ APPROVED        │
│     │                                           │           │
│     └── reject(decided_by, reason) ──→ REJECTED │           │
│                                                 │           │
│                                           execute()         │
│                                                 │           │
│                                                 ▼           │
│                                        ExecutionResult       │
│                                        (simulated=True)     │
└─────────────────────────────────────────────────────────────┘
```

Key rules:
- No automatic execution — approval is always required
- Default TTL: 3600 seconds (configurable per service instance)
- EXPIRED records cannot be approved or rejected
- Already-decided records raise `ApprovalAlreadyProcessedError`

---

## Audit Workflow

Every state transition produces an `OrchestratorAuditEvent`:

| Event Type | Triggered By |
|---|---|
| `playbook_selected` | `orchestrate()` |
| `approval_requested` | `orchestrate()` |
| `approved` | `approve()` |
| `rejected` | `reject()` |
| `approval_expired` | `_load_and_check_expiry()` |
| `execution_started` | `execute()` |
| `execution_complete` | `execute()` |

Events are appended to the `OrchestratorRecord.audit_trail` list **and** written to the daily JSONL audit log.

---

## Integration with AttackContext

The orchestrator consumes `AttackContext` via:

| Field | Used By |
|---|---|
| `context.detection.anomaly_score` | Playbook severity threshold gate |
| `context.mitre.all_tactic_ids` | Playbook tactic matching |
| `context.mitre.all_technique_ids` | Playbook technique matching |
| `context.chain` | Chain requirement gate, chain confidence |
| `context.evidence.has_ot_indicators` | OT playbook fast-path |
| `context.evidence.affected_hosts/users` | Blast radius |
| `context.graph.node_count` | Blast radius scope estimate |
| `context.chain.matched_alert_ids` | Blast radius alert breadth |
| `context.behavioral.baseline_available` | Blast radius cold-start flag |
| `context.identity.*` | Record identity fields |

`AttackContext` is **never modified**. `to_summary()` is available but not required — the orchestrator reads fields directly.

---

## Extension Guide

### Adding a New Playbook
1. Define a `ResponsePlaybook` instance in `playbooks.py`
2. Add to `_ALL_PLAYBOOKS` list (more specific playbooks first)
3. Update `_PLAYBOOK_BY_ID` dict
4. Add tests in `tests/unit/orchestrator/test_playbooks.py`

### Adding a New Approval State
1. Add the literal to `ApprovalStatus` in `models.py`
2. Add transition method to `ApprovalManager` in `approval.py`
3. Add guard assertions as needed
4. Add new audit event type in `service.py`
5. Add tests

### Wiring to a Real Executor (post-demo)
1. Create `RealExecutor` implementing the same `execute(record) → ExecutionResult` interface
2. Inject into `OrchestratorService.__init__` via `executor` parameter
3. `MockExecutor` remains the default — no changes to other files

---

## Tests

**Location:** `tests/unit/orchestrator/`

| File | Coverage |
|---|---|
| `conftest.py` | Fixtures and context helpers |
| `test_models.py` | Serialization round-trips, field defaults, `to_summary` contract |
| `test_playbooks.py` | All 5 playbooks selected correctly, chain gate, OT fast-path, fallback |
| `test_blast_radius.py` | Host/user inclusion, scope rules, OT priority, chain alert propagation |
| `test_approval.py` | Full lifecycle: create, approve, reject, expiry, guards, immutability |
| `test_executor.py` | Approved execution, action count, pending/rejected rejection, timestamps |
| `test_audit.py` | JSONL write/read, filter by orchestration_id, ordering, unique IDs |
| `test_storage.py` | Save/load/list, batch, date partition, index overwrite, thread-safety |
| `test_service.py` | Full orchestrate→approve→execute flow, rejection, audit trail, persistence |

**Run:**
```bash
pytest tests/unit/orchestrator/ -q --no-cov
# 123 passed, 0 failed
```
