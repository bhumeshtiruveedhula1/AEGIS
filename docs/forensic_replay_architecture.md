# Forensic Replay Architecture
## CyberShield — Module 7.3

> **Deterministic reconstruction** of historical security incidents.
> Read-only. Chronological. Immutable. Never regenerates upstream data.

---

## 1. Module Responsibilities

The Forensic Replay Engine replays historical security incidents from stored audit records.

It is **not** responsible for:
- Detection, scoring, or any analytics
- Regenerating SHAP, MITRE mappings, attack graphs, attack chains
- Regenerating attack context or response decisions
- Business logic of any upstream module

It is a dedicated **read + replay** subsystem.

---

## 2. Module Structure

```
backend/replay/
├── __init__.py          Public API re-exports
├── exceptions.py        Exception hierarchy (ReplayError ← CyberShieldError)
├── models.py            Immutable Pydantic data models
├── timeline.py          Deterministic timeline builder (TimelineBuilder)
├── player.py            Stateless replay player (ReplayPlayer)
├── navigator.py         Session and frame lookup (ReplayNavigator)
├── storage.py           Atomic JSON index + JSONL log (ReplayStore)
└── service.py           Single public facade (ReplayService)

tests/unit/replay/
├── conftest.py          Shared fixtures and factory helpers
├── test_models.py       Model immutability, validation, serialisation
├── test_timeline.py     Timeline construction, ordering, determinism
├── test_player.py       Player navigation, state transitions, edge cases
├── test_navigator.py    Lookup, filtering, frame access
├── test_storage.py      Persistence, listing, ordering, robustness
└── test_service.py      Full integration via ReplayService
```

---

## 3. Replay Sources

The engine reads from the **Audit Ledger** exclusively. It never touches:

- Detection models
- SHAP calculators
- MITRE mapping logic
- Graph builders
- Chain detectors
- Context assemblers
- Orchestrator decision logic

Every `ReplayFrame` is built from a stored `AuditEntry`.

---

## 4. Data Flow

```
AuditLedger (source of truth)
    │
    │  AuditService.get_by_alert(alert_id) / get_by_context() / get_for_date()
    │  → list[AuditEntry]
    ▼
TimelineBuilder.build(entries, source_query=...)
    │
    │  sort by (timestamp, recorded_at, sequence_number)
    │  convert AuditEntry → ReplayFrame (with AuditEventType→ReplayEventType mapping)
    │  assign sequential frame_index values
    ▼
ReplayTimeline (immutable, frozen, tuple of ReplayFrames)
    │
    │  wrapped in ReplaySession (with alert_id, context_id, metadata)
    ▼
ReplayStore.save(session)
    │
    │  atomic write → index/<session_id>.json
    │  append → sessions.jsonl
    ▼
ReplayPlayer
    │
    │  start / stop / pause / resume / next / previous / first / last / seek
    │  returns ReplayStep (frame + position + action)
    ▼
ReplayNavigator / ReplayService
    │
    │  lookup by ID, alert, context, orchestration, type
    │  frame access by index, audit_id, module, event_type
    ▼
Operational Dashboard (read-only consumption)
```

---

## 5. Replay Models

| Model | Purpose |
|-------|---------|
| `ReplayEventType` | Enum of 11 replay-visible event categories |
| `ReplayFrame` | Single timestamped event (immutable, from AuditEntry) |
| `ReplayTimeline` | Ordered tuple of ReplayFrames |
| `ReplayPosition` | Cursor position within a session (index, flags, progress) |
| `ReplayStep` | Result of a navigation action (frame + position + action) |
| `ReplaySession` | Root object: timeline + metadata + current position |
| `ReplaySummary` | Lightweight session summary (no frames) |
| `ReplayStatistics` | Aggregate stats across all sessions |

All models are `frozen=True` — immutable after creation.

### ReplayFrame Fields

| Field | Type | Description |
|-------|------|-------------|
| `frame_index` | int ≥ 0 | Zero-based position in parent timeline |
| `audit_id` | str | Source AuditEntry ID |
| `event_type` | ReplayEventType | Replay-level event category |
| `timestamp` | datetime | UTC event time (from audit record) |
| `recorded_at` | datetime | UTC time audit entry was written |
| `source_module` | str | Backend module that produced the event |
| `description` | str | Human-readable summary |
| `severity` | str\|None | critical/high/medium/low/info |
| `outcome` | str\|None | success/failure/pending/unknown |
| `actor_id` | str | Actor who performed the event |
| `correlation` | dict | alert_id, context_id, orchestration_id, host, user |
| `payload` | dict | Original module-specific data |

---

## 6. AuditEventType → ReplayEventType Mapping

| AuditEventType | ReplayEventType |
|----------------|----------------|
| detection_alert, detection_scored | detection |
| shap_explanation | explanation |
| mitre_mapped | mitre_mapping |
| attack_graph_built | attack_graph |
| attack_chain_detected | attack_chain |
| context_created | context |
| orchestration_created | orchestration |
| approval_* (pending/approved/rejected/expired) | approval |
| execution_simulated | execution |
| dashboard_accessed, metric_collected, integrity_checked, custom | audit |
| platform_started, platform_stopped | platform |
| (unmapped) | unknown |

---

## 7. Timeline Construction

`TimelineBuilder.build(entries)`:

1. Sort entries by `(timestamp, recorded_at, sequence_number)` — fully deterministic
2. Convert each `AuditEntry` to a `ReplayFrame` (mapping event type + extracting fields)
3. Assign sequential `frame_index` (0-based)
4. Return immutable `ReplayTimeline`

Same input always produces the same frame ordering regardless of insertion order.

**Convenience methods:**
- `build_for_alert(entries, alert_id)` — filter + build
- `build_for_context(entries, context_id)` — filter + build
- `build_for_orchestration(entries, orchestration_id)` — filter + build

---

## 8. Player Lifecycle

```
ReplayPlayer(session)

─── Not started ────────────────────────────────────────────────────
  current_index = -1, is_started = False

─── start() ────────────────────────────────────────────────────────
  current_index = 0, is_started = True, is_paused = False

─── next() ─────────────────────────────────────────────────────────
  current_index += 1
  if current_index == total_frames - 1: is_finished = True

─── previous() ──────────────────────────────────────────────────────
  current_index -= 1 (raises if already at 0)

─── seek(index) ──────────────────────────────────────────────────────
  current_index = index (raises if out of range)
  is_finished = (index == total_frames - 1)

─── pause() ────────────────────────────────────────────────────────
  is_paused = True

─── resume() ────────────────────────────────────────────────────────
  is_paused = False

─── first() / last() ────────────────────────────────────────────────
  Jump to index 0 / total_frames - 1

─── stop() ─────────────────────────────────────────────────────────
  current_index = -1, is_started = False, is_finished = False
```

Every operation returns a `ReplayStep(frame, position, action)` and updates the internal session snapshot. The player is stateless — each operation produces a new `ReplaySession` copy via `model_copy(update=...)`.

---

## 9. Storage Strategy

Simpler than AuditStore — sessions are large point-in-time objects, not date-streamed:

```
data/replay/
├── sessions.jsonl            ← ordered log of session_ids (insertion order)
└── index/
    ├── rpl-<uuid-1>.json     ← full ReplaySession (atomic write)
    └── rpl-<uuid-2>.json
```

**Guarantees:**
- Atomic writes: write to `.tmp` then `os.replace()` — no partial writes
- Update without duplicate log entry: checks existence before appending
- Thread-safe log append: per-file `threading.Lock`
- Newest-first listing: reverses the log on read

---

## 10. Navigation Flow

```
ReplayNavigator.get_session(session_id)
  → ReplayStore.load(session_id)

ReplayNavigator.list_sessions(limit, offset)
  → ReplayStore.list_ids()  (newest first)
  → load each + convert to ReplaySummary

ReplayNavigator.get_sessions_by_alert(alert_id)
  → ReplayStore.load_all()
  → filter by s.alert_id == alert_id

ReplayNavigator.get_frame(session_id, frame_index)
  → ReplayStore.load(session_id)
  → session.timeline.frames[frame_index]

ReplayNavigator.find_frame_by_audit_id(session_id, audit_id)
  → linear scan of frames in session
```

---

## 11. Dashboard Integration

The Replay Engine exposes replay data for the Operational Dashboard via `ReplayService`:

```python
from backend.replay.service import ReplayService

svc = ReplayService()

# Build and store a replay session
session = svc.build_session_for_alert(alert_id)

# Navigate
step, updated = svc.player_start(session.session_id)
step, updated = svc.player_next(session.session_id)
step, updated = svc.player_seek(session.session_id, 5)

# Access frames for display
frames = svc.get_frames(session.session_id, start=0, end=10)

# List all sessions for history panel
summaries = svc.list_sessions(limit=50)
```

The dashboard **does not modify** the replay module. It only calls `ReplayService` methods.

---

## 12. Public API (`backend.replay`)

```python
from backend.replay import (
    ReplayService,          # facade — use this
    ReplayPlayer,           # player — for direct navigation
    ReplayEventType,        # event category enum
    ReplayFrame,            # single timeline event
    ReplayTimeline,         # ordered frame sequence
    ReplayPosition,         # cursor position
    ReplayStep,             # navigation result
    ReplaySession,          # root replay object
    ReplaySummary,          # lightweight session info
    ReplayStatistics,       # aggregate stats
    ReplayError,            # base exception
    ReplaySessionNotFoundError,
    ReplayNavigationError,
    ReplayStorageError,
    ReplayTimelineError,
    ReplaySchemaError,
    ReplaySourceError,
)
```

---

## 13. Extension Guidelines

### Adding a new replay source type
1. Add a value to `ReplayEventType` in `models.py`
2. Add a mapping entry to `_AUDIT_TO_REPLAY` in `timeline.py`
3. Add a convenience build method to `TimelineBuilder`
4. Add a service method to `ReplayService`

### Adding a new filter
1. Add a convenience lookup method to `ReplayNavigator`
2. Expose it on `ReplayService`
3. Add a test in `test_navigator.py`

### Connecting to a new upstream source
1. Inject the upstream service into `ReplayService.__init__`
2. Call its read-only query methods in a new `build_session_for_*` method
3. No changes to upstream modules required
