# SOFTWARE TEST PLAN (STP)
# AI-Driven Cyber Resilience Platform — Operation AEGIS / CyberShield
# Version: 1.0.0 | Status: ACTIVE | Scope: Modules 1.x – 4.1

---

## Document Metadata

| Field | Value |
|---|---|
| Document Type | Software Test Plan (STP) |
| Project | Operation AEGIS — CyberShield |
| Scope | Modules through Attack Context Generation (4.1) |
| Out of Scope | LLM Agent, Response Orchestrator, Dashboard, Audit Ledger, SOAR |
| Audience | Developers, QA Engineers, Cybersecurity Evaluators, Hackathon Judges |
| Branch | `phase-3-behavioral-detection` |
| Tests Passing | 1541 / 0 failures |
| Last Updated | 2026-07-08 |

---

# SECTION 1 — TESTING OBJECTIVES

## 1.1 What Is Being Validated

This plan validates the deterministic AI-driven threat detection pipeline from raw log ingestion through structured attack context assembly. Every completed module is validated independently and as an integrated system.

### Modules Under Test

| Module | Component | Validates |
|---|---|---|
| 1.1 | Repository Foundation | Project structure, config, shared utilities |
| 1.2 | Digital Twin | Simulated host/user/process/network/OT environment |
| 1.3 | Log Collection + Normalization | Raw → CanonicalEvent transformation |
| 2.1 | Baseline Generator | Per-entity behavioral baseline from historical events |
| 2.2 | Feature Engineering | Numerical feature vector extraction from CanonicalEvents |
| 2.3 | Metrics Engine | Entity-level statistical metrics |
| 2.4 | Isolation Forest | Anomaly detection, scoring, thresholding |
| 3.2 | SHAP Explainability | Feature attribution for anomaly decisions |
| 3.3 | MITRE ATT&CK Mapper | Technique + tactic identification from SHAP output |
| 3.4 | Attack Graph Builder | Multi-alert graph construction |
| 3.5 | Attack Chain Detection | Kill-chain discovery from Attack Graph |
| 3.X | Synthetic Attack Generation | Realistic attack event injection |
| 4.1 | Attack Context Generation | Deterministic intelligence package assembly |

## 1.2 Why Each Component Is Critical

- **Digital Twin**: Without a realistic test environment, pipeline validation is impossible
- **Normalization**: Schema correctness is the foundation for every downstream module
- **Feature Engine**: Bad features corrupt all detection and explanation downstream
- **Isolation Forest**: The primary anomaly signal; accuracy directly drives false positive rate
- **SHAP**: Explainability is required for operator trust and MITRE attribution
- **MITRE Mapper**: ATT&CK accuracy determines tactical awareness and response relevance
- **Attack Graph**: Multi-alert correlation is what separates APT detection from single-event alerting
- **Attack Chain**: Kill-chain ordering is the primary input to threat narrative generation
- **Attack Context**: The final intelligence package; completeness determines LLM Reasoning Agent quality

## 1.3 Expected System Behaviour

- Normal events pass through the pipeline without triggering alerts
- Attack events generate anomaly scores > 0.5 within the detection layer
- SHAP attributions correctly identify the features driving the anomaly
- MITRE mapper identifies the correct technique and tactic from SHAP features
- Attack Graph grows with each new mapped technique
- Attack chains emerge from correlated graph nodes
- Attack Context packages all evidence deterministically with no inference

---

# SECTION 2 — TEST ENVIRONMENT

## 2.1 Software Requirements

| Component | Version |
|---|---|
| Python | 3.11+ |
| OS | Windows 10/11 or Linux (Ubuntu 22.04+) |
| Git | 2.40+ |
| pytest | 7.4+ |
| Virtual Environment | `.venv` (project root) |

## 2.2 Python Dependencies (Key)

```
pydantic>=2.7
scikit-learn>=1.4
shap>=0.45
networkx>=3.2
structlog>=24.0
numpy>=1.26
```

Full list: `cybershield/pyproject.toml`

## 2.3 Directory Structure

```
cyber-et/
├── cybershield/               ← Project root
│   ├── backend/               ← All modules
│   │   ├── context/           ← Module 4.1
│   │   ├── chain_detection/   ← Module 3.5
│   │   ├── attack_graph/      ← Module 3.4
│   │   ├── mitre/             ← Module 3.3
│   │   ├── explainability/    ← Module 3.2 (SHAP)
│   │   ├── detection/         ← Module 2.4
│   │   ├── features/          ← Module 2.2
│   │   ├── baseline/          ← Module 2.1
│   │   ├── normalization/     ← Module 1.3
│   │   ├── digital_twin/      ← Module 1.2
│   │   └── synthetic_attack/  ← Module 3.X
│   ├── tests/
│   │   └── unit/              ← All unit tests
│   ├── data/                  ← Runtime data (gitignored)
│   └── docs/                  ← Architecture docs
└── antigravityreferencefiles/ ← Agent reference files
```

## 2.4 Required Configuration

```python
# backend/core/config.py — key settings
Settings:
  data_dir: Path    # default: cybershield/data/
  log_level: str    # default: INFO
  model_version: str
```

## 2.5 Setup Commands

```powershell
# 1. Activate virtual environment
cd C:\Users\bhumeshjyothi\Desktop\cyber-et\cybershield
.\.venv\Scripts\Activate.ps1

# 2. Verify all tests pass
python -m pytest tests/ --no-cov -q

# 3. Confirm test count
# Expected: 1541 passed, 0 failed

# 4. Verify import chain
python -c "from backend.context import AttackContextService; print('All modules importable')"
```

## 2.6 No Docker Required

This implementation runs entirely on Python. No Docker containers are required for testing.

---

# SECTION 3 — TEST CATEGORIES

## 3.1 Unit Tests
**Purpose:** Validate each class and function in isolation with mocked dependencies.
**Why:** Catches bugs at the smallest scope before integration failures obscure root cause.
**Location:** `tests/unit/<module>/`

## 3.2 Integration Tests
**Purpose:** Validate that two or more modules interact correctly across their public API contracts.
**Why:** Module A may produce valid output, but if Module B cannot parse it, the pipeline breaks.

## 3.3 Pipeline Tests
**Purpose:** Run a full synthetic event through the entire pipeline end-to-end.
**Why:** Verifies that data flows correctly from CanonicalEvent through to AttackContext.

## 3.4 Behavioural Validation
**Purpose:** Inject known attack patterns and verify expected model behaviour (technique identification, chain formation).
**Why:** Confirms the system detects real-world threats, not just synthetic test fixtures.

## 3.5 Performance Tests
**Purpose:** Measure throughput, latency, memory, and CPU at varying event rates.
**Why:** Confirms the pipeline can handle production volumes.

## 3.6 Stress Tests
**Purpose:** Drive the system beyond expected load to find memory leaks, deadlocks, or crashes.
**Why:** Ensures stability under peak conditions.

## 3.7 Negative Tests
**Purpose:** Feed malformed, incomplete, or adversarial input to confirm correct rejection.
**Why:** Security-critical systems must never silently corrupt data or crash on bad input.

## 3.8 Regression Tests
**Purpose:** Re-run the full test suite after any change to confirm no existing behaviour broke.
**Why:** Deterministic output is a core architectural constraint.

---

# SECTION 4 — COMPONENT-WISE TEST PLAN

---

## 4.1 Digital Twin

### Purpose
The Digital Twin simulates a realistic enterprise environment: hosts, users, processes, network activity, and OT devices. It is the event source for all pipeline testing.

### What Should Be Tested
- Host generation (hostname, OS, IP)
- User generation (username, role, associated host)
- Process simulation (name, PID, parent)
- Network activity generation
- OT/Modbus register simulation
- Temporal event distribution (business hours vs. off-hours)
- Entity diversity (multiple hosts, multiple users)

### Prerequisites
```powershell
from backend.digital_twin import DigitalTwin
```

### Test Inputs
- Default configuration
- Custom host/user counts
- Custom time windows

### Execution Steps
```python
from backend.digital_twin import DigitalTwin

twin = DigitalTwin()
events = twin.generate_events(count=1000)

# Verify structure
for event in events:
    assert event.host is not None
    assert event.timestamp is not None
    assert event.event_type in ["authentication", "process", "network", "ot_modbus", "file"]
```

### Expected Output
- Events covering all event types
- Realistic timestamps within configured window
- Entity keys consistent across event set

### Pass Criteria
- ✅ All generated events pass CanonicalEvent schema validation
- ✅ All event types represented
- ✅ No None values in required fields

### Fail Criteria
- ❌ Any event fails Pydantic validation
- ❌ Single event type dominates >95% of output
- ❌ Timestamps out of configured range

### Edge Cases
- Zero-event generation request
- Single host, single user configuration
- 100% OT event configuration

---

## 4.2 Log Generation and Collection

### Purpose
Converts raw log-like data into structured CanonicalEvents that the entire pipeline consumes.

### What Should Be Tested
- Windows authentication event parsing
- Linux SSH event parsing
- Process creation event parsing
- Network connection event parsing
- OT Modbus event parsing
- Field completeness (host, user, timestamp, action, result)
- Source tagging

### Test Inputs
```python
raw_windows_auth = "source=windows EventID=4625 host=ws01 user=alice"
raw_ot = "source=ot register=40001 value=9999 function_code=6"
```

### Execution Steps
```powershell
python -m pytest tests/unit/normalization/ -v
```

### Expected Output
Each input produces a valid CanonicalEvent with correct field mapping.

### Pass Criteria
- ✅ All 36 required CanonicalEvent fields populated correctly where applicable
- ✅ Schema version tagged
- ✅ Normalizer version tagged

### Fail Criteria
- ❌ Required fields are None or empty string
- ❌ Timestamp not UTC-aware
- ❌ Unknown event_type accepted without warning

---

## 4.3 Normalization (CanonicalEvent)

### Purpose
Guarantees a single, consistent event schema traverses the entire pipeline.

### Critical Schema Fields

| Field | Type | Required |
|---|---|---|
| event_id | str | Yes |
| timestamp | datetime (UTC) | Yes |
| source | str | Yes |
| event_type | str | Yes |
| host | str | Yes |
| user | str | Yes |
| action | str | Yes |
| result | str | Yes |
| raw_log | str | Yes |

### Test Inputs
- Valid minimal event
- Valid full event (all optional fields populated)
- Event with extra_fields payload

### Execution Steps
```python
from datetime import UTC, datetime
from backend.normalization.models import CanonicalEvent

# Test minimal valid
e = CanonicalEvent(
    event_id="test-001",
    timestamp=datetime.now(UTC),
    source="windows",
    event_type="authentication",
    host="ws01", user="alice",
    resource="ws01", action="logon_failure",
    result="failure", raw_log="raw"
)
print(e.model_dump_json())
```

### Pass Criteria
- ✅ Pydantic validates without error
- ✅ JSON serialisation round-trips correctly
- ✅ All datetime fields are UTC-aware

### Fail Criteria
- ❌ Naive datetime accepted
- ❌ schema_version missing from output
- ❌ extra_fields silently dropped

---

## 4.4 Feature Engineering

### Purpose
Extracts numerical feature vectors from CanonicalEvents for use by the Isolation Forest.

### What Should Be Tested
- Feature extraction for each event type
- Feature vector dimensionality consistency
- Baseline-relative feature computation
- Novel feature detection (features not in baseline)
- Zero-baseline fallback behaviour

### Test Execution
```powershell
python -m pytest tests/unit/features/ -v
```

### Key Features to Validate

| Feature | Source Field | Expected Range |
|---|---|---|
| anomalous_hour | timestamp.hour | 0–23 |
| failed_logon_rate | result=failure count | 0.0–1.0 normalised |
| novel_process_rate | process vs baseline | 0.0–1.0 |
| bytes_out_zscore | bytes_out vs baseline | continuous |
| modbus_register_change | modbus_value delta | continuous |

### Pass Criteria
- ✅ Feature vector dimensionality is constant per entity type
- ✅ Baseline-relative features produce 0.0 for normal events
- ✅ Attack events produce non-zero feature values
- ✅ FeatureRecord JSON round-trips without loss

### Fail Criteria
- ❌ Feature vector contains NaN or Inf
- ❌ Dimensionality changes between events for same entity
- ❌ Feature extraction throws exception on valid CanonicalEvent

---

## 4.5 Isolation Forest (Anomaly Detection)

### Purpose
Scores each event's feature vector for anomalous behaviour relative to the trained baseline model.

### What Should Be Tested
- Model training on clean baseline data
- Inference returns scores in [0, 1]
- Threshold application (is_alert flag)
- Normal events score < threshold
- Attack events score > threshold
- Model serialisation/deserialisation
- Batch inference consistency

### Test Execution
```powershell
python -m pytest tests/unit/detection/ -v
```

### Specific Tests

| Test | Input | Expected |
|---|---|---|
| Normal auth event | Typical hour, typical user | score < 0.5 |
| 20 failed logins | logon_failure × 20 | score > 0.7 |
| Off-hours process | process at 3am, novel | score > 0.6 |
| OT register spike | value=9999 on register 40001 | score > 0.8 |

### Pass Criteria
- ✅ Trained model persists to disk and reloads correctly
- ✅ Inference scores are deterministic for same input
- ✅ DetectionAlert schema_version matches DETECTION_SCHEMA_VERSION constant
- ✅ is_alert flag correctly set for scores above threshold

### Fail Criteria
- ❌ Score outside [0, 1]
- ❌ Non-deterministic scores on identical inputs
- ❌ Model loads from wrong version without error

---

## 4.6 SHAP Explainability

### Purpose
Attributes each anomaly score to specific feature contributions so operators understand why an event was flagged.

### What Should Be Tested
- ExplanationResult produced for every DetectionAlert
- Top features correctly ranked by |shap_value|
- Direction field is "anomaly" or "normal"
- total_abs_shap = sum of |shap_values|
- Feature contributions sum to anomaly_score - expected_value
- Batch explanation consistency
- Storage round-trip

### Test Execution
```powershell
python -m pytest tests/unit/explainability/ -v
```

### Pass Criteria
- ✅ Every alert produces a non-empty ExplanationResult
- ✅ feature_contributions ordered by abs_shap_value descending
- ✅ top_features list matches top N by contribution_rank
- ✅ ExplanationResult JSON round-trips without loss

### Fail Criteria
- ❌ Empty feature_contributions list for a valid alert
- ❌ contribution_pct values do not sum to ~100
- ❌ direction field takes value outside ("anomaly", "normal")

---

## 4.7 MITRE ATT&CK Mapper

### Purpose
Maps SHAP-explained features to MITRE ATT&CK techniques and tactics using an embedded knowledge base.

### What Should Be Tested
- Top SHAP features correctly trigger technique lookups
- Primary technique is the highest-confidence technique
- Multiple techniques mapped for multi-feature anomalies
- Tactic inheritance from technique definition
- Knowledge base version tagged
- MappedAttack JSON round-trip
- Batch mapping consistency

### Test Execution
```powershell
python -m pytest tests/unit/mitre/ -v
```

### Feature → Technique Mapping Examples

| Top Feature | Expected Technique | Expected Tactic |
|---|---|---|
| failed_logon_rate | T1110 (Brute Force) | TA0006 (Credential Access) |
| novel_process | T1059 (Command Execution) | TA0002 (Execution) |
| bytes_out_spike | T1041 (Exfiltration) | TA0010 (Exfiltration) |
| modbus_register_change | T0836 (Modify Controller) | TA0105 (Impair Process) |
| off_hours_access | T1078 (Valid Accounts) | TA0001 (Initial Access) |

### Pass Criteria
- ✅ Every ExplanationResult produces a non-empty MappedAttack
- ✅ Primary technique has highest confidence score
- ✅ All techniques reference valid ATT&CK IDs
- ✅ knowledge_version field populated

### Fail Criteria
- ❌ MappedAttack with zero techniques for a valid explanation
- ❌ Technique ID not prefixed with "T" or "T0"
- ❌ Tactic ID not prefixed with "TA"

---

## 4.8 Attack Graph Builder

### Purpose
Builds a directed graph of TECHNIQUE and ENTITY nodes from multiple MappedAttack objects, enabling multi-alert correlation.

### What Should Be Tested
- GraphNode created for each unique technique × entity combination
- PRECEDES edges created between temporally ordered techniques
- RELATED_TO edges created for same-alert co-occurring techniques
- GraphStatistics accurately reflect graph state
- GraphSnapshot consistent with underlying NetworkX graph
- Graph grows correctly across multiple MappedAttack inputs
- Node observation_count increments on repeated observations

### Test Execution
```powershell
python -m pytest tests/unit/attack_graph/ -v
```

### Pass Criteria
- ✅ Graph is a valid DAG (no cycles) for single-entity sequences
- ✅ node_count equals unique technique × entity combinations
- ✅ GraphSnapshot serialises and loads without loss
- ✅ Adding duplicate technique increments observation_count

### Fail Criteria
- ❌ Cycle introduced in single-entity chronological sequence
- ❌ node_count does not match actual NetworkX node count
- ❌ Two nodes with identical node_id exist in graph

---

## 4.9 Attack Chain Detection

### Purpose
Discovers ordered attack kill-chains (minimum 2 technique steps) within an entity-scoped subgraph.

### What Should Be Tested
- Chains contain minimum MIN_CHAIN_LENGTH (2) steps
- Chains are entity-scoped (no cross-entity mixing)
- ChainEvaluation confidence is [0, 1]
- is_multi_tactic correctly set when chain spans >1 tactic
- is_temporally_ordered correctly set when steps are chronological
- Deduplication removes identical chains (keeps higher confidence)
- Cross-alert temporal chaining works (synthesised PRECEDES edges)

### Test Execution
```powershell
python -m pytest tests/unit/chain_detection/ -v
```

### Pass Criteria
- ✅ Chain with 2+ technique steps detected for multi-alert scenarios
- ✅ ChainEvaluation.confidence in range [0.0, 1.0]
- ✅ ChainReport.chains list is non-empty for attack scenarios
- ✅ Storage round-trip preserves all chain data

### Fail Criteria
- ❌ Chain with single technique step emitted
- ❌ Chain confidence outside [0, 1]
- ❌ Same chain_id appears twice in ChainReport

---

## 4.10 Synthetic Attack Generation

### Purpose
Generates realistic CanonicalEvents that simulate attack scenarios for pipeline validation without requiring live attack traffic.

### What Should Be Tested
- All 10 built-in templates generate without error
- Generated events pass CanonicalEvent Pydantic validation
- Entity substitution correctly replaces {target_host}, {attacker_user}
- synthetic=True flag set in extra_fields
- Deterministic output with fixed seed
- Batch generation works across all templates
- OT template populates modbus_register, modbus_value, modbus_function_code

### Test Execution
```powershell
python -m pytest tests/unit/synthetic_attack/ -v
```

### Template Verification

| Template ID | Domain | Expected Events |
|---|---|---|
| brute_force_auth | auth | 21 |
| credential_stuffing | auth | 31 |
| lateral_movement_smb | network | 9 |
| privilege_escalation_token | process | 3 |
| persistence_scheduled_task | process | 2 |
| command_execution_powershell | process | 4 |
| network_discovery_scan | network | 50 |
| data_exfiltration_http | network | 15 |
| ot_register_manipulation | ot_ics | 17 |
| full_kill_chain_it | it | 26 |

### Pass Criteria
- ✅ All 10 templates generate correct event counts with seed=42
- ✅ Each event has synthetic=True in extra_fields
- ✅ No CanonicalEvent validation errors across all templates

---

## 4.11 Attack Context Generation

### Purpose
Assembles every module's output into a single, deterministic AttackContext — the intelligence package for the Phase 5 LLM Reasoning Agent.

### What Should Be Tested
- Minimal context (alert only) builds without error
- Full context (all inputs) builds without error
- context_id is globally unique
- identity.entity_type and entity_id correctly extracted from EntityKey
- completeness_pct = 33.3% for alert-only input
- completeness_pct = 100.0% when all inputs provided
- Timeline ordered by step_index ascending
- Evidence fields correctly extracted from CanonicalEvents
- OT indicator flags set when modbus fields present
- Storage round-trip preserves all fields
- Filter helpers work correctly

### Test Execution
```powershell
python -m pytest tests/unit/context/ -v
```

### Completeness Matrix

| Inputs Provided | Expected completeness_pct |
|---|---|
| alert only | 33.3% |
| alert + SHAP | 44.4% |
| alert + SHAP + MITRE | 55.6% |
| alert + SHAP + MITRE + chain | 66.7% |
| all inputs | 100.0% |

### Pass Criteria
- ✅ AttackContext.context_id starts with "ctx-"
- ✅ completeness_pct within ±0.1 of expected
- ✅ timeline steps ordered: step_index 0, 1, 2, ...
- ✅ JSON round-trip produces identical completeness_pct
- ✅ load_context() returns same object as build_context()

### Fail Criteria
- ❌ context_id collision across 100 builds
- ❌ Missing components reported as present in completeness
- ❌ Timeline events out of step_index order

---

# SECTION 5 — END-TO-END PIPELINE TESTS

## E2E-001: Normal Behaviour Baseline

**Purpose:** Verify that normal events produce no alerts.

**Input:** Digital Twin events representing typical business-hours activity.

**Steps:**
```python
from backend.synthetic_attack import SyntheticAttackService
from backend.normalization.models import CanonicalEvent
# Use Digital Twin to generate normal events
# Feed through Feature Engine
# Score with trained Isolation Forest
# Assert: is_alert = False for all events
```

**Expected Output:**
- All anomaly_score < 0.5
- No DetectionAlerts generated (is_alert=False)
- No SHAP explanations triggered
- No MITRE mappings

**Validation Criteria:**
- Zero false positive rate on normal baseline data
- Feature vectors within 2 standard deviations of baseline mean

**Failure Indicators:**
- Any is_alert=True on normal events
- anomaly_score consistently > 0.3 on normal events

---

## E2E-002: Brute Force Authentication Attack

**Purpose:** Verify complete pipeline response to credential brute-force.

**Input:** `SyntheticAttackService.generate("brute_force_auth", "ws01", "alice")`

**Steps:**
1. Generate 21 synthetic auth events (20 failures + 1 success)
2. Extract features for entity `user::alice`
3. Score with Isolation Forest
4. Generate SHAP explanation for alert
5. Map to MITRE ATT&CK
6. Add to Attack Graph
7. Detect attack chains
8. Assemble Attack Context

**Expected Output:**

| Stage | Expected |
|---|---|
| Feature Engine | failed_logon_rate feature elevated |
| Isolation Forest | anomaly_score > 0.7, is_alert=True |
| SHAP | failed_logon_rate as top feature |
| MITRE | T1110 (Brute Force), TA0006 (Credential Access) |
| Attack Graph | 1 TECHNIQUE node for T1110 |
| Attack Chain | Length 1 (single technique — chain if followed by lateral movement) |
| Attack Context | completeness_pct ≥ 55.6%, tactic_sequence = ["Credential Access"] |

**Validation Criteria:**
- T1110 appears in MitreSummary.all_technique_ids
- anomaly_score in AttackContext.detection ≥ 0.7

---

## E2E-003: Full Kill Chain Attack

**Purpose:** Verify multi-stage attack produces a coherent kill chain.

**Input:** `SyntheticAttackService.generate("full_kill_chain_it", "ws01", "alice")`

**Steps:**
1. Generate 26 events spanning credential access → lateral movement → execution → exfiltration
2. Feed through full pipeline in timestamp order
3. Verify graph grows across 4 technique families
4. Verify chain detection finds multi-tactic chain

**Expected Output:**

| Stage | Expected |
|---|---|
| MITRE | T1110, T1021.002, T1059.001, T1041 |
| Attack Graph | ≥4 TECHNIQUE nodes |
| Attack Chain | chain_length ≥ 2, is_multi_tactic=True |
| Attack Context | tactic_sequence includes ≥3 distinct tactics |

---

## E2E-004: OT/ICS Attack

**Purpose:** Verify OT-specific event fields propagate through the pipeline.

**Input:** `SyntheticAttackService.generate("ot_register_manipulation", "plc01", "attacker")`

**Steps:**
1. Generate 17 OT events (scan + 2 register write stages)
2. Feed through pipeline
3. Verify OT fields preserved in CanonicalEvent
4. Verify Attack Context evidence.has_ot_indicators=True

**Expected Output:**
- modbus_register, modbus_value in evidence
- has_ot_indicators=True in AttackContext.evidence
- T0836 in MITRE mappings

---

## E2E-005: Slow/Staged Attack (Multi-Session)

**Purpose:** Verify cross-alert chaining across multiple independently processed alerts.

**Input:** Two separate alerts 30 minutes apart for the same entity:
- Alert 1: T1110 (credential brute force)
- Alert 2: T1021 (lateral movement)

**Steps:**
1. Process Alert 1 → MappedAttack → add to Attack Graph
2. Process Alert 2 → MappedAttack → add to same Attack Graph
3. Run Attack Chain Detection on the combined graph
4. Verify chain connects T1110 → T1021

**Expected Output:**
- Chain with 2 steps: T1110 precedes T1021
- chain_length = 2
- is_multi_tactic=True (TA0006 → TA0008)
- duration_seconds ≈ 1800

---

# SECTION 6 — MANUAL TESTING PLAN

## 6.1 How to Manually Validate Each Component

---

### MANUAL-01: Digital Twin

**Run:**
```powershell
python -c "
from backend.digital_twin import DigitalTwin
twin = DigitalTwin()
events = twin.generate_events(count=100)
print(f'Generated {len(events)} events')
types = set(e.event_type for e in events)
print(f'Event types: {types}')
hosts = set(e.host for e in events)
print(f'Hosts: {hosts}')
"
```

**What to observe:**
- `Generated 100 events` should print
- Event types should include ≥3 different values
- Hosts should show multiple distinct values

**What should NOT happen:**
- Exception or traceback
- Single event_type dominating 100% of output
- Any event with `host=None`

**You know it's working when:** Multiple hosts, users, and event types appear in output without errors.

---

### MANUAL-02: Normalization

**Run:**
```powershell
python -c "
from datetime import UTC, datetime
from backend.normalization.models import CanonicalEvent
e = CanonicalEvent(
    event_id='test-001',
    timestamp=datetime.now(UTC),
    source='windows', event_type='authentication',
    host='ws01', user='alice',
    resource='ws01', action='logon_failure',
    result='failure', raw_log='raw',
    windows_event_id=4625, logon_type='network'
)
print(e.model_dump_json(indent=2))
"
```

**What to observe:**
- Valid JSON output with all fields
- timestamp has UTC timezone (`+00:00` suffix)
- schema_version and normalized_at fields present

**What should NOT happen:**
- ValidationError
- Naive datetime (no timezone info)

---

### MANUAL-03: Synthetic Attack Generation

**Run:**
```powershell
python -c "
from backend.synthetic_attack import SyntheticAttackService
svc = SyntheticAttackService(persist=False, seed=42)
for tid in svc.list_templates():
    r = svc.generate(tid, 'host1', 'user1')
    print(f'{tid}: {r.total_events} events')
print('All templates OK')
"
```

**What to observe:**
- 10 lines, one per template
- Total events: brute_force=21, credential_stuffing=31, etc.
- Final line: `All templates OK`

**What should NOT happen:**
- Any exception during generation
- Any template showing 0 events

---

### MANUAL-04: Feature Engine

**Run:**
```powershell
python -c "
from backend.features.service import FeatureService
# Verify service initialises and explain its feature vector structure
svc = FeatureService()
print('Feature service initialised successfully')
print('Feature dimension:', svc.get_feature_dimension())
"
```

**What to observe:**
- Service initialises without error
- Feature dimension printed (typically 40–80)

---

### MANUAL-05: Isolation Forest

**Run:**
```powershell
python -c "
from backend.detection.service import DetectionService
svc = DetectionService()
status = svc.get_model_status()
print('Model status:', status)
"
```

**What to observe:**
- Model status dict printed
- `trained: True` if model exists on disk
- `trained: False` if no baseline trained yet

---

### MANUAL-06: SHAP Explainability

**Run:**
```powershell
python -c "
from backend.explainability.service import ExplainabilityService
svc = ExplainabilityService()
status = svc.get_status()
print('SHAP status:', status)
"
```

**What to observe:**
- Status dict printed without error
- `initialized: True/False` depending on model state

---

### MANUAL-07: MITRE Mapper

**Run:**
```powershell
python -c "
from backend.mitre.knowledge_base import MitreKnowledgeBase
kb = MitreKnowledgeBase()
print('Techniques loaded:', len(kb.get_all_techniques()))
print('Sample T1110:', kb.get_technique('T1110').name)
print('Knowledge version:', kb.version)
"
```

**What to observe:**
- 36+ techniques loaded
- T1110 name: "Brute Force" (or similar)
- Knowledge version string

**What should NOT happen:**
- Exception on `get_technique('T1110')`
- Technique count = 0

---

### MANUAL-08: Attack Context

**Run:**
```powershell
python -c "
from datetime import UTC, datetime
from backend.detection.models import DetectionAlert, EntityKey
from backend.context.service import AttackContextService

alert = DetectionAlert(
    model_id='iso-v1',
    entity_key=EntityKey(entity_type='user', entity_id='alice'),
    event_id='evt-001',
    event_type='authentication', event_source='windows',
    event_timestamp=datetime.now(UTC),
    event_host='ws01', event_user='alice',
    anomaly_score=0.85, raw_if_score=-0.12,
    threshold_used=0.5, is_alert=True,
    feature_dimension=10, raw_feature_values={'failed_logins': 20.0},
    novelty_count=2, baseline_available=True,
)

svc = AttackContextService(persist=False)
ctx = svc.build_context(alert=alert)
s = ctx.to_summary()
print('Context ID:', s['context_id'][:20])
print('Anomaly score:', s['anomaly_score'])
print('Completeness:', s['completeness_pct'], '%')
print('Missing components:', len(ctx.completeness.missing))
"
```

**What to observe:**
- context_id starts with `ctx-`
- anomaly_score = 0.85
- completeness_pct = 33.3 (3 components guaranteed: detection, behavioral, statistical)
- Missing components = 6

---

# SECTION 7 — AUTOMATED VALIDATION

## 7.1 Run Full Automated Test Suite

```powershell
# Full suite
python -m pytest tests/ --no-cov -q -p no:cacheprovider

# With verbose output
python -m pytest tests/ -v

# Module-specific
python -m pytest tests/unit/context/ -v
python -m pytest tests/unit/chain_detection/ -v
python -m pytest tests/unit/attack_graph/ -v
python -m pytest tests/unit/mitre/ -v
python -m pytest tests/unit/synthetic_attack/ -v
```

## 7.2 Test Coverage by Module

| Module | Tests | Coverage Area |
|---|---|---|
| Digital Twin | varies | Generation, entity diversity |
| Normalization | varies | Schema, field mapping |
| Feature Engine | varies | Vector extraction, dimensionality |
| Detection | 97 | Training, inference, threshold, storage |
| Explainability | 73 | SHAP, attribution, storage |
| MITRE | 88 | Mapping, knowledge base, storage |
| Attack Graph | varies | Node/edge creation, statistics |
| Chain Detection | 106 | Path finding, evaluation, deduplication |
| Synthetic Attack | 68 | Template generation, entity substitution |
| Attack Context | 82 | Assembly, completeness, storage |
| **Total** | **1541** | |

## 7.3 Schema Validation Tests

```python
# JSON round-trip for every model
for model in [AttackContext, AttackChain, MappedAttack, ExplanationResult]:
    instance = create_test_instance(model)
    reloaded = model.model_validate_json(instance.model_dump_json())
    assert reloaded == instance
```

## 7.4 Contract Tests

```python
# Verify public API contracts across module boundaries
# DetectionAlert → ExplanationResult
# ExplanationResult → MappedAttack
# MappedAttack → AttackGraph
# AttackGraph → AttackChain
# AttackChain → AttackContext
```

---

# SECTION 8 — ATTACK SIMULATION TESTS

## ATTACK-01: Normal Behaviour (Baseline)

| Field | Value |
|---|---|
| Objective | Confirm zero false positives on normal activity |
| Template | Digital Twin default |
| Actions | Typical 9-5 logons, standard process launches, normal network |
| Expected Feature Changes | All features within 2σ of baseline |
| Expected Isolation Forest | score < 0.3, is_alert=False |
| Expected SHAP | Not triggered |
| Expected MITRE | Not triggered |
| Expected Graph Growth | None |
| Expected Chain | None |
| Expected Context | Not generated |

---

## ATTACK-02: Credential Brute Force (T1110)

| Field | Value |
|---|---|
| Objective | Validate auth anomaly detection pipeline |
| Template | `brute_force_auth` |
| Actions | 20 failed logons then 1 success |
| Expected Feature Changes | failed_logon_rate → 0.95+, off_hours if 3am |
| Expected Isolation Forest | score > 0.70, is_alert=True |
| Expected SHAP | failed_logon_rate = top feature, direction=anomaly |
| Expected MITRE | T1110, TA0006 (Credential Access) |
| Expected Graph Growth | 1 new TECHNIQUE node T1110::user::alice |
| Expected Chain | Single-step or extends if lateral movement follows |
| Expected Context | completeness ≥ 55.6%, identity.user=alice |

---

## ATTACK-03: PowerShell Abuse (T1059.001)

| Field | Value |
|---|---|
| Objective | Validate process anomaly detection |
| Template | `command_execution_powershell` |
| Actions | powershell.exe with -EncodedCommand, network callback |
| Expected Feature Changes | novel_process_rate elevated, off-hours, cmd_length_anomaly |
| Expected Isolation Forest | score > 0.65 |
| Expected SHAP | novel_process, command_line_entropy as top features |
| Expected MITRE | T1059.001 (PowerShell), TA0002 (Execution) |
| Expected Graph Growth | T1059.001 node added |
| Expected Chain | Links to prior T1110 if same entity |
| Expected Context | has_process_indicators=True, command_lines populated |

---

## ATTACK-04: Lateral Movement via SMB (T1021.002)

| Field | Value |
|---|---|
| Objective | Validate network anomaly detection |
| Template | `lateral_movement_smb` |
| Actions | SMB connection to new host on port 445, file copy |
| Expected Feature Changes | novel_dst_ip, novel_port_445, bytes_out spike |
| Expected Isolation Forest | score > 0.60 |
| Expected SHAP | novel_dst_ip, smb_port as top features |
| Expected MITRE | T1021.002 (Remote Services: SMB), TA0008 (Lateral Movement) |
| Expected Graph Growth | T1021.002 TECHNIQUE node; PRECEDES edge from T1110 |
| Expected Chain | 2-step chain: T1110 → T1021.002, is_multi_tactic=True |
| Expected Context | tactic_sequence = ["Credential Access", "Lateral Movement"] |

---

## ATTACK-05: Data Exfiltration (T1041)

| Field | Value |
|---|---|
| Objective | Validate outbound data anomaly detection |
| Template | `data_exfiltration_http` |
| Actions | 10 file reads followed by 5 large HTTP POSTs to external IP |
| Expected Feature Changes | bytes_out_zscore very high, novel_external_ip |
| Expected Isolation Forest | score > 0.80 |
| Expected SHAP | bytes_out_zscore, novel_dst_ip as top features |
| Expected MITRE | T1041 (Exfiltration Over C2), TA0010 (Exfiltration) |
| Expected Graph Growth | T1041 node, PRECEDES from T1059 if chained |
| Expected Chain | 3–4 step kill chain if full_kill_chain_it template |
| Expected Context | dst_ips=[185.220.101.99], has_network_indicators=True |

---

## ATTACK-06: OT Register Manipulation (T0836)

| Field | Value |
|---|---|
| Objective | Validate OT/ICS-specific detection path |
| Template | `ot_register_manipulation` |
| Actions | Modbus scan → write register 40001 value=9999 → write safety relay=0 |
| Expected Feature Changes | modbus_register_change, anomalous_modbus_value |
| Expected Isolation Forest | score > 0.85 (critical infrastructure pattern) |
| Expected SHAP | modbus_register_change as top feature |
| Expected MITRE | T0836 (Modify Controller Tasking), TA0105 |
| Expected Graph Growth | T0836 node with OT entity type |
| Expected Chain | OT-scoped chain |
| Expected Context | has_ot_indicators=True, modbus_registers=[40001, 40010] |

---

## ATTACK-07: Full Kill Chain (Multi-Tactic)

| Field | Value |
|---|---|
| Objective | Validate end-to-end multi-tactic chain formation |
| Template | `full_kill_chain_it` |
| Actions | BruteForce → SMB → PowerShell → Exfil (26 events) |
| Expected Feature Changes | Progressive across all 4 categories |
| Expected Isolation Forest | Multiple alerts across stages |
| Expected SHAP | Different top features per stage |
| Expected MITRE | T1110, T1021.002, T1059.001, T1041 |
| Expected Graph Growth | 4+ TECHNIQUE nodes, PRECEDES edges between them |
| Expected Chain | chain_length≥4, is_multi_tactic=True, 4 tactics |
| Expected Context | completeness 100% if all enrichments provided; tactic_sequence covers all 4 tactics |

---

# SECTION 9 — NEGATIVE TESTS

## NEG-01: Broken CanonicalEvent (Missing Required Fields)

```python
from pydantic import ValidationError
with pytest.raises(ValidationError):
    CanonicalEvent(event_id="x")  # Missing all required fields
```
**Expected:** `ValidationError` raised immediately.

## NEG-02: Wrong Timestamp (Naive DateTime)

```python
from datetime import datetime
event = CanonicalEvent(..., timestamp=datetime.now())  # naive, no UTC
# Expected: Should raise ValidationError or coerce to UTC
```

## NEG-03: Duplicate Event IDs

```python
events = [make_event(event_id="same-id") for _ in range(5)]
# Feed through pipeline
# Expected: Pipeline must not crash; deduplication policy is log-based
```

## NEG-04: Out-of-Order Events (Future Timestamps)

```python
event = CanonicalEvent(..., timestamp=datetime(2099, 1, 1, tzinfo=UTC))
# Expected: Accepted (schema allows any valid datetime), logged as anomalous timestamp
```

## NEG-05: Empty Feature Vector

```python
feature_record = FeatureRecord(feature_vector={})
# Expected: Detection service raises or skips with warning
```

## NEG-06: Corrupted JSONL Storage Line

```python
# Write invalid JSON to a JSONL file, then load
# Expected: Malformed line skipped, valid lines loaded, errors=N logged
```

## NEG-07: Missing Host Field

```python
event = CanonicalEvent(..., host="", ...)
# Expected: Accepted (empty string is valid), but may produce empty entity_key
```

## NEG-08: Anomaly Score Out of Range

```python
# If scorer returns value outside [0,1], sigmoid must clamp it
alert = DetectionAlert(..., anomaly_score=1.5)
# Expected: ValidationError from Pydantic (ge=0.0, le=1.0 constraint)
```

## NEG-09: Attack Graph — No Mapped Techniques

```python
mapped = MappedAttack(..., techniques=[])
graph_builder.add_mapped_attack(mapped)
# Expected: No nodes added to graph, no exception
```

## NEG-10: Attack Context — None Alert (Required Input)

```python
from backend.context.exceptions import InsufficientInputError
with pytest.raises(InsufficientInputError):
    AttackContextBuilder().build(alert=None)
```
**Expected:** `InsufficientInputError` raised immediately.

---

# SECTION 10 — PERFORMANCE TESTS

## 10.1 Throughput Benchmarks

```powershell
python -c "
import time
from backend.synthetic_attack import SyntheticAttackService

svc = SyntheticAttackService(persist=False, seed=0)
start = time.perf_counter()
r = svc.generate('network_discovery_scan', 'host1', 'user1')
events = svc.get_canonical_events(r)
elapsed = time.perf_counter() - start
print(f'{len(events)} events in {elapsed:.3f}s = {len(events)/elapsed:.0f} events/sec')
"
```

### Target Performance Table

| Event Rate | Max Latency per Event | Max Memory | Status |
|---|---|---|---|
| 10 events/sec | < 100ms | < 500MB | Must pass |
| 100 events/sec | < 50ms | < 1GB | Must pass |
| 500 events/sec | < 20ms | < 2GB | Should pass |
| 1000 events/sec | < 10ms | < 4GB | Stretch goal |

## 10.2 Feature Extraction Speed

```python
import time
from backend.features.service import FeatureService

svc = FeatureService()
events = generate_n_events(1000)
start = time.perf_counter()
records = [svc.extract(e) for e in events]
elapsed = time.perf_counter() - start
print(f"Feature extraction: {1000/elapsed:.0f} events/sec")
# Target: > 500 events/sec
```

## 10.3 Isolation Forest Inference Speed

```python
import time
vectors = generate_n_feature_vectors(1000)
start = time.perf_counter()
alerts = scorer.score_batch(vectors)
elapsed = time.perf_counter() - start
print(f"IF inference: {1000/elapsed:.0f} vectors/sec")
# Target: > 1000 vectors/sec
```

## 10.4 SHAP Explanation Speed

```python
# SHAP is inherently slower than Isolation Forest
# Target: < 1 second per explanation for TreeExplainer
# Batch should be linear: 100 explanations in < 5 seconds
```

## 10.5 Context Assembly Speed

```python
import time
start = time.perf_counter()
ctx = svc.build_context(alert=alert, chain=chain, explanation=explanation)
elapsed = time.perf_counter() - start
print(f"Context assembly: {elapsed*1000:.1f}ms")
# Target: < 100ms for full context assembly
```

---

# SECTION 11 — EDGE CASES

## 11.1 Digital Twin Edge Cases
- Single entity (1 host, 1 user): verify no cross-contamination
- Zero events requested: should return empty list, not crash
- All OT events: all event_type = "ot_modbus"

## 11.2 Normalization Edge Cases
- Event with all optional fields None: valid
- Event with very long command_line (>10,000 chars): must not truncate
- Event with Unicode in user/host: must preserve
- Modbus function_code as string "6" vs integer 6: verify coercion

## 11.3 Feature Engine Edge Cases
- First event for entity (no baseline): all baseline-relative features = 0
- 3am vs 3pm: off_hours_access feature changes
- Port 80 vs port 4444: known vs novel port detection

## 11.4 Isolation Forest Edge Cases
- All-zero feature vector: must score, not crash
- Single training sample: model must still train (not divide by zero)
- Feature vector with one NaN: must be caught before inference

## 11.5 SHAP Edge Cases
- Zero features contributing: total_abs_shap = 0 (valid)
- All features contributing equally: all contribution_pct = 100/n
- Model not initialised: ExplainerNotInitializedError raised

## 11.6 MITRE Edge Cases
- SHAP features with no matching technique: graceful fallback
- Empty top_shap_features list: returns MappedAttack with techniques=[]
- OT feature → T0836 correctly: not mapped to IT techniques

## 11.7 Attack Graph Edge Cases
- Single MappedAttack with one technique: 1 node, 0 edges
- Same technique re-observed: observation_count increments, no duplicate node
- 50+ techniques on same entity: graph remains consistent

## 11.8 Attack Chain Edge Cases
- Single-node graph: no chains (< MIN_CHAIN_LENGTH)
- Fully connected graph (all techniques related): DFS explores all paths
- Chain with identical tactic sequence: is_multi_tactic=False

## 11.9 Attack Context Edge Cases
- All optional inputs None: completeness_pct = 33.3%
- Chain with 0 nodes: timeline=[], chain.chain_length=0
- Events list empty: all evidence indicators False
- Graph with 0 statistics: all counts = 0

---

# SECTION 12 — SUCCESS CRITERIA

## 12.1 Measurable Acceptance Criteria

| Criterion | Target | Measurement |
|---|---|---|
| Test suite pass rate | 100% (1541/1541) | `pytest tests/ -q` |
| Normal event false positive rate | < 5% | Score normal events |
| Brute-force detection rate | > 90% | Score attack events |
| MITRE technique accuracy | ≥ 80% for known patterns | Manual verification |
| Feature extraction speed | > 500 events/sec | Benchmark |
| Context assembly latency | < 100ms | Timer |
| Context completeness (full input) | 100% | `completeness_pct` |
| Pipeline completion (no crash) | 100% | E2E test runs |
| JSON schema validity | 100% | Round-trip tests |
| Storage round-trip fidelity | 100% | Load = Save |
| Graph consistency (no duplicate nodes) | 100% | Node count check |
| Chain confidence range | 100% in [0,1] | Assertion |
| Cold-start (empty data dir) | 100% boot without crash | Fresh dir test |
| Regression stability | 0 new failures | `pytest` after each change |

---

# SECTION 13 — TEST RESULT TEMPLATES

## 13.1 Unit Test Result Table

| Test ID | Module | Description | Expected | Actual | Status | Notes |
|---|---|---|---|---|---|---|
| UT-DT-001 | Digital Twin | Generate 100 events | 100 events, 3+ types | | ⬜ | |
| UT-NORM-001 | Normalization | Valid CanonicalEvent | No ValidationError | | ⬜ | |
| UT-FEAT-001 | Feature Engine | Extract auth features | dim=consistent | | ⬜ | |
| UT-DET-001 | Detection | Train on clean data | model saved to disk | | ⬜ | |
| UT-DET-002 | Detection | Score normal event | score < 0.5 | | ⬜ | |
| UT-DET-003 | Detection | Score attack event | score > 0.7 | | ⬜ | |
| UT-SHAP-001 | SHAP | Explain alert | top_features non-empty | | ⬜ | |
| UT-MITRE-001 | MITRE | Map T1110 features | technique_id=T1110 | | ⬜ | |
| UT-GRAPH-001 | Attack Graph | Add mapped attack | 1 new node | | ⬜ | |
| UT-CHAIN-001 | Chain Detection | 2-alert chain | chain_length≥2 | | ⬜ | |
| UT-SYN-001 | Synthetic | brute_force_auth | 21 events | | ⬜ | |
| UT-CTX-001 | Context | Alert-only build | completeness=33.3% | | ⬜ | |
| UT-CTX-002 | Context | Full build | completeness=100% | | ⬜ | |

## 13.2 E2E Test Result Table

| Test ID | Scenario | Pipeline Stages | Expected Outcome | Status | Evidence |
|---|---|---|---|---|---|
| E2E-001 | Normal behaviour | All | 0 alerts | ⬜ | |
| E2E-002 | Brute force | All | T1110 in context | ⬜ | |
| E2E-003 | Full kill chain | All | 4-tactic chain | ⬜ | |
| E2E-004 | OT attack | All | has_ot_indicators=True | ⬜ | |
| E2E-005 | Slow attack | All | Cross-alert chain | ⬜ | |

## 13.3 Performance Result Table

| Test ID | Event Rate | Avg Latency | Peak Memory | CPU% | Status |
|---|---|---|---|---|---|
| PERF-001 | 10 evt/s | | | | ⬜ |
| PERF-002 | 100 evt/s | | | | ⬜ |
| PERF-003 | 500 evt/s | | | | ⬜ |
| PERF-004 | 1000 evt/s | | | | ⬜ |

## 13.4 Negative Test Result Table

| Test ID | Scenario | Expected Behaviour | Actual Behaviour | Status |
|---|---|---|---|---|
| NEG-001 | Broken CanonicalEvent | ValidationError | | ⬜ |
| NEG-002 | Naive datetime | Error or UTC coerce | | ⬜ |
| NEG-003 | Duplicate event IDs | No crash | | ⬜ |
| NEG-004 | Future timestamp | Accepted, logged | | ⬜ |
| NEG-005 | Empty feature vector | Skip with warning | | ⬜ |
| NEG-006 | Corrupted JSONL | Skip bad line | | ⬜ |
| NEG-007 | Missing host | Accepted, empty string | | ⬜ |
| NEG-008 | Score out of range | Clamped or ValidationError | | ⬜ |
| NEG-009 | No techniques in graph | No nodes added | | ⬜ |
| NEG-010 | None alert in context | InsufficientInputError | | ⬜ |

---

# SECTION 14 — FINAL ACCEPTANCE CHECKLIST

## 14.1 Production Readiness Checklist

### Phase 1 — Foundation

- [ ] **1.1 Repository Foundation**: Project structure correct, config loads, shared utilities importable
- [ ] **1.2 Digital Twin**: Generates realistic multi-type events for all entity categories
- [ ] **1.3 Log Normalization**: CanonicalEvent schema validates 100% of generated events

### Phase 2 — Behavioral Intelligence

- [ ] **2.1 Baseline Generator**: EntityBaseline built from historical data, persists to disk
- [ ] **2.2 Feature Engine**: Feature vectors consistent, dimensionality stable, no NaN/Inf
- [ ] **2.3 Metrics Engine**: Entity-level statistical metrics computed and stored
- [ ] **2.4 Isolation Forest**: Trained model persists, normal events score < threshold, attack events score > threshold

### Phase 3 — Threat Intelligence

- [ ] **3.2 SHAP Explainability**: Every alert produces ExplanationResult with non-empty feature_contributions
- [ ] **3.3 MITRE ATT&CK Mapper**: Feature → technique mapping correct for brute force, execution, exfiltration, OT scenarios
- [ ] **3.4 Attack Graph Builder**: Multi-alert graph grows correctly, no duplicate nodes, statistics accurate
- [ ] **3.5 Attack Chain Detection**: Multi-step kill chains detected, chain_length ≥ 2, is_multi_tactic correct
- [ ] **3.X Synthetic Attack Generation**: All 10 templates generate correct event counts, events pass validation

### Phase 4 — Context Assembly

- [ ] **4.1 Attack Context Generation**: Full context builds at 100% completeness, all enrichments preserved, storage round-trip fidelity

### System-Level

- [ ] **Full test suite**: 1541 tests pass, 0 failures (`pytest tests/ -q`)
- [ ] **Cold-start**: Empty `data/` directory boots all services without error
- [ ] **JSON round-trip**: Every model serialises and deserialises without data loss
- [ ] **Regression stability**: Repeated runs produce identical outputs for deterministic scenarios
- [ ] **No circular imports**: All modules import cleanly in any order

### Documentation

- [ ] `docs/architecture.md` — reflects current module set
- [ ] `docs/attack_chain_architecture.md` — Module 3.5 documented
- [ ] `docs/attack_context_architecture.md` — Module 4.1 documented
- [ ] `antigravityreferencefiles/QUICK_REF` — current status accurate
- [ ] `antigravityreferencefiles/TASK_HANDOVER` — last session recorded

### Sign-off

| Role | Name | Signature | Date |
|---|---|---|---|
| QA Engineer | | | |
| Cybersecurity Evaluator | | | |
| Lead Developer | | | |

---

> **GO / NO-GO Decision:** All checkboxes must be ticked before the project advances to Phase 5 (LLM Reasoning Agent).
