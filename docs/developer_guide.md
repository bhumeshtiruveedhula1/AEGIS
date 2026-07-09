# CyberShield — Developer Guide

**Operation AEGIS · Phases 1–4.1 Complete**
**Document status:** Official · Based on current implementation only

---

## Contents

1. [Environment Setup](#1-environment-setup)
2. [Project Structure](#2-project-structure)
3. [Implemented Modules](#3-implemented-modules)
4. [Development Workflow](#4-development-workflow)
5. [Coding Standards](#5-coding-standards)
6. [Testing Guide](#6-testing-guide)
7. [Adding a New Module](#7-adding-a-new-module)
8. [Module Contract Reference](#8-module-contract-reference)
9. [Configuration Reference](#9-configuration-reference)
10. [Troubleshooting](#10-troubleshooting)
11. [Known Gotchas](#11-known-gotchas)

---

## 1. Environment Setup

### Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Python | 3.11+ | Runtime (3.12 may have dep conflicts) |
| Git | 2.40+ | Version control |
| Docker Desktop | 4.x | Optional — only for live container telemetry |

### First-Time Setup (Windows)

```powershell
# Clone and enter project
git clone <repository-url> cybershield
cd cybershield

# Create virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install all dependencies
pip install -e ".[dev]"

# Confirm 1542 tests pass
python -m pytest tests/ --no-cov -q -p no:cacheprovider
```

**Expected final line:**
```
1542 passed in XX.XXs
```

### Daily Session Start

```powershell
cd C:\Users\<you>\Desktop\cyber-et\cybershield
.\.venv\Scripts\Activate.ps1
python -m pytest tests/ --no-cov -q -p no:cacheprovider   # confirm baseline clean
```

---

## 2. Project Structure

```
cybershield/
│
├── backend/                     ← Python application package
│   ├── core/                    ← Cross-cutting infrastructure (no upstream deps)
│   │   ├── config.py            ← Settings (Pydantic BaseSettings, env vars)
│   │   ├── constants.py         ← Project-wide constants
│   │   ├── logging.py           ← Structured logging (structlog)
│   │   ├── exceptions.py        ← CyberShieldError base + hierarchy
│   │   └── health.py            ← Health check primitives
│   │
│   ├── shared/                  ← Shared types, base models, utilities
│   │   ├── models.py            ← CyberShieldBaseModel (all models inherit this)
│   │   └── utils/
│   │       └── id_utils.py      ← generate_id(), is_valid_id()
│   │
│   ├── digital_twin/            ← Module 1.2 — Simulated infrastructure
│   ├── normalization/           ← Module 1.3 — CanonicalEvent schema + pipeline
│   ├── baseline/                ← Module 2.1 — EntityBaseline builder
│   ├── features/                ← Module 2.2 — Feature vector extraction
│   ├── metrics/                 ← Module 2.3 — Entity-level metrics
│   ├── detection/               ← Module 2.4 — Isolation Forest anomaly detection
│   ├── explainability/          ← Module 3.2 — SHAP feature attribution
│   ├── mitre/                   ← Module 3.3 — ATT&CK technique mapping
│   ├── attack_graph/            ← Module 3.4 — Attack graph builder
│   ├── chain_detection/         ← Module 3.5 — Kill-chain discovery
│   ├── synthetic_attack/        ← Module 3.X — Synthetic attack event generation
│   ├── context/                 ← Module 4.1 — Attack context assembly
│   │
│   ├── llm/                     ← Module 5.1 — ⏳ NOT IMPLEMENTED
│   ├── response/                ← Module 5.2 — ⏳ NOT IMPLEMENTED
│   ├── dashboard/               ← ⏳ NOT IMPLEMENTED
│   └── api/                     ← FastAPI application layer
│       ├── app.py               ← Application factory (create_app)
│       ├── dependencies.py      ← Dependency injection
│       ├── middleware.py        ← Request ID + logging
│       └── routes/              ← API route handlers
│
├── tests/
│   ├── conftest.py              ← Shared fixtures
│   └── unit/                   ← All unit tests (1542 total)
│       ├── detection/           ← 97 tests
│       ├── explainability/      ← 73 tests
│       ├── mitre/               ← 88 tests
│       ├── chain_detection/     ← 106 tests
│       ├── synthetic_attack/    ← 68 tests
│       └── context/             ← 82 tests
│
├── data/                        ← Runtime data (gitignored — auto-created)
│   ├── normalized/              ← CanonicalEvent JSONL output
│   ├── baseline/                ← EntityBaseline per-entity JSON
│   ├── features/                ← Feature vector JSONL
│   ├── metrics/                 ← Metric snapshots
│   ├── detection/               ← Trained Isolation Forest .pkl + metadata
│   ├── explanations/            ← SHAP ExplanationResult JSONL + index
│   ├── mitre/                   ← MappedAttack JSONL + index
│   ├── attack_graph/            ← GraphSnapshot JSONL + index
│   ├── chain_detection/         ← AttackChain JSONL + index
│   ├── synthetic/               ← Synthetic attack executions + reports
│   └── context/                 ← AttackContext JSONL + index
│
└── docs/                        ← Documentation
    ├── Developer_Startup_Manual.md
    ├── developer_guide.md       ← (this file)
    ├── SOFTWARE_TEST_PLAN.md    ← Complete STP for all modules
    ├── architecture.md
    ├── detection_architecture.md
    ├── attack_chain_architecture.md
    ├── attack_context_architecture.md
    ├── attack_graph_architecture.md
    └── mitre_architecture.md
```

---

## 3. Implemented Modules

### Module Status

| Phase | Module | Package | Key Class | Tests |
|---|---|---|---|---|
| 1.2 | Digital Twin | `backend/digital_twin/` | `DigitalTwin` | — |
| 1.3 | Normalization | `backend/normalization/` | `CanonicalEvent`, `NormalizationPipeline` | — |
| 2.1 | Baseline | `backend/baseline/` | `BaselineService` | — |
| 2.2 | Features | `backend/features/` | `FeatureService` | — |
| 2.3 | Metrics | `backend/metrics/` | `MetricsEngine` | — |
| 2.4 | Detection | `backend/detection/` | `DetectionService`, `DetectionAlert` | 97 |
| 3.2 | SHAP | `backend/explainability/` | `ExplainabilityService`, `ExplanationResult` | 73 |
| 3.3 | MITRE | `backend/mitre/` | `MitreService`, `MappedAttack` | 88 |
| 3.4 | Attack Graph | `backend/attack_graph/` | `AttackGraphService`, `AttackGraph` | — |
| 3.5 | Chain Detection | `backend/chain_detection/` | `ChainDetectionService`, `AttackChain` | 106 |
| 3.X | Synthetic Attack | `backend/synthetic_attack/` | `SyntheticAttackService` | 68 |
| 4.1 | Context | `backend/context/` | `AttackContextService`, `AttackContext` | 82 |

### Data Flow

```
DigitalTwin / SyntheticAttackService
         │
         ▼  raw events
NormalizationPipeline  →  CanonicalEvent  (data/normalized/)
         │
         ├──► BaselineService    →  EntityBaseline   (data/baseline/)
         │
         └──► FeatureService     →  FeatureRecord    (data/features/)
                    │
                    ▼
              DetectionService  →  DetectionAlert   (data/detection/)
                    │
                    ▼
          ExplainabilityService →  ExplanationResult (data/explanations/)
                    │
                    ▼
              MitreService      →  MappedAttack     (data/mitre/)
                    │
                    ▼
          AttackGraphService    →  AttackGraph      (data/attack_graph/)
                    │
                    ▼
       ChainDetectionService    →  AttackChain      (data/chain_detection/)
                    │
                    ▼
        AttackContextService    →  AttackContext    (data/context/)
                    │
                    ▼
         ⏳ LLM Reasoning Agent  (Phase 5 — not yet implemented)
```

---

## 4. Development Workflow

### Session Start

```powershell
.\.venv\Scripts\Activate.ps1
python -m pytest tests/ --no-cov -q -p no:cacheprovider
# Must show: 1542 passed
```

### Making Changes

```powershell
# After each code change, run affected module tests
python -m pytest tests/unit/context/ --no-cov -q

# Before committing, run full suite
python -m pytest tests/ --no-cov -q -p no:cacheprovider

# Commit (--no-verify bypasses detect-secrets which needs baseline update)
git add .
git commit --no-verify -m "feat(module): description"
```

### Commit Message Format

```
feat(module-4.1): Attack Context Generation - deterministic assembly
fix(context): fix entity_key parsing for EntityKey model
test(context): add 82 unit tests for context module
docs: update SOFTWARE_TEST_PLAN with all modules
```

### Pre-commit Hooks

Hooks run on `git commit` (use `--no-verify` to bypass during development):
- `ruff` — lint and auto-fix
- `ruff-format` — format check
- `detect-secrets` — block committing secrets

---

## 5. Coding Standards

### Python Style

- **Python 3.11+** — type annotations on every function
- **Imports** — absolute only: `from backend.core.config import get_settings`
- **Docstrings** — module-level docstring required on every file
- **Line length** — 100 chars (configured in `pyproject.toml`)

### Naming

| Element | Convention | Example |
|---------|-----------|---------|
| Files | `snake_case.py` | `attack_graph.py` |
| Classes | `PascalCase` | `AttackContextBuilder` |
| Functions | `snake_case` | `build_context()` |
| Constants | `UPPER_SNAKE_CASE` | `CONTEXT_SCHEMA_VERSION` |
| Schema versions | `"X.Y.Z"` string | `"1.0.0"` |

### Module Dependency Rules

```
backend.core         ← NO dependencies on backend.*
backend.shared       ← only imports from backend.core
backend.[module]     ← imports from backend.core and backend.shared only
                        NEVER imports from another backend.[module]
backend.api          ← may import from any backend.*
backend.context      ← reads (never writes) all upstream module outputs
```

**Never cross-import between modules at module level.** Pass data via function arguments or through the service layer.

### Pydantic Model Rules

Every model must:
1. Inherit from `CyberShieldBaseModel` (from `backend.shared.models`)
2. Have a `schema_version` field defaulting to the module constant
3. Use `model_config = ConfigDict(protected_namespaces=())` if it has a `model_id` field
4. Be fully JSON-serialisable (all fields must round-trip through `model_dump_json()`)

```python
from backend.shared.models import CyberShieldBaseModel
from backend.shared.utils.id_utils import generate_id

MY_SCHEMA_VERSION = "1.0.0"

class MyModel(CyberShieldBaseModel):
    model_config = ConfigDict(protected_namespaces=())  # if has model_id
    record_id: str = Field(default_factory=lambda: f"rec-{generate_id()}")
    schema_version: str = Field(default=MY_SCHEMA_VERSION)
    model_id: str
    ...
```

### Storage Pattern

All modules use the **identical** atomic storage pattern:

```
data/<module>/
├── <records>_YYYY-MM-DD.jsonl    ← append-only, date-partitioned
└── index/
    └── <record_id>.json           ← atomic: write .tmp then os.replace()
```

```python
# Atomic write (correct pattern)
tmp = path.with_suffix(".tmp")
tmp.write_text(content, encoding="utf-8")
tmp.replace(path)  # atomic on all platforms

# Thread safety: per-file threading.Lock
```

**Do NOT invent a different persistence strategy.**

### Exception Hierarchy

```
CyberShieldError (backend.core.exceptions)
└── [Module]Error            ← base for each module
    ├── [Module]StorageError
    ├── [Module]SchemaError
    └── ...
```

Every exception must accept a `context: dict` kwarg for structured logging.

---

## 6. Testing Guide

### Running Tests

```powershell
# Full suite (use this before every commit)
python -m pytest tests/ --no-cov -q -p no:cacheprovider

# Single module
python -m pytest tests/unit/context/ -v

# Single test
python -m pytest tests/unit/context/test_context.py::TestAttackContextBuilder::test_full_build -v

# With output (useful for debugging)
python -m pytest tests/unit/context/ -v -s
```

### Test File Structure

Every module test directory must have:
```
tests/unit/<module>/
├── __init__.py
├── conftest.py       ← shared fixtures (make_<model>, svc, store fixtures)
└── test_<module>.py  ← grouped into classes by component
```

### Writing Tests — Conventions

```python
class TestMyComponent:
    """Group tests by class — one class per component/layer."""

    def test_builds_correctly(self, my_fixture) -> None:
        """Descriptive names — what behaviour, what inputs, what outcome."""
        result = MyComponent().build(input=my_fixture)
        assert result.field == expected_value

    def test_raises_on_none_input(self) -> None:
        """Negative tests in same class."""
        with pytest.raises(InsufficientInputError):
            MyComponent().build(input=None)
```

### conftest.py Conventions

```python
# Make factory functions for complex objects (not just fixtures)
# so tests can call them directly with custom params

def make_alert(entity_type="user", entity_id="alice", anomaly_score=0.85) -> DetectionAlert:
    return DetectionAlert(
        entity_key=EntityKey(entity_type=entity_type, entity_id=entity_id),
        ...
    )

@pytest.fixture()
def alert() -> DetectionAlert:
    return make_alert()
```

### Schema Version Tests

Every module must include a schema version round-trip test:

```python
def test_json_round_trip(self, my_model_instance) -> None:
    reloaded = MyModel.model_validate_json(my_model_instance.model_dump_json())
    assert reloaded.record_id == my_model_instance.record_id

def test_schema_version_constant(self) -> None:
    assert MY_SCHEMA_VERSION == "1.0.0"
```

---

## 7. Adding a New Module

When implementing a new pipeline module (e.g., `backend/llm/`):

### Step 1: Create Package Structure

```powershell
New-Item -ItemType Directory -Force "backend\llm" | Out-Null
```

Create these files **in this order** (dependencies first):
```
backend/llm/
├── exceptions.py      ← LlmError, LlmStorageError, etc.
├── models.py          ← Pure Pydantic models only
├── [logic].py         ← Single-responsibility logic layer(s)
├── storage.py         ← ContextStore-pattern storage
├── service.py         ← Single public orchestration entry point
└── __init__.py        ← Full __all__ export
```

### Step 2: exceptions.py Template

```python
"""backend.llm.exceptions — LLM Exception Hierarchy."""
from backend.core.exceptions import CyberShieldError

class LlmError(CyberShieldError):
    """Base class for LLM errors."""

class LlmStorageError(LlmError):
    """Raised on I/O failure."""
```

### Step 3: models.py Template

```python
"""backend.llm.models — LLM Data Models."""
from backend.shared.models import CyberShieldBaseModel
from backend.shared.utils.id_utils import generate_id

LLM_SCHEMA_VERSION = "1.0.0"

class LlmResult(CyberShieldBaseModel):
    result_id: str = Field(default_factory=lambda: f"llm-{generate_id()}")
    schema_version: str = Field(default=LLM_SCHEMA_VERSION)
    ...
```

### Step 4: service.py Template

```python
"""backend.llm.service — LLM Service (single public entry point)."""
class LlmService:
    def __init__(self, *, store_dir=None, persist=True):
        settings = get_settings()
        self._store = LlmStore(store_dir=store_dir or settings.data_dir / "llm")
        ...

    def process(self, ctx: AttackContext) -> LlmResult:
        ...
```

### Step 5: Create Tests

```powershell
New-Item -ItemType Directory -Force "tests\unit\llm" | Out-Null
New-Item -Force "tests\unit\llm\__init__.py" | Out-Null
```

Create `tests/unit/llm/conftest.py` + `tests/unit/llm/test_llm.py`.

### Step 6: Verify

```powershell
python -m pytest tests/unit/llm/ --no-cov -q
python -m pytest tests/ --no-cov -q   # full regression — must still pass
```

---

## 8. Module Contract Reference

### CanonicalEvent (Module 1.3) — Foundation Schema

**Every event in the system is a CanonicalEvent.** All modules consume it.

```python
from backend.normalization.models import CanonicalEvent
from datetime import UTC, datetime

event = CanonicalEvent(
    event_id="evt-001",
    timestamp=datetime.now(UTC),     # MUST be UTC-aware
    source="windows",
    event_type="authentication",     # "authentication"|"process"|"network"|"ot_modbus"|"file"
    host="ws01",
    user="alice",
    resource="ws01",
    action="logon_failure",
    result="failure",
    raw_log="raw log string here",
    # Optional fields:
    src_ip="10.0.0.1",
    dst_ip="10.0.0.2",
    port=445,
    protocol="SMB",
    process="lsass.exe",
    command_line="lsass.exe -encode ...",
    logon_type="network",
    auth_package="NTLM",
    windows_event_id=4625,
    modbus_register=40001,           # OT only
    modbus_value=9999,               # OT only
    modbus_function_code="6",        # OT only — MUST be string, not int
)
```

### EntityKey (Module 2.4) — NOT a String

```python
from backend.detection.models import EntityKey

# EntityKey is a Pydantic model, NOT a string
ek = EntityKey(entity_type="user", entity_id="alice")

# Access like:
ek.entity_type   # "user"
ek.entity_id     # "alice"

# WRONG — will raise AttributeError:
ek.split("::")   # ✗ EntityKey is not a string
```

### FeatureContribution.direction — "anomaly" / "normal"

```python
from backend.explainability.models import FeatureContribution

# direction has pattern constraint: "^(anomaly|normal)$"
fc = FeatureContribution(
    feature_name="failed_logins",
    raw_value=20.0,
    shap_value=0.4,
    abs_shap_value=0.4,
    contribution_rank=1,
    contribution_pct=80.0,
    direction="anomaly",   # ✓ "anomaly" or "normal" ONLY
    # direction="positive"  ✗ raises ValidationError
)
```

### AttackContext (Module 4.1) — Phase 5 Input Contract

```python
from backend.context.service import AttackContextService
from backend.context.models import AttackContext

svc = AttackContextService(persist=True)

# Minimal (alert is the only required input)
ctx = svc.build_context(alert=alert)

# Full enrichment
ctx = svc.build_context(
    alert=alert,              # Required: DetectionAlert
    explanation=explanation,  # Optional: ExplanationResult
    mapped=mapped_attack,     # Optional: MappedAttack
    graph=graph,              # Optional: AttackGraph
    chain=chain,              # Optional: AttackChain
    events=canonical_events,  # Optional: list[CanonicalEvent]
    feature_record=fr,        # Optional: FeatureRecord
)

# Quality gate for Phase 5 LLM
if ctx.completeness.completeness_pct < 50.0:
    # Context is incomplete — LLM should weight confidence accordingly
    pass

# Access all enrichments
entity = ctx.identity.entity_id
score  = ctx.detection.anomaly_score
techs  = ctx.chain.technique_sequence if ctx.chain else []
feats  = ctx.shap.top_features
hosts  = ctx.evidence.affected_hosts
is_ot  = ctx.evidence.has_ot_indicators
```

---

## 9. Configuration Reference

All settings are in `backend/core/config.py`.

### Key Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_ENV` | `development` | Deployment environment |
| `LOG_LEVEL` | `INFO` | Log verbosity |
| `DATA_DIR` | `./data` | Runtime data root |
| `ANOMALY_SCORE_THRESHOLD` | `0.5` | Alert trigger threshold |
| `ISOLATION_FOREST_CONTAMINATION` | `0.01` | Expected anomaly rate |
| `ANTHROPIC_API_KEY` | _(empty)_ | Required for Phase 5 LLM module |

### Accessing Settings in Code

```python
from backend.core.config import get_settings

settings = get_settings()
data_dir = settings.data_dir / "context"
```

---

## 10. Troubleshooting

### Tests Failing After Checkout

```powershell
# Reinstall dependencies
pip install -e ".[dev]"

# Confirm test count
python -m pytest tests/ --no-cov -q -p no:cacheprovider
# Expected: 1542 passed
```

### Import Error After Adding Module

```powershell
python -c "from backend.context import AttackContextService; print('OK')"
```
- Check `__init__.py` exists in the new package
- Verify no circular imports
- Confirm all referenced modules are importable

### Pydantic ValidationError on `model_id`

```python
# Add to any model that has a field named model_id:
from pydantic import ConfigDict
class MyModel(CyberShieldBaseModel):
    model_config = ConfigDict(protected_namespaces=())
    model_id: str
```

### `AttributeError: 'str' object has no attribute 'value'` on Enum

Pydantic with `use_enum_values=True` stores enum values as plain strings. Use:
```python
# Instead of: obj.domain.value
# Use:
obj.domain if isinstance(obj.domain, str) else obj.domain.value
```

### Commit Blocked by detect-secrets

```powershell
git commit --no-verify -m "your message"
```

This is the established project practice. Run `detect-secrets scan > .secrets.baseline` to update the baseline properly when ready.

### Windows Permission Error in pytest tmp

```
PermissionError: [WinError 5] Access is denied: pytest-current
```
This is a known Windows issue with pytest's temp directory cleanup. Exit code 1 with all tests passing is **not a real failure** — check the test count line.

---

## 11. Known Gotchas

| Gotcha | Detail |
|--------|--------|
| `EntityKey` is a model | `alert.entity_key.entity_type` — NOT `alert.entity_key.split("::")` |
| `modbus_function_code` is a string | Must be `"6"` not `6` — Pydantic rejects int |
| `FeatureContribution.direction` | Only `"anomaly"` or `"normal"` — not "positive"/"negative" |
| `model_id` namespace | Any model with `model_id` needs `ConfigDict(protected_namespaces=())` |
| `numba` version | Pinned to `0.61.0` — do NOT upgrade without checking coverage compatibility |
| UTC datetime | All `datetime` fields must be timezone-aware UTC — naive datetimes will fail |
| Enum serialisation | `use_enum_values=True` means `.value` is already a string — calling `.value` again raises `AttributeError` |
| `git commit --no-verify` | Required until `detect-secrets` baseline is updated |
| `data/` directory | Gitignored, auto-created by services. Delete freely to reset state |
