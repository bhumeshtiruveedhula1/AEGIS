# CyberShield — Developer Guide

## Contents

1. [Environment Setup](#environment-setup)
2. [Project Structure](#project-structure)
3. [Development Workflow](#development-workflow)
4. [Coding Standards](#coding-standards)
5. [Testing Guide](#testing-guide)
6. [Adding a New Module](#adding-a-new-module)
7. [Configuration Reference](#configuration-reference)
8. [Troubleshooting](#troubleshooting)

---

## Environment Setup

### Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Python | 3.11+ | Runtime |
| Docker | 24+ | Containerisation |
| Docker Compose | 2.20+ | Service orchestration |
| Git | 2.40+ | Version control |

### First-Time Setup

```bash
git clone https://github.com/your-org/cybershield.git
cd cybershield
chmod +x scripts/setup_dev.sh
./scripts/setup_dev.sh
```

This script:
1. Verifies Python 3.11+
2. Creates `.venv/`
3. Installs `requirements-dev.txt`
4. Installs pre-commit hooks
5. Creates `.env` from `.env.example`
6. Creates data/models/reports directories

### Starting Development

```bash
source .venv/bin/activate    # activate virtual environment
make run                     # start dev server (http://localhost:8000)
```

---

## Project Structure

```
cybershield/
├── backend/                   Python application package
│   ├── core/                  Cross-cutting infrastructure
│   │   ├── config.py          Settings (Pydantic BaseSettings)
│   │   ├── constants.py       Project-wide constants
│   │   ├── logging.py         Structured logging (structlog)
│   │   ├── exceptions.py      Custom exception hierarchy
│   │   └── health.py          Health check primitives
│   ├── shared/                Shared types, models, utilities
│   │   ├── types.py           NewType aliases and Literals
│   │   ├── models.py          Base Pydantic models
│   │   ├── schemas.py         API schemas (success/error/paginated)
│   │   └── utils/             Pure utility functions
│   ├── [module]/              One directory per pipeline stage
│   │   └── __init__.py        Module contract documentation
│   └── api/                   FastAPI application layer
│       ├── app.py             Application factory
│       ├── dependencies.py    Dependency injection
│       ├── middleware.py      Request ID + logging
│       └── routes/            API route handlers
├── tests/
│   ├── conftest.py            Shared fixtures
│   ├── unit/                  Fast isolated tests
│   └── integration/           HTTP-level tests
├── data/                      Runtime data (gitignored)
├── models/                    Trained artifacts (gitignored)
├── docker/                    Docker configuration
├── scripts/                   Developer scripts
└── docs/                      Documentation
```

---

## Development Workflow

### Daily Development

```bash
# Start your session
source .venv/bin/activate

# Start dev server
make run

# In another terminal, run tests after changes
make test-fast    # quick feedback loop

# Before committing
make lint         # ruff + mypy
make test         # full suite with coverage
```

### Git Workflow

```bash
# Create feature branch
git checkout -b feat/module-1.2-ingestion

# Commit (pre-commit hooks run automatically)
git add .
git commit -m "feat(ingestion): add log ingestion service"

# Push and open PR
git push origin feat/module-1.2-ingestion
```

### Pre-commit Hooks

Pre-commit runs automatically on `git commit`:
- `ruff` — lint and auto-fix
- `ruff-format` — format check
- `mypy` — type check
- `detect-secrets` — block committing secrets
- `no-commit-to-branch` — block direct commits to main

Run manually:
```bash
pre-commit run --all-files
```

---

## Coding Standards

### Python Style

- **Python 3.11+**: Use `match` statements, `tomllib`, `StrEnum`, etc.
- **Typing**: All functions must have type annotations (mypy strict)
- **Imports**: Absolute imports only (`from backend.core.config import Settings`)
- **Docstrings**: Google style for all public functions and classes
- **Line length**: 100 characters (configured in `pyproject.toml`)

### Naming Conventions

| Element | Convention | Example |
|---------|-----------|---------|
| Files | `snake_case.py` | `log_normalizer.py` |
| Classes | `PascalCase` | `IsolationForestAnomalyDetector` |
| Functions | `snake_case` | `parse_sysmon_event()` |
| Constants | `UPPER_SNAKE_CASE` | `ANOMALY_SCORE_THRESHOLD` |
| Type aliases | `PascalCase` | `AlertId = NewType("AlertId", str)` |

### Module Dependency Rules

```
backend.core      ← no dependencies on backend.*
backend.shared    ← only imports from backend.core
backend.[module]  ← imports backend.core and backend.shared only
                    (no cross-module imports at module level)
backend.api       ← imports from any backend.*
```

**Forbidden:**
```python
# backend.detection importing from backend.graph — WRONG
from backend.graph.builder import AttackGraphBuilder  # ✗

# Cross-module at import time
# Pass data between modules via function arguments, not imports
```

---

## Testing Guide

### Test Categories

| Marker | Where | Speed | Usage |
|--------|-------|-------|-------|
| `@pytest.mark.unit` | `tests/unit/` | Fast (<100ms) | Logic, validators, utilities |
| `@pytest.mark.integration` | `tests/integration/` | Moderate | HTTP endpoints |
| `@pytest.mark.slow` | Any | Slow | Stress tests, ML training |

### Writing Tests

```python
import pytest
from backend.shared.utils.id_utils import generate_id, is_valid_id

@pytest.mark.unit
class TestGenerateId:
    def test_generates_valid_uuid(self) -> None:
        id_ = generate_id()
        assert is_valid_id(id_)

    def test_generates_unique_ids(self) -> None:
        ids = {generate_id() for _ in range(100)}
        assert len(ids) == 100
```

### Using Fixtures

```python
# From conftest.py (available automatically):
def test_health(client):           # FastAPI TestClient
def test_data(test_settings):      # Settings with tmp dirs
def test_file(tmp_data_dir):       # Temp data directory
```

### Running Specific Tests

```bash
make test-unit                          # unit only
make test-integration                   # integration only
pytest tests/ -k "test_health"         # by test name
pytest tests/ -m unit                  # by marker
pytest tests/unit/core/test_config.py  # specific file
```

---

## Adding a New Module

When implementing a new pipeline module (e.g., `backend.ingestion`):

### Step 1: Create Module Structure

```bash
mkdir -p backend/ingestion/{models,parsers}
touch backend/ingestion/__init__.py    # already exists (stub)
touch backend/ingestion/service.py
touch backend/ingestion/router.py
```

### Step 2: Enable Feature Flag

In `.env`:
```bash
FEATURE_INGESTION_ENABLED=true
```

### Step 3: Register FastAPI Router

In `backend/api/app.py`, find `_register_routers()`:
```python
if settings.feature_ingestion_enabled:
    from backend.api.routes import ingestion as ingestion_router
    app.include_router(
        ingestion_router.router,
        prefix=f"{API_PREFIX}/ingest",
        tags=["Ingestion"],
    )
```

### Step 4: Register Health Check (if applicable)

```python
from backend.api.routes.health import register_health_check
from backend.ingestion.health import check_ingestion_pipeline

register_health_check("ingestion", check_ingestion_pipeline)
```

### Step 5: Write Tests

```bash
mkdir -p tests/unit/ingestion tests/integration/
touch tests/unit/ingestion/__init__.py
touch tests/unit/ingestion/test_log_normalizer.py
```

---

## Configuration Reference

All settings are defined in `backend/core/config.py` and documented in `.env.example`.

### Frequently Changed Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_ENV` | `development` | Deployment environment |
| `LOG_LEVEL` | `INFO` | Log verbosity |
| `ANTHROPIC_API_KEY` | _(empty)_ | Required for LLM module |
| `ANOMALY_SCORE_THRESHOLD` | `0.5` | Alert trigger threshold |
| `ISOLATION_FOREST_CONTAMINATION` | `0.01` | Expected anomaly rate |

---

## Troubleshooting

### Common Issues

**Port 8000 already in use:**
```bash
lsof -i :8000 | grep LISTEN    # find the process
kill -9 <PID>
```

**Mypy errors on startup:**
```bash
mypy backend --ignore-missing-imports   # quick check
```

**Pre-commit blocking commit:**
```bash
pre-commit run --all-files              # see all errors
pre-commit run ruff --all-files         # run specific hook
```

**Import errors after adding a new module:**
- Check `backend/[module]/__init__.py` exists
- Verify imports follow the dependency rules
- Run `python -c "from backend.[module] import ..."` to test

**Tests failing with settings errors:**
- Use `test_settings` fixture (see conftest.py) — never call `get_settings()` in tests
- Clear lru_cache: `get_settings.cache_clear()` before overriding
