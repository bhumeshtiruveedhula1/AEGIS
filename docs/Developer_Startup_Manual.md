# CyberShield — Developer Startup Manual

**Operation AEGIS · Phases 1–4.1 Complete**
**Document status:** Official · Based on current implementation only
**Tests passing:** 1541 / 0 failures | **Branch:** `phase-3-behavioral-detection`

---

## Table of Contents

1. [Repository Setup](#1-repository-setup)
2. [Python Environment](#2-python-environment)
3. [Dependency Installation](#3-dependency-installation)
4. [Environment Verification](#4-environment-verification)
5. [FastAPI Startup](#5-fastapi-startup)
6. [Digital Twin Startup](#6-digital-twin-startup)
7. [Digital Twin Verification](#7-digital-twin-verification)
8. [Telemetry Generation](#8-telemetry-generation)
9. [Normalization Verification](#9-normalization-verification)
10. [Baseline Generation Verification](#10-baseline-generation-verification)
11. [Feature Generation Verification](#11-feature-generation-verification)
12. [Metrics Verification](#12-metrics-verification)
13. [Detection Verification (Isolation Forest)](#13-detection-verification-isolation-forest)
14. [SHAP Explainability Verification](#14-shap-explainability-verification)
15. [MITRE ATT&CK Mapper Verification](#15-mitre-attck-mapper-verification)
16. [Attack Graph Verification](#16-attack-graph-verification)
17. [Attack Chain Verification](#17-attack-chain-verification)
18. [Synthetic Attack Generation Verification](#18-synthetic-attack-generation-verification)
19. [Attack Context Verification](#19-attack-context-verification)
20. [Directory Structure After Each Stage](#20-directory-structure-after-each-stage)
21. [Common Setup Problems](#21-common-setup-problems)
22. [Resetting the Development Environment](#22-resetting-the-development-environment)
23. [Updating After New Commits](#23-updating-after-new-commits)
24. [Git Workflow for Contributors](#24-git-workflow-for-contributors)
25. [Current Implementation Status — Phases 1–4.1 Complete](#25-current-implementation-status--phases-14-complete)
26. [Not Yet Implemented — Phase 5+](#26-not-yet-implemented--phase-5)

---

## Prerequisites

Before starting, ensure the following are installed on your machine:

| Tool | Minimum Version | Check Command |
|------|----------------|---------------|
| Python | 3.11 | `python --version` |
| Git | 2.x | `git --version` |
| Docker Desktop | 4.x (optional) | `docker --version` |

> **Windows note:** Docker Desktop is optional for development. All data pipeline stages
> (normalization, baseline, features, metrics) run locally without Docker. Docker is only
> required if you want live telemetry from running containers. All telemetry data can
> instead be generated via a local Python script (Section 8).

---

## 1. Repository Setup

### 1.1 Clone the Repository

**Purpose:** Obtain a local copy of the source code.

```powershell
git clone <repository-url> cybershield
cd cybershield
```

**Expected output:**
```
Cloning into 'cybershield'...
remote: Enumerating objects: ...
Resolving deltas: 100%
```

**Success criteria:** A `cybershield/` directory exists containing `pyproject.toml`, `backend/`, `tests/`, `data/`, `docs/`.

**Failure symptoms:**
- `fatal: repository '<url>' not found` — wrong URL or no network access.
- `Permission denied (publickey)` — SSH key not configured.

**Recovery:**
- For HTTPS: `git clone https://<host>/<org>/cybershield.git`
- For SSH: run `ssh-keygen -t ed25519` and add the public key to your Git host.

### 1.2 Confirm Repository Root

**Purpose:** All commands in this manual must be run from the repository root (`cybershield/`).

```powershell
Get-ChildItem pyproject.toml, backend, tests | Select-Object Name
```

**Expected output:**
```
Name
----
pyproject.toml
backend
tests
```

**Success criteria:** All three names appear. If any are missing, you are not in the correct directory.

---

## 2. Python Environment

### 2.1 Confirm Python 3.11

**Purpose:** The project requires Python 3.11. Python 3.10 or 3.12 may cause compatibility issues.

```powershell
python --version
```

**Expected output:**
```
Python 3.11.x
```

**Success criteria:** Major version 3, minor version 11.

**Failure symptoms:**
- `Python 3.10.x` — acceptable for test runs but `pip install -e .` will fail.
- `Python 3.12.x` — some dependencies have 3.11 upper bounds.
- `'python' is not recognized` — Python is not on PATH.

**Recovery (Windows):**
1. Download Python 3.11 from https://python.org/downloads/
2. During install, check "Add Python to PATH".
3. Open a new terminal and retry.

### 2.2 Create the Virtual Environment

**Purpose:** Isolate project dependencies from your global Python installation.

```powershell
python -m venv .venv
```

**Expected output:** No output. A `.venv/` directory appears in the repository root.

**Success criteria:** `.venv\Scripts\python.exe` exists.

**Failure symptoms:**
- `ModuleNotFoundError: No module named 'venv'` — run `pip install virtualenv` then `python -m virtualenv .venv`.

### 2.3 Activate the Virtual Environment

**Purpose:** Make `.venv`'s Python and pip the active executables for this terminal session.

```powershell
# Windows PowerShell
.\.venv\Scripts\Activate.ps1
```

```cmd
REM Windows CMD
.venv\Scripts\activate.bat
```

**Expected output:** Your prompt changes to include `(.venv)`:
```
(.venv) PS C:\...\cybershield>
```

**Success criteria:** Run `python -c "import sys; print(sys.prefix)"` — output ends with `.venv`.

**Failure symptoms:**
- `cannot be loaded because running scripts is disabled` — PowerShell execution policy blocking.

**Recovery:**
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

> **Important:** Activation only applies to the current terminal session. You must
> activate again in every new terminal.

### 2.4 Windows Automated Setup (Alternative)

Use the provided script for a single-command setup:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\setup_windows.ps1
```

**Purpose:** Performs steps 2.2, 2.3, 3.1, 3.2, and configures `.env` and pre-commit in one pass.

**Expected output:**
```
  [OK]   Python 3.11.x found at: C:\...\python.exe
  [OK]   .venv created
  [OK]   All dependencies installed
  [OK]   cybershield installed in editable mode
  [OK]   .env created from .env.example
  [OK]   pre-commit hooks installed
```

**Failure symptoms:** Any `[FAIL]` line — the message is self-describing.

---

## 3. Dependency Installation

### 3.1 Upgrade pip

**Purpose:** Avoid build failures from outdated pip versions.

```powershell
python -m pip install --upgrade pip
```

**Expected output:**
```
Successfully installed pip-xx.x.x
```

**Success criteria:** pip version >= 23.

### 3.2 Install Development Dependencies

**Purpose:** Install all production and development packages from `requirements-dev.txt`.

```powershell
python -m pip install -r requirements-dev.txt
```

**Expected output:** Long stream of download/install messages ending with:
```
Successfully installed fastapi-... pydantic-... uvicorn-... pytest-... ruff-... mypy-...
```

**Success criteria:** No `ERROR` lines. Exit code 0.

**Failure symptoms:**
- `ERROR: Could not find a version that satisfies the requirement` — network issue. Retry.
- `Microsoft Visual C++ 14.0 or greater is required` — install [Microsoft C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/).

**Recovery:**
```powershell
python -m pip cache purge
python -m pip install -r requirements-dev.txt
```

### 3.3 Install the Package in Editable Mode

**Purpose:** Makes `import backend` work from anywhere in the project. Required for tests and scripts.

```powershell
python -m pip install -e . --no-deps
```

**Expected output:**
```
Successfully installed cybershield-0.1.0
```

**Verify:**
```powershell
python -c "from backend.core.config import Settings; print('OK')"
```

**Expected output:** `OK`

**Failure symptoms:**
- `ERROR: Multiple top-level packages discovered` — run `python -m pip install --upgrade setuptools` then retry.
- `BackendUnavailable` — same fix.

### 3.4 Install Pre-commit Hooks

**Purpose:** Automatically run linting checks before each `git commit`.

```powershell
python -m pre_commit install
```

**Expected output:**
```
pre-commit installed at .git/hooks/pre-commit
```

---

## 4. Environment Verification

### 4.1 Configure the `.env` File

**Purpose:** The application reads all runtime configuration from `.env`.

```powershell
Copy-Item .env.example .env
```

**Success criteria:** `.env` exists in the repository root. It is listed in `.gitignore` and must never be committed.

**Key `.env` values for development:**

| Variable | Default | Purpose |
|----------|---------|---------|
| `APP_ENV` | `development` | Controls debug mode and Swagger UI exposure |
| `LOG_LEVEL` | `INFO` | Structured log verbosity |
| `LOG_FORMAT` | `console` | `console` for dev; `json` for production |
| `APP_PORT` | `8000` | FastAPI server port |
| `DATABASE_URL` | `sqlite+aiosqlite:///./data/cybershield.db` | Local SQLite for dev |
| `DATA_DIR` | `./data` | Root for all pipeline output |
| `CORS_ALLOWED_ORIGINS` | `["http://localhost:3000","http://localhost:8080"]` | **Must remain a JSON array** |
| `DT_LOG_BASE_DIR` | `./data/digital_twin` | Digital Twin log output |
| `DT_ACCELERATED_MODE` | `false` | Set `true` for fast baseline generation |

> **Critical:** `CORS_ALLOWED_ORIGINS` must use JSON array syntax
> (`["url1","url2"]`). A comma-separated string will cause `SettingsError` on startup.

### 4.2 Run the Environment Verification Script

**Purpose:** Diagnose the entire development environment in one pass.

```powershell
python verify_environment.py
```

**Expected output (condensed):**
```
  CHECK 1 — Python version
  [PASS] Python 3.11.x (3.11 — fully supported)

  CHECK 2 — Virtual environment
  [PASS] Virtual environment active: C:\...\cybershield\.venv

  CHECK 3 — pip health
  [PASS] No broken dependencies (pip check passed)

  CHECK 4 — Package imports
  [PASS] fastapi
  [PASS] pydantic
  [PASS] structlog
  ... (all packages)

  CHECK 7 — pre-commit hooks
  [PASS] pre-commit hook installed at .git/hooks/pre-commit

  CHECK 8 — Core backend module smoke test
  [PASS] backend.core.config  (Settings / config layer)
  [PASS] backend.shared.models  (Shared Pydantic base models)
  [PASS] backend.normalization.models  (CanonicalEvent model)
  [PASS] backend.baseline.models  (Baseline data models)
  [PASS] backend.features.models  (Feature schema)
  [PASS] backend.metrics.models  (Metrics models)
  [PASS] All 9 core backend modules importable

  ENVIRONMENT VERIFICATION SUMMARY
  ✓ All checks passed (1 warning)
```

**Success criteria:** No `[FAIL]` lines. The placeholder-values warning is expected in development.

**Failure symptom → recovery table:**

| Symptom | Recovery |
|---------|----------|
| `[FAIL] Virtual environment not active` | `.\.venv\Scripts\Activate.ps1` |
| `[FAIL] pip check found issues` | `python -m pip install -r requirements-dev.txt` |
| `[FAIL] X package(s) could not be imported` | `python -m pip install -r requirements-dev.txt` |
| `[FAIL] backend.core.config not importable` | `python -m pip install -e . --no-deps` |
| `shap NOT IMPORTABLE (AttributeError)` | Known `numba`/`coverage` conflict. Non-blocking — `shap` is unused in Phase 2 tests. |

### 4.3 Run the Full Test Suite

**Purpose:** Confirm all 925 unit and integration tests pass.

```powershell
python -m pytest tests/ --no-cov -q -p no:cacheprovider
```

**Expected output:**
```
collected 925 items
.......................................................... (all dots)
========================= 925 passed in X.XXs ==========================
```

**Success criteria:** `925 passed`, `PYTEST_EXIT_CODE: 0`.

**Failure symptoms:**
- Any `FAILED` line — see [Section 14: Common Setup Problems](#14-common-setup-problems).
- `PermissionError: [WinError 5] ... pytest-current` in stderr after `925 passed` — **non-fatal** Windows atexit cleanup; tests still passed.

**Run with coverage report (slower):**
```powershell
python -m pytest tests/ -q -p no:cacheprovider
```

Coverage HTML report: `reports/coverage/index.html`

---

## 5. FastAPI Startup

### 5.1 Start the Development Server

**Purpose:** Start the FastAPI application with auto-reload.

```powershell
python -m uvicorn backend.api.app:create_app --factory --host 0.0.0.0 --port 8000 --reload --log-level info
```

**Expected output:**
```
2026-...Z [info] cybershield_starting version=0.1.0 environment=development
2026-...Z [info] cybershield_started module=foundation status=ready
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
INFO:     Application startup complete.
```

**Success criteria:** `Application startup complete.` appears and the process does not exit.

**Failure symptoms:**
- `ModuleNotFoundError: No module named 'backend'` — run `python -m pip install -e . --no-deps`.
- `SettingsError` / `ValidationError` — `.env` malformed. Check `CORS_ALLOWED_ORIGINS` format.
- `Address already in use` — port 8000 occupied. See [Section 14](#14-common-setup-problems).

### 5.2 Verify the Health Endpoint

**Purpose:** Confirm the server responds and the foundation health check is healthy.

```powershell
# In a second terminal (keep the server running in the first)
Invoke-RestMethod http://localhost:8000/health | ConvertTo-Json -Depth 5
```

**Expected output:**
```json
{
  "status": "healthy",
  "version": "0.1.0",
  "environment": "development",
  "components": [
    {
      "name": "foundation",
      "status": "healthy",
      "details": { "version": "0.1.0", "module": "foundation" }
    }
  ],
  "checked_at": "2026-..."
}
```

**Success criteria:** `status` is `"healthy"`. `components[0].name` is `"foundation"` with status `"healthy"`.

### 5.3 Verify the Readiness Endpoint

```powershell
Invoke-RestMethod http://localhost:8000/ready
```

**Expected output:**
```json
{ "status": "ready", "checked_at": "2026-..." }
```

**Success criteria:** HTTP 200. `status` is `"ready"`. A 503 means a component has failed — check `/health` for details.

### 5.4 Verify the Version Endpoint

```powershell
Invoke-RestMethod http://localhost:8000/version
```

**Expected output:**
```json
{
  "name": "CyberShield",
  "version": "0.1.0",
  "module": "foundation",
  "environment": "development",
  "timestamp": "2026-..."
}
```

### 5.5 Verify Swagger UI (Development Only)

Open in a browser: **http://localhost:8000/docs**

**Success criteria:** Swagger UI renders with three endpoints: `/health`, `/ready`, `/version`. In `production` mode, this URL returns 404 by design.

### 5.6 Verify the Request-ID Middleware

**Purpose:** Every response must include a unique `X-Request-ID` header.

```powershell
Invoke-WebRequest http://localhost:8000/health | Select-Object -ExpandProperty Headers
```

**Success criteria:** `X-Request-Id` is present and is a UUID v4 (36 characters).

---

## 6. Digital Twin Startup

The Digital Twin is the simulated Critical National Infrastructure (CNI) environment consisting of four containers:

| Container | IP | Port | Role |
|-----------|----|------|------|
| `hospital-server` | `172.20.1.10` | `9002` | IT application server |
| `domain-controller` | `172.20.1.20` | `9001` | Active Directory domain controller |
| `ot-node` | `172.20.2.10` | `9003` | OT/SCADA PLC node |
| `attacker` | `172.20.3.10` | N/A | Controlled attack source (no inbound port) |

### 6.1 Digital Twin Without Docker (Development Mode)

The Digital Twin Registry, configuration, and all pipeline modules run fully in-process without Docker. Docker containers are only needed for live HTTP health probes and real-time telemetry streaming.

**For development, you do not need Docker.** Proceed directly to [Section 8: Telemetry Generation](#8-telemetry-generation) to generate log files locally via Python.

### 6.2 Digital Twin With Docker (Optional)

**Purpose:** Start all four containers for live health probes and real-time telemetry generation.

**Prerequisite:** Docker Desktop is running.

```powershell
docker compose -f docker/docker-compose.yml up -d
```

**Expected output:**
```
[+] Running 4/4
 ✔ Container hospital-server     Started
 ✔ Container domain-controller   Started
 ✔ Container ot-node             Started
 ✔ Container attacker            Started
```

**Success criteria:** All four containers show `Started`.

**Failure symptoms:**
- `error during connect: ... pipe/docker_engine` — Docker Desktop is not running. Start it.
- Port conflict on 9001, 9002, or 9003 — stop the conflicting service.

**Check container status:**
```powershell
docker compose -f docker/docker-compose.yml ps
```

**View live logs:**
```powershell
docker compose -f docker/docker-compose.yml logs -f
```

**Stop containers:**
```powershell
docker compose -f docker/docker-compose.yml down
```

---

## 7. Digital Twin Verification

### 7.1 Verify the Registry Initialises

**Purpose:** Confirm the `DigitalTwinRegistry` singleton constructs correctly and discovers all telemetry sources.

```powershell
python -c "
from backend.digital_twin.registry import get_registry
registry = get_registry()
sources = registry.list_telemetry_sources()
print(f'Registry initialised: {len(sources)} telemetry sources')
for s in sources:
    print(f'  {s.source_id}: {s.host_log_path}')
"
```

**Expected output:**
```
Registry initialised: 4 telemetry sources
  hospital_server_main: data/digital_twin/hospital_server/hospital_server.jsonl
  domain_controller_main: data/digital_twin/domain_controller/domain_controller.jsonl
  ot_node_main: data/digital_twin/ot_node/ot_node.jsonl
  attacker_main: data/digital_twin/attacker/attacker.jsonl
```

**Success criteria:** Exactly 4 telemetry sources. All paths point inside `data/digital_twin/`.

**Failure symptoms:**
- `ModuleNotFoundError` — run `python -m pip install -e . --no-deps`.
- `SettingsError` — `.env` missing or malformed.

### 7.2 Verify Digital Twin Settings

```powershell
python -c "
from backend.digital_twin.config import get_digital_twin_settings
s = get_digital_twin_settings()
print(f'Hospital Server:    {s.hospital_server_ip}:{s.hospital_server_port}')
print(f'Domain Controller:  {s.domain_controller_ip}:{s.domain_controller_port}')
print(f'OT Node:            {s.ot_node_ip}:{s.ot_node_port}')
print(f'Attacker:           {s.attacker_ip}')
print(f'Log Base Dir:       {s.log_base_dir}')
print(f'Accelerated Mode:   {s.accelerated_mode}')
"
```

**Expected output:**
```
Hospital Server:    172.20.1.10:9002
Domain Controller:  172.20.1.20:9001
OT Node:            172.20.2.10:9003
Attacker:           172.20.3.10
Log Base Dir:       data/digital_twin
Accelerated Mode:   False
```

**Success criteria:** All IPs and ports match the values above exactly.

### 7.3 Verify Digital Twin Health (Docker Only)

> Skip this section if Docker containers are not running.

```powershell
python -c "
import asyncio
from backend.digital_twin.health import check_digital_twin

async def main():
    result = await check_digital_twin()
    print(f'Status: {result.status}')
    for k, v in (result.details or {}).items():
        print(f'  {k}: {v}')

asyncio.run(main())
"
```

**Expected output (containers running):**
```
Status: healthy
  hospital_server: healthy
  domain_controller: healthy
  ot_node: healthy
  attacker: unknown
```

**Expected output (containers not running):**
```
Status: degraded
  hospital_server: unreachable
  domain_controller: unreachable
  ot_node: unreachable
  attacker: unknown
```

**Success criteria:** If Docker is running, first three containers are `healthy`. Attacker is always `unknown` — no inbound health port by design.

---

## 8. Telemetry Generation

Telemetry is the JSONL log data produced by each Digital Twin container. The pipeline requires telemetry files before normalization can run.

### 8.1 Method A — Docker (Live Generation)

If Docker containers are running, they generate telemetry continuously into `data/digital_twin/`.

**Verify after 10 seconds:**
```powershell
Start-Sleep -Seconds 10
Get-ChildItem data\digital_twin -Recurse -Filter "*.jsonl" |
  Select-Object Name, Length
```

**Success criteria:** All four JSONL files exist with non-zero sizes.

### 8.2 Method B — Local Python Script (No Docker Required)

**Purpose:** Generate realistic synthetic JSONL log data for all four Digital Twin sources to enable the full pipeline without Docker.

```powershell
python -c "
import json, random, uuid
from pathlib import Path
from datetime import datetime, UTC, timedelta

random.seed(42)
base = Path('data/digital_twin')

# Hospital Server — process, network, file, auth events
hs_dir = base / 'hospital_server'
hs_dir.mkdir(parents=True, exist_ok=True)
with open(hs_dir / 'hospital_server.jsonl', 'w') as f:
    for i in range(500):
        ts = (datetime.now(UTC) - timedelta(hours=random.randint(0, 168))).isoformat()
        line = {
            'event_id': str(uuid.uuid4()), 'timestamp': ts,
            'event_type': random.choice(['process_create', 'network_connect', 'file_create', 'user_logon']),
            'source': 'hospital_server', 'hostname': 'hospital-server-01',
            'user': random.choice(['svc-iis', 'svc-db', 'CORP\\\\admin', 'CORP\\\\nurse01', 'CORP\\\\doctor02']),
            'process_image': random.choice(['C:\\\\Windows\\\\System32\\\\svchost.exe', 'C:\\\\inetpub\\\\wwwroot\\\\app.exe', 'sqlservr.exe']),
            'process_id': random.randint(1000, 9000),
            'destination_ip': f'10.0.{random.randint(0,5)}.{random.randint(1,254)}',
            'destination_port': random.choice([80, 443, 1433, 3389, 445]),
        }
        f.write(json.dumps(line) + '\n')
print('hospital_server.jsonl: 500 events')

# Domain Controller — Windows logon events
dc_dir = base / 'domain_controller'
dc_dir.mkdir(parents=True, exist_ok=True)
with open(dc_dir / 'domain_controller.jsonl', 'w') as f:
    for i in range(300):
        ts = (datetime.now(UTC) - timedelta(hours=random.randint(0, 168))).isoformat()
        line = {
            'event_id': str(uuid.uuid4()), 'timestamp': ts,
            'event_type': 'windows_event', 'source': 'domain_controller',
            'hostname': 'dc-01', 'windows_event_id': random.choice([4624, 4625, 4672, 4720, 4726]),
            'subject_username': random.choice(['admin', 'nurse01', 'svc-backup', 'doctor02']),
            'subject_domain': 'CORP', 'logon_type': random.choice([2, 3, 10]),
            'ip_address': f'172.20.1.{random.randint(10,50)}',
        }
        f.write(json.dumps(line) + '\n')
print('domain_controller.jsonl: 300 events')

# OT Node — Modbus register read/write events
ot_dir = base / 'ot_node'
ot_dir.mkdir(parents=True, exist_ok=True)
with open(ot_dir / 'ot_node.jsonl', 'w') as f:
    for i in range(200):
        ts = (datetime.now(UTC) - timedelta(hours=random.randint(0, 168))).isoformat()
        line = {
            'event_id': str(uuid.uuid4()), 'timestamp': ts,
            'event_type': 'modbus_read', 'source': 'ot_node',
            'hostname': 'plc-01', 'function_code': random.choice([1, 2, 3, 4]),
            'register_address': random.randint(10, 40), 'register_count': random.randint(1, 10),
            'source_ip': '192.168.1.100', 'destination_ip': '172.20.2.10',
        }
        f.write(json.dumps(line) + '\n')
print('ot_node.jsonl: 200 events')

# Attacker — port scan events
att_dir = base / 'attacker'
att_dir.mkdir(parents=True, exist_ok=True)
with open(att_dir / 'attacker.jsonl', 'w') as f:
    for i in range(50):
        ts = (datetime.now(UTC) - timedelta(hours=random.randint(0, 48))).isoformat()
        line = {
            'event_id': str(uuid.uuid4()), 'timestamp': ts,
            'event_type': 'port_scan', 'source': 'attacker',
            'hostname': 'attacker-kali',
            'target_ip': f'172.20.1.{random.randint(10, 50)}',
            'target_port': random.choice([22, 80, 443, 3389, 445, 1433]),
            'tool': random.choice(['nmap', 'masscan']),
        }
        f.write(json.dumps(line) + '\n')
print('attacker.jsonl: 50 events')

print('Telemetry generation complete.')
"
```

**Expected output:**
```
hospital_server.jsonl: 500 events
domain_controller.jsonl: 300 events
ot_node.jsonl: 200 events
attacker.jsonl: 50 events
Telemetry generation complete.
```

**Verify file creation:**
```powershell
Get-ChildItem data\digital_twin -Recurse -Filter "*.jsonl" |
  Select-Object @{N='Source';E={$_.Directory.Name}},
                @{N='Events';E={(Get-Content $_.FullName | Measure-Object -Line).Lines}}
```

**Expected output:**
```
Source              Events
------              ------
hospital_server     500
domain_controller   300
ot_node             200
attacker            50
```

**Success criteria:** All four files exist and contain the correct event counts.

**Failure symptoms:**
- `PermissionError` on `data/digital_twin/` — run `icacls data /grant "$env:USERNAME:(OI)(CI)F" /T`.
- Any directory missing — run the script again; it creates missing directories automatically.

---

## 9. Normalization Verification

The Normalization Pipeline (Module 1.3) reads raw JSONL from all four Digital Twin sources and produces a unified `normalized_events.jsonl` in the `CanonicalEvent` schema.

### 9.1 Run the Normalization Pipeline

**Purpose:** Transform raw logs into the canonical `CanonicalEvent` format.

```powershell
python -c "
from backend.digital_twin.registry import get_registry
from backend.normalization.pipeline import NormalizationPipeline

registry = get_registry()
pipeline = NormalizationPipeline(registry)
report = pipeline.run()

print(f'Run ID:               {report.run_id}')
print(f'Sources processed:    {report.total_sources}')
print(f'Events normalized:    {report.total_events_normalized}')
print(f'Parse errors:         {report.total_parse_errors}')
print(f'Output file:          {report.output_file}')
"
```

**Expected output:**
```
Run ID:               xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
Sources processed:    4
Events normalized:    XXX
Parse errors:         XXX
Output file:          data/normalized/normalized_events.jsonl
```

**Success criteria:**
- `Sources processed` = 4.
- `Events normalized` > 0.
- `Output file` exists.

**Failure symptoms:**
- `Sources processed: 0` — telemetry files are missing. Run Section 8 first.
- `Events normalized: 0` — all events failed parsing. Check `data/normalized/errors/` for dead-letter records.
- `FileNotFoundError` for a log path — generate telemetry first.

### 9.2 Verify the Normalized Output

```powershell
# Count events
(Get-Content data\normalized\normalized_events.jsonl | Measure-Object -Line).Lines

# Inspect first event
Get-Content data\normalized\normalized_events.jsonl |
  Select-Object -First 1 |
  ConvertFrom-Json |
  ConvertTo-Json -Depth 3
```

**Expected first-event output (abbreviated):**
```json
{
  "event_id": "...",
  "timestamp": "2026-...",
  "source": "hospital_server",
  "event_type": "process_create",
  "hostname": "hospital-server-01",
  "schema_version": "1.0.0"
}
```

**Success criteria:** JSON parses without error. Fields `event_id`, `timestamp`, `source`, `event_type`, `hostname`, `schema_version` are present.

### 9.3 Check for Parse Errors

```powershell
Get-ChildItem data\normalized\errors\ -ErrorAction SilentlyContinue
```

**Expected output (healthy):** Empty directory or no output.

**If error files exist:** They are dead-letter records kept for debugging. They do not block the pipeline. Check their content for unsupported event types.

---

## 10. Baseline Generation Verification

The Baseline System (Module 2.1) reads normalized events and computes statistical behavioral profiles for each entity (grouped by user, host, source, and user+host dimensions).

### 10.1 Run the Baseline Builder

**Purpose:** Compute behavioral baselines from normalized telemetry.

```powershell
python -c "
from backend.baseline.service import BaselineService

service = BaselineService()
report = service.build_from_normalized_output()

print(f'Build ID:          {report.build_id}')
print(f'Events processed:  {report.total_events_processed}')
print(f'Entities built:    {report.entities_built}')
print(f'Baseline dir:      {report.baseline_dir}')
print(f'Duration:          {report.duration_seconds:.3f}s')
"
```

**Expected output:**
```
Build ID:          xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
Events processed:  XXX
Entities built:    XX
Baseline dir:      data/baseline
Duration:          X.XXXs
```

**Success criteria:**
- `Events processed` > 0.
- `Entities built` > 0.
- `data/baseline/` is populated.

**Failure symptoms:**
- `BaselineInputError: normalized_events.jsonl not found` — run normalization first (Section 9).
- `Events processed: 0` — normalized events file is empty. Re-run normalization.
- `Entities built: 0` — events have no parseable user/hostname fields. Check normalized output.

### 10.2 Verify Baseline Artifacts

```powershell
# List baseline files
Get-ChildItem data\baseline | Select-Object Name, Length

# Inspect manifest
Get-Content data\baseline\manifest.json | ConvertFrom-Json |
  Select-Object schema_version, entity_count, build_id
```

**Expected output:**
```
Name                           Length
----                           ------
manifest.json                  XXXX
user_svc-iis.json              XXXX
host_hospital-server-01.json   XXXX
...

schema_version  entity_count  build_id
--------------  ------------  --------
1.0.0           XX            xxxxxxxx-...
```

**Success criteria:** `manifest.json` exists with `schema_version` = `"1.0.0"`. At least one entity JSON file exists.

### 10.3 Verify the Baseline Reader API

**Purpose:** Confirm the Feature Engine can query baselines via the sanctioned `BaselineReader` interface.

```powershell
python -c "
from backend.baseline.reader_api import BaselineReader

reader = BaselineReader()
entities = reader.list_entities()
print(f'Total entities: {len(entities)}')
for e in entities[:5]:
    print(f'  {e.dimension}:{e.identifier}')
"
```

**Expected output:**
```
Total entities: XX
  user:svc-iis
  user:CORP\admin
  host:hospital-server-01
  ...
```

**Success criteria:** `Total entities` > 0. Each entity shows a dimension prefix.

---

## 11. Feature Generation Verification

The Feature Engine (Module 2.2) transforms normalized `CanonicalEvent` records plus learned baselines into deterministic 56-dimensional behavioral feature vectors.

### 11.1 Run Feature Extraction

**Purpose:** Produce feature vectors for all normalized events.

```powershell
python -c "
from backend.features.service import FeatureService

service = FeatureService()
report = service.extract_from_normalized_output()

print(f'Run ID:               {report.run_id}')
print(f'Events processed:     {report.total_events_processed}')
print(f'Records extracted:    {report.total_records_extracted}')
print(f'Extraction errors:    {report.total_extraction_errors}')
print(f'Feature dimension:    {report.feature_dimension}')
print(f'Schema version:       {report.schema_version}')
print(f'Output dir:           {report.output_dir}')
"
```

**Expected output:**
```
Run ID:               xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
Events processed:     XXX
Records extracted:    XXX
Extraction errors:    X
Feature dimension:    56
Schema version:       1.0.0
Output dir:           data/features
```

**Success criteria:**
- `Feature dimension` = 56 (always, by schema contract).
- `Records extracted` > 0.
- `Schema version` = `1.0.0`.

**Failure symptoms:**
- `FeaturePipelineError: normalized_events.jsonl not found` — run normalization first.
- `BaselineNotFoundError` — run baseline builder first (Section 10).
- `Records extracted: 0` — check extraction errors.

### 11.2 Verify Feature Output Files

```powershell
Get-ChildItem data\features -ErrorAction SilentlyContinue | Select-Object Name, Length
```

**Expected output:**
```
Name                                          Length
----                                          ------
features_xxxxxxxx-xxxx-xxxx-xxxx.jsonl        XXXXX
pipeline_report.json                          XXXX
```

**Success criteria:** At least one `features_*.jsonl` and a `pipeline_report.json` exist.

### 11.3 Verify a Feature Vector

```powershell
$featureFile = (Get-ChildItem data\features\features_*.jsonl | Select-Object -First 1).FullName
$first = Get-Content $featureFile | Select-Object -First 1 | ConvertFrom-Json
Write-Host "Event ID:       $($first.event_id)"
Write-Host "Entity:         $($first.entity_key)"
Write-Host "Feature count:  $($first.feature_vector.Count)"
```

**Expected output:**
```
Event ID:       xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
Entity:         user:svc-iis
Feature count:  56
```

**Success criteria:** `Feature count` = 56. `Entity` shows a dimension prefix.

---

## 12. Metrics Verification

The Metrics System (Module 2.3) collects operational health metrics across all pipeline stages and persists them as structured snapshots in `data/metrics/`.

### 12.1 Run Metrics Collection

**Purpose:** Collect a complete metric snapshot for the current platform state.

```powershell
python -c "
from backend.digital_twin.registry import get_registry
from backend.normalization.pipeline import NormalizationPipeline
from backend.metrics.service import MetricService

registry = get_registry()
pipeline = NormalizationPipeline(registry)
norm_report = pipeline.run()

service = MetricService()
snapshot = service.collect_all(norm_report=norm_report)

print(f'Snapshot ID:     {snapshot.snapshot_id}')
print(f'Computed:        {snapshot.computed_count}')
print(f'Unavailable:     {snapshot.unavailable_count}')
print(f'Schema version:  {snapshot.schema_version}')
"
```

**Expected output:**
```
Snapshot ID:     xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
Computed:        XX
Unavailable:     XX
Schema version:  1.0.0
```

**Success criteria:**
- `Snapshot ID` is a valid UUID.
- `Computed` > 0.
- `Schema version` = `1.0.0`.

> **Note on `Unavailable`:** Metrics from modules not yet implemented (detection, response)
> always report as unavailable. This is expected behavior in Phase 2.

### 12.2 Verify Metrics Persistence

```powershell
# History file
Get-Item data\metrics\history.jsonl | Select-Object Name, Length

# Manifest
Get-Content data\metrics\manifest.json | ConvertFrom-Json |
  Select-Object run_count, latest_run_id

# Snapshot files
Get-ChildItem data\metrics\snapshots\ | Select-Object Name
```

**Expected output:**
```
Name           Length
----           ------
history.jsonl  XXXXX

run_count  latest_run_id
---------  -------------
X          xxxxxxxx-xxxx-...

Name
----
xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.json
```

**Success criteria:** `history.jsonl` and `manifest.json` exist. At least one snapshot file in `data/metrics/snapshots/`.

### 12.3 Verify the Metric Reader

```powershell
python -c "
from backend.metrics.reader import MetricReader

reader = MetricReader()
snapshot = reader.latest_snapshot()
if snapshot:
    print(f'Latest snapshot: {snapshot.snapshot_id}')
    print(f'Timestamp:       {snapshot.collected_at}')
    print(f'Events normalized: {snapshot.pipeline.events_normalized.value}')
else:
    print('No snapshots yet — run metrics collection first (Section 12.1)')
"
```

**Expected output:**
```
Latest snapshot: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
Timestamp:       2026-...
Events normalized: XXX.0
```

**Success criteria:** A snapshot is returned. `events_normalized` is a positive number.

---

## 13. Directory Structure After Each Stage

### After Stage 0: Fresh Clone
```
data/
├── attack_reference/
├── baseline/
│   └── .gitkeep
├── digital_twin/
│   ├── attacker/
│   ├── domain_controller/
│   ├── hospital_server/
│   └── ot_node/
├── metrics/
│   └── .gitkeep
├── normalized/
│   ├── .gitkeep
│   └── errors/
└── raw/
```

### After Stage 1: Telemetry Generation (Section 8)
```
data/
└── digital_twin/
    ├── attacker/
    │   └── attacker.jsonl                  ← 50 events
    ├── domain_controller/
    │   └── domain_controller.jsonl         ← 300 events
    ├── hospital_server/
    │   └── hospital_server.jsonl           ← 500 events
    └── ot_node/
        └── ot_node.jsonl                   ← 200 events
```

### After Stage 2: Normalization (Section 9)
```
data/
└── normalized/
    ├── normalized_events.jsonl             ← all canonical events (JSONL)
    ├── normalization_report.json           ← pipeline run summary
    └── errors/
        └── errors_*.jsonl                  ← dead-letter records (if any)
```

### After Stage 3: Baseline Generation (Section 10)
```
data/
└── baseline/
    ├── manifest.json                       ← entity index
    ├── user_svc-iis.json                   ← per-entity behavioral profiles
    ├── user_CORP_admin.json
    ├── host_hospital-server-01.json
    └── ...
```

### After Stage 4: Feature Generation (Section 11)
```
data/
└── features/
    ├── features_<run_id>.jsonl             ← 56-dimensional feature vectors
    └── pipeline_report.json                ← extraction run summary
```

### After Stage 5: Metrics Collection (Section 12)
```
data/
└── metrics/
    ├── history.jsonl                       ← append-only metric history
    ├── manifest.json                       ← lightweight index
    └── snapshots/
        └── <snapshot_id>.json              ← per-snapshot JSON (random access)
```

### Full Data Directory (All Stages Complete)
```
data/
├── attack_reference/                       ← MITRE ATT&CK data (Phase 3+, not yet implemented)
├── baseline/
│   ├── manifest.json
│   └── *.json                              ← entity profiles
├── digital_twin/
│   ├── attacker/attacker.jsonl
│   ├── domain_controller/domain_controller.jsonl
│   ├── hospital_server/hospital_server.jsonl
│   └── ot_node/ot_node.jsonl
├── features/
│   ├── features_<run_id>.jsonl
│   └── pipeline_report.json
├── metrics/
│   ├── history.jsonl
│   ├── manifest.json
│   └── snapshots/*.json
├── normalized/
│   ├── normalized_events.jsonl
│   ├── normalization_report.json
│   └── errors/
└── raw/                                    ← reserved for ingestion (Phase 3+, not yet implemented)
```

---

## 14. Common Setup Problems

### `ModuleNotFoundError: No module named 'backend'`

**Cause:** Package not installed in the virtual environment.

**Fix:**
```powershell
python -m pip install -e . --no-deps
```

---

### `SettingsError` or `ValidationError` on startup

**Symptom:**
```
pydantic_settings.errors.SettingsError: error parsing value for field "cors_allowed_origins"
```

**Cause:** `CORS_ALLOWED_ORIGINS` in `.env` uses comma-separated format instead of JSON array.

**Fix:** Edit `.env`:
```
CORS_ALLOWED_ORIGINS=["http://localhost:3000","http://localhost:8080"]
```

---

### `BackendUnavailable` during `pip install -e .`

**Cause:** Outdated `setuptools`.

**Fix:**
```powershell
python -m pip install --upgrade setuptools
python -m pip install -e . --no-deps
```

---

### `Multiple top-level packages discovered in a flat-layout`

**Cause:** Package discovery picked up `data/`, `docker/`, or `models/` as Python packages.

**Fix:** Ensure `pyproject.toml` has:
```toml
[tool.setuptools.packages.find]
where = ["."]
include = ["backend*"]
exclude = ["data*", "models*", "docker*", "reports*", "tests*"]
```

---

### `cannot be loaded because running scripts is disabled`

**Cause:** PowerShell execution policy.

**Fix (current session only):**
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

---

### `PermissionError: [WinError 5] ... pytest-current` after `925 passed`

**Cause:** Windows ACL restriction on pytest's temp dir cleanup. Runs in atexit after tests complete.

**Impact:** None. Tests passed. Exit code is 0.

**Fix (suppress the noise):**
```powershell
python -m pytest tests/ --no-cov -q -p no:cacheprovider
```

---

### `shap NOT IMPORTABLE (AttributeError: module 'coverage.types' ...)`

**Cause:** `numba 0.66.0` (transitive dependency of `shap`) uses `coverage.types.Tracer` removed in `coverage 7.0`.

**Impact:** None. `shap` is not used in any Phase 2 code or tests. All 925 tests pass.

**Fix:** None required as of Phase 2.

---

### `Address already in use` starting uvicorn

**Fix:**
```powershell
# Find the occupying process
netstat -ano | findstr :8000

# Kill it (replace 12345 with the PID shown)
taskkill /PID 12345 /F

# Or use a different port
python -m uvicorn backend.api.app:create_app --factory --port 8001 --reload
```

---

### `BaselineInputError: normalized_events.jsonl not found`

**Cause:** Baseline builder run before normalization.

**Fix:** Run pipeline in order: telemetry → normalization → baseline → features → metrics.

---

### `PermissionError` writing to `data/`

**Fix:**
```powershell
icacls data /grant "$env:USERNAME:(OI)(CI)F" /T
```

---

## 15. Resetting the Development Environment

### 15.1 Clear Generated Data (Keep Source Code)

```powershell
# Remove all pipeline output
Remove-Item -Recurse -Force data\normalized\* -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force data\baseline\* -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force data\features\* -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force data\metrics\* -ErrorAction SilentlyContinue
Remove-Item data\digital_twin\*\*.jsonl -Recurse -ErrorAction SilentlyContinue

# Remove test/coverage artifacts
Remove-Item -Recurse -Force .pytest_cache, .mypy_cache, .ruff_cache -ErrorAction SilentlyContinue
Remove-Item -Force .coverage -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force reports\coverage -ErrorAction SilentlyContinue

# Restore gitkeep files
New-Item -ItemType File -Force data\baseline\.gitkeep | Out-Null
New-Item -ItemType File -Force data\normalized\.gitkeep | Out-Null
New-Item -ItemType File -Force data\metrics\.gitkeep | Out-Null

Write-Host "Data reset complete."
```

### 15.2 Full Environment Reset (Including `.venv`)

```powershell
deactivate
Remove-Item -Recurse -Force .venv
Remove-Item -Recurse -Force cybershield.egg-info -ErrorAction SilentlyContinue

# Recreate from scratch (Sections 2 and 3)
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
python -m pip install -e . --no-deps
python -m pre_commit install
```

**Verify reset succeeded:**
```powershell
python verify_environment.py
```

### 15.3 Reset Docker (If Used)

```powershell
docker compose -f docker/docker-compose.yml down -v --remove-orphans
docker compose -f docker/docker-compose.yml build --no-cache
docker compose -f docker/docker-compose.yml up -d
```

---

## 16. Updating After New Commits

### 16.1 Pull Latest Changes

```powershell
git pull origin main
```

### 16.2 Update Dependencies

Run after every pull — new modules may add dependencies:

```powershell
python -m pip install -r requirements-dev.txt
python -m pip install -e . --no-deps
```

### 16.3 Check for Schema Changes

If any data model schema versions changed, existing data files are incompatible:

```powershell
git diff HEAD~1 HEAD -- backend/normalization/models.py backend/baseline/models.py `
  backend/features/models.py backend/metrics/models.py | Select-String "SCHEMA_VERSION"
```

If any `SCHEMA_VERSION` constant changed:
1. Reset all data (Section 15.1)
2. Regenerate from telemetry (Sections 8–12)

### 16.4 Re-run Verification

```powershell
python verify_environment.py
python -m pytest tests/ --no-cov -q -p no:cacheprovider
```

**Success criteria:** No `[FAIL]` lines. 925 tests pass.

---

## 17. Git Workflow for Contributors

### 17.1 Branch Strategy

| Branch | Purpose |
|--------|---------|
| `main` | Stable, tested. Protected — no direct push. |
| `feature/<name>` | New feature development |
| `fix/<name>` | Bug fixes |
| `refactor/<name>` | Code restructuring (no behavior change) |
| `docs/<name>` | Documentation changes |
| `test/<name>` | Test additions or corrections |

### 17.2 Start a New Feature

```powershell
git checkout main
git pull origin main
git checkout -b feature/your-feature-name
```

### 17.3 Commit Message Format

CyberShield uses **Conventional Commits**:

```
<type>(<scope>): <short summary>

[optional body — explain WHY, not WHAT]

[optional footer — Breaking changes, issue refs]
```

**Types:**

| Type | When |
|------|------|
| `feat` | New functionality |
| `fix` | Bug fix |
| `refactor` | Restructuring, no behavior change |
| `test` | Adding or fixing tests |
| `docs` | Documentation only |
| `chore` | Build scripts, dependencies, tooling |
| `perf` | Performance improvement |

**Examples:**
```
feat(normalization): add OT node Modbus parser

fix(config): handle JSON array format for CORS_ALLOWED_ORIGINS

test(baseline): add unit tests for Welford online algorithm

docs: add Developer Startup Manual
```

### 17.4 Pre-commit Checks

Pre-commit runs automatically on `git commit` and checks:
- `ruff check` — linting
- `ruff format` — code formatting
- `trailing-whitespace` — no trailing spaces
- `end-of-file-fixer` — files end with newline

If pre-commit rejects a commit, it auto-fixes what it can. Re-stage and recommit:

```powershell
git add -A
git commit -m "your message"
```

**Run manually:**
```powershell
python -m pre_commit run --all-files
```

### 17.5 Test Before Pushing

```powershell
python -m pytest tests/ --no-cov -q -p no:cacheprovider
```

Do not push with failing tests.

### 17.6 Open a Pull Request

```powershell
git push origin feature/your-feature-name
```

Open a PR targeting `main`.

**PR checklist:**
- [ ] All 925 tests pass
- [ ] Pre-commit passes on all files
- [ ] New functionality covered by unit tests
- [ ] Integration tests updated if API surface changed
- [ ] `SCHEMA_VERSION` bumped if data models changed
- [ ] `.env.example` updated if new settings added
- [ ] `docs/Developer_Startup_Manual.md` updated if new modules reached Phase Complete

### 17.7 Linting and Type Checking

```powershell
# Lint and auto-fix
python -m ruff check backend tests --fix

# Format
python -m ruff format backend tests

# Type checking
python -m mypy backend
```

---

## 18. Current Implementation Status — Phase 2 Complete

### Implemented Modules

| Module | Location | Status |
|--------|----------|--------|
| **1.1 Foundation & Config** | `backend/core/` | Complete |
| **1.1 FastAPI Application Factory** | `backend/api/app.py` | Complete |
| **1.1 Health Endpoints** (`/health`, `/ready`, `/version`) | `backend/api/routes/health.py` | Complete |
| **1.1 Middleware** (CORS, Request-ID, Logging) | `backend/api/middleware.py` | Complete |
| **1.1 Structured Logging** | `backend/core/logging.py` | Complete |
| **1.1 Exception Hierarchy** | `backend/core/exceptions.py` | Complete |
| **1.2 Digital Twin Registry** | `backend/digital_twin/registry.py` | Complete |
| **1.2 Digital Twin Config** | `backend/digital_twin/config.py` | Complete |
| **1.2 Digital Twin Health** | `backend/digital_twin/health.py` | Complete |
| **1.2 Digital Twin Models** | `backend/digital_twin/models.py` | Complete |
| **1.3 Normalization Pipeline** | `backend/normalization/pipeline.py` | Complete |
| **1.3 Telemetry Collector** | `backend/normalization/collector.py` | Complete |
| **1.3 Parsers** (hospital_server, domain_controller, ot_node, attacker) | `backend/normalization/parsers/` | Complete |
| **1.3 Normalized Event Writer** | `backend/normalization/writer.py` | Complete |
| **1.3 CanonicalEvent Schema** | `backend/normalization/models.py` | Complete |
| **2.1 Baseline Builder** | `backend/baseline/builder.py` | Complete |
| **2.1 Baseline Statistics** (Welford online) | `backend/baseline/statistics.py` | Complete |
| **2.1 Baseline Storage** | `backend/baseline/storage.py` | Complete |
| **2.1 Baseline Reader API** | `backend/baseline/reader_api.py` | Complete |
| **2.1 Baseline Service** | `backend/baseline/service.py` | Complete |
| **2.1 Baseline Updater** | `backend/baseline/updater.py` | Complete |
| **2.2 Feature Engine** (56-dimensional vectors) | `backend/features/pipeline.py` | Complete |
| **2.2 Feature Extractors** (temporal, process, network, auth, OT, frequency, entity, baseline) | `backend/features/extractors/` | Complete |
| **2.2 Feature Writer** | `backend/features/writer.py` | Complete |
| **2.2 Feature Service** | `backend/features/service.py` | Complete |
| **2.3 Metrics Collectors** (pipeline, baseline, feature, detection, response, platform_health) | `backend/metrics/collectors/` | Complete |
| **2.3 Metric Store** (append-only JSONL) | `backend/metrics/store.py` | Complete |
| **2.3 Metric Reader** | `backend/metrics/reader.py` | Complete |
| **2.3 Metric Service** | `backend/metrics/service.py` | Complete |

### Test Coverage

| Suite | Tests | Result |
|-------|-------|--------|
| `tests/unit/core/` | 27 | All pass |
| `tests/unit/baseline/` | 232 | All pass |
| `tests/unit/digital_twin/` | 103 | All pass |
| `tests/unit/features/` | 170 | All pass |
| `tests/unit/metrics/` | 101 | All pass |
| `tests/unit/normalization/` | 175 | All pass |
| `tests/unit/shared/` | 57 | All pass |
| `tests/integration/` | 60 | All pass |
| **Total** | **925** | **All pass** |

### Active API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/health` | GET | Liveness probe — always 200 if process is alive |
| `/ready` | GET | Readiness probe — 503 if a component is not ready |
| `/version` | GET | Version and environment information |
| `/docs` | GET | Swagger UI (development mode only) |
| `/redoc` | GET | ReDoc UI (development mode only) |
| `/openapi.json` | GET | OpenAPI schema (development mode only) |

---

## 19. Not Yet Implemented — Phases 3–9

The following modules have skeleton structures or placeholder files but **no business logic** as of Phase 2. Every item below states this clearly.

### Detection Module (`backend/detection/`)

**Not implemented as of Phase 2.**

Planned: Isolation Forest anomaly detection trained on Phase 2 feature vectors. Will consume `FeatureRecord` objects and produce `AnomalyAlert` structures. Feature flag: `FEATURE_DETECTION_ENABLED=false`.

### MITRE ATT&CK Mapping (`backend/mitre/`)

**Not implemented as of Phase 2.**

Planned: Map detected anomalies to MITRE ATT&CK techniques and tactics using the ATT&CK JSON knowledge base stored in `data/attack_reference/`. Feature flag: `FEATURE_MITRE_ENABLED=false`.

### Attack Graph Module (`backend/graph/`)

**Not implemented as of Phase 2.**

Planned: Build attack chains from correlated alerts using NetworkX graph analysis. Feature flag: `FEATURE_GRAPH_ENABLED=false`.

### LLM Enrichment Module (`backend/llm/`)

**Not implemented as of Phase 2.**

Planned: Enrich attack alerts with natural language context using Anthropic Claude. Requires `ANTHROPIC_API_KEY` in `.env`. Feature flag: `FEATURE_LLM_ENABLED=false`.

### Response Orchestration Module (`backend/response/`)

**Not implemented as of Phase 2.**

Planned: Automated containment and remediation actions triggered by confirmed attack chains. Feature flag: `FEATURE_RESPONSE_ENABLED=false`.

### Explainability Module (`backend/explainability/`)

**Not implemented as of Phase 2.**

Planned: SHAP-based feature attribution explaining why each event was flagged as anomalous. Note: requires resolving the `numba`/`coverage` dependency conflict before `shap` can be imported.

### Audit Log Module (`backend/audit/`)

**Not implemented as of Phase 2.**

Planned: Immutable audit trail for all security decisions, API calls, and response actions. Feature flag: `FEATURE_AUDIT_ENABLED=false`.

### Dashboard Module (`backend/dashboard/`)

**Not implemented as of Phase 2.**

Planned: REST API endpoints for real-time dashboard and metrics visualization. Feature flag: `FEATURE_DASHBOARD_ENABLED=false`.

### Ingestion Service (`backend/ingestion/`)

**Not implemented as of Phase 2.**

A placeholder service file exists. Planned: Real-time streaming telemetry ingestion from the Digital Twin via message queue or webhook. Feature flag: `FEATURE_INGESTION_ENABLED=false`.

### Future API Routes

The following routes are commented out in `backend/api/app.py` pending module implementation:

| Route | Module | Status |
|-------|--------|--------|
| `/api/v1/alerts` | ingestion | Not implemented as of Phase 2 |
| `/api/v1/anomalies` | detection | Not implemented as of Phase 2 |
| `/api/v1/attack_chains` | graph | Not implemented as of Phase 2 |
| `/api/v1/enrich` | llm | Not implemented as of Phase 2 |
| `/api/v1/actions` | response | Not implemented as of Phase 2 |
| `/api/v1/metrics` | dashboard | Not implemented as of Phase 2 |

### Database Schema (Alembic Migrations)

**Not implemented as of Phase 4.1.**

`DATABASE_URL` is configured and SQLAlchemy/Alembic are installed. No schema migrations exist yet. All pipeline stages currently use flat files (JSONL/JSON). A relational database will be added when modules requiring persistent relational storage are implemented.

---

## 13. Detection Verification (Isolation Forest)

**Purpose:** Confirm the Isolation Forest anomaly scorer is functional.

```powershell
python -c "
from backend.detection.service import DetectionService
svc = DetectionService()
status = svc.get_model_status()
print('Model status:', status)
"
```

**Expected output (no model trained yet):**
```
Model status: {'trained': False, 'version': None}
```

**Expected output (model trained):**
```
Model status: {'trained': True, 'version': 'v1', 'feature_dim': 56}
```

**Run detection unit tests:**
```powershell
python -m pytest tests/unit/detection/ --no-cov -q
# Expected: 97 passed
```

---

## 14. SHAP Explainability Verification

**Purpose:** Confirm the SHAP explainability layer initialises correctly.

```powershell
python -m pytest tests/unit/explainability/ --no-cov -q
# Expected: 73 passed
```

**Manual import check:**
```powershell
python -c "from backend.explainability import ExplainabilityService; print('SHAP OK')"
```

---

## 15. MITRE ATT&CK Mapper Verification

**Purpose:** Confirm the ATT&CK knowledge base loads and techniques are queryable.

```powershell
python -c "
from backend.mitre.knowledge_base import MitreKnowledgeBase
kb = MitreKnowledgeBase()
print('Techniques loaded:', len(kb.get_all_techniques()))
print('T1110:', kb.get_technique('T1110').name)
print('Version:', kb.version)
"
```

**Expected output:**
```
Techniques loaded: 36
T1110: Brute Force
Version: ATT&CK v15 (2024-10-01)
```

```powershell
python -m pytest tests/unit/mitre/ --no-cov -q
# Expected: 88 passed
```

---

## 16. Attack Graph Verification

**Purpose:** Confirm the attack graph builder initialises and the package imports correctly.

```powershell
python -c "from backend.attack_graph import AttackGraphService; print('Attack Graph OK')"
```

---

## 17. Attack Chain Verification

**Purpose:** Confirm the attack chain detector initialises correctly.

```powershell
python -m pytest tests/unit/chain_detection/ --no-cov -q
# Expected: 106 passed
```

```powershell
python -c "from backend.chain_detection import ChainDetectionService; print('Chain Detection OK')"
```

---

## 18. Synthetic Attack Generation Verification

**Purpose:** Confirm all 10 attack templates generate correctly.

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

**Expected output:**
```
brute_force_auth: 21 events
credential_stuffing: 31 events
lateral_movement_smb: 9 events
privilege_escalation_token: 3 events
persistence_scheduled_task: 2 events
command_execution_powershell: 4 events
network_discovery_scan: 50 events
data_exfiltration_http: 15 events
ot_register_manipulation: 17 events
full_kill_chain_it: 26 events
All templates OK
```

```powershell
python -m pytest tests/unit/synthetic_attack/ --no-cov -q
# Expected: 68 passed
```

---

## 19. Attack Context Verification

**Purpose:** Confirm Module 4.1 builds a valid AttackContext from a minimal alert.

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
print('Context ID:', ctx.context_id[:20])
print('Anomaly score:', ctx.detection.anomaly_score)
print('Completeness:', ctx.completeness.completeness_pct, '%')
print('Entity:', ctx.identity.entity_type, ctx.identity.entity_id)
print('Missing:', [m.component for m in ctx.completeness.missing])
"
```

**Expected output:**
```
Context ID: ctx-XXXXXXXX-XXXX-
Anomaly score: 0.85
Completeness: 33.3 %
Entity: user alice
Missing: ['shap', 'mitre', 'graph', 'chain', 'timeline', 'evidence']
```

```powershell
python -m pytest tests/unit/context/ --no-cov -q
# Expected: 82 passed
```

---

## 20. Directory Structure After Each Stage

---

## Quick Reference

### Essential Commands

```powershell
# Activate environment (every new terminal)
.\.venv\Scripts\Activate.ps1

# Verify all 1541 tests pass
python -m pytest tests/ --no-cov -q -p no:cacheprovider

# Start API server
python -m uvicorn backend.api.app:create_app --factory --port 8000 --reload

# Health check
Invoke-RestMethod http://localhost:8000/health

# Run individual module tests
python -m pytest tests/unit/detection/ --no-cov -q     # 97 tests
python -m pytest tests/unit/explainability/ --no-cov -q # 73 tests
python -m pytest tests/unit/mitre/ --no-cov -q          # 88 tests
python -m pytest tests/unit/chain_detection/ --no-cov -q # 106 tests
python -m pytest tests/unit/synthetic_attack/ --no-cov -q # 68 tests
python -m pytest tests/unit/context/ --no-cov -q        # 82 tests

# Verify MITRE knowledge base
python -c "from backend.mitre.knowledge_base import MitreKnowledgeBase; kb=MitreKnowledgeBase(); print(len(kb.get_all_techniques()), 'techniques loaded')"

# Verify synthetic attack templates (all 10)
python -c "from backend.synthetic_attack import SyntheticAttackService; svc=SyntheticAttackService(persist=False,seed=42); [print(f'{t}: {svc.generate(t,\"h\",\"u\").total_events}') for t in svc.list_templates()]"

# Build a minimal AttackContext
python -c "
from datetime import UTC, datetime
from backend.detection.models import DetectionAlert, EntityKey
from backend.context.service import AttackContextService
alert = DetectionAlert(model_id='iso-v1', entity_key=EntityKey(entity_type='user',entity_id='alice'), event_id='e1', event_type='auth', event_source='win', event_timestamp=datetime.now(UTC), event_host='ws01', event_user='alice', anomaly_score=0.85, raw_if_score=-0.1, threshold_used=0.5, is_alert=True, feature_dimension=10, raw_feature_values={}, novelty_count=0, baseline_available=True)
svc = AttackContextService(persist=False)
ctx = svc.build_context(alert=alert)
print('context_id:', ctx.context_id[:20], '| completeness:', ctx.completeness.completeness_pct, '%')
"
```

### Key Paths

| Path | Purpose |
|------|---------|
| `.env` | All runtime configuration |
| `verify_environment.py` | Environment diagnostic tool |
| `pyproject.toml` | Project metadata, test config, build system |
| `requirements-dev.txt` | Pinned dev + prod dependencies |
| `backend/core/config.py` | Settings class (all environment variables documented) |
| `backend/api/app.py` | FastAPI application factory |
| `data/normalized/` | CanonicalEvent JSONL from normalization pipeline |
| `data/baseline/` | EntityBaseline JSON per entity |
| `data/features/` | FeatureRecord JSONL (56-dimensional vectors) |
| `data/metrics/` | Metric snapshots and history |
| `data/detection/` | Trained Isolation Forest model (.pkl + metadata.json) |
| `data/explanations/` | SHAP ExplanationResult JSONL + index/ |
| `data/mitre/` | MappedAttack JSONL + index/ |
| `data/attack_graph/` | AttackGraph snapshots JSONL + index/ |
| `data/chain_detection/` | AttackChain JSONL + index/ |
| `data/synthetic/` | Synthetic attack execution records |
| `data/context/` | AttackContext JSONL + index/ |
| `docs/SOFTWARE_TEST_PLAN.md` | Complete STP for all modules |
| `docs/attack_context_architecture.md` | Module 4.1 architecture |
| `docs/developer_guide.md` | Coding standards, contracts, gotchas |

---

## 25. Current Implementation Status — Phases 1–4.1 Complete

| Phase | Module | Package | Tests | Status |
|---|---|---|---|---|
| 1.2 | Digital Twin | `backend/digital_twin/` | — | ✅ Complete |
| 1.3 | Normalization | `backend/normalization/` | — | ✅ Complete |
| 2.1 | Baseline Generator | `backend/baseline/` | — | ✅ Complete |
| 2.2 | Feature Engine | `backend/features/` | — | ✅ Complete |
| 2.3 | Metrics Engine | `backend/metrics/` | — | ✅ Complete |
| 2.4 | Isolation Forest | `backend/detection/` | 97 | ✅ Complete |
| 3.2 | SHAP Explainability | `backend/explainability/` | 73 | ✅ Complete |
| 3.3 | MITRE ATT&CK Mapper | `backend/mitre/` | 88 | ✅ Complete |
| 3.4 | Attack Graph Builder | `backend/attack_graph/` | — | ✅ Complete |
| 3.5 | Attack Chain Detection | `backend/chain_detection/` | 106 | ✅ Complete |
| 3.X | Synthetic Attack Gen | `backend/synthetic_attack/` | 68 | ✅ Complete |
| 4.1 | Attack Context | `backend/context/` | 82 | ✅ Complete |
| **Total** | | | **1541** | **✅** |

---

## 26. Not Yet Implemented — Phase 5+

The following modules are **planned but not implemented**. Do not attempt to use them.

| Module | Package | Planned Input | Status |
|--------|---------|---------------|---------|
| LLM Reasoning Agent | `backend/llm/` | `AttackContext` | ⏳ Phase 5 |
| Response Orchestrator | `backend/response/` | LLM output | ⏳ Phase 5 |
| Human Approval | TBD | Response plan | ⏳ Phase 5 |
| Dashboard | `backend/dashboard/` | All module outputs | ⏳ Phase 5 |
| Audit Ledger | TBD | All decisions | ⏳ Phase 5 |
| SOAR Integration | TBD | Approved actions | ⏳ Phase 5 |

---

*Document maintained by the CyberShield engineering team.
Update this file when a new module reaches Phase Complete status or setup procedures change.*
