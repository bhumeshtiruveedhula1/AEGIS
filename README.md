# CyberShield — AI-Driven Cyber Resilience Platform
## Critical National Infrastructure Protection

[![CI](https://github.com/your-org/cybershield/actions/workflows/ci.yml/badge.svg)](https://github.com/your-org/cybershield/actions)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://python.org)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Mypy](https://img.shields.io/badge/mypy-strict-blue)](https://mypy.readthedocs.io)

---

## Overview

**CyberShield Autonomous Response (CAR)** is a real-time anomaly detection and autonomous incident response platform for critical national infrastructure (CNI) protection.

It combines:
- **Unsupervised ML** (Isolation Forest) — detects zero-day attacks without labeled data
- **Attack Graph Reasoning** (NetworkX + MITRE ATT&CK) — maps threat chains
- **LLM Analysis** (Anthropic Claude) — explains threats in plain language
- **Human-Gated Response** — SOC analyst approves all autonomous actions

> ⚡ **Current status:** Module 1.1 — Repository Foundation  
> The complete pipeline is implemented incrementally across 4 weeks.

---

## Architecture

```
Log Collection → Normalisation → Feature Engineering → Isolation Forest
      → SHAP Explainability → MITRE ATT&CK Mapping → Attack Graph
      → LLM Reasoning (Claude) → Response Orchestrator
      → Human Approval Gate → Action Execution → Audit Log → Dashboard
```

See [docs/architecture.md](docs/architecture.md) for the full technical diagram.

---

## Quick Start

### Prerequisites

- Python 3.11+
- Docker & Docker Compose
- Git

### 1. Clone and Setup

```bash
git clone https://github.com/your-org/cybershield.git
cd cybershield
chmod +x scripts/setup_dev.sh
./scripts/setup_dev.sh
```

### 2. Configure Environment

```bash
# Edit .env with your settings
nano .env

# At minimum, set:
# SECRET_KEY=<generated-secret>
# ANTHROPIC_API_KEY=<your-key>  (required for Week 3+)
```

### 3. Run the Development Server

```bash
# Activate virtual environment
source .venv/bin/activate

# Start server (hot-reload)
make run
```

The API is now available at:
- **API:** http://localhost:8000
- **Health:** http://localhost:8000/health
- **Docs:** http://localhost:8000/docs

### 4. Run Tests

```bash
make test        # full suite with coverage
make test-fast   # fast, no coverage
make test-unit   # unit tests only
```

### 5. Run Linting

```bash
make lint        # ruff + mypy
```

---

## Project Structure

```
cybershield/
├── backend/
│   ├── core/           # Config, logging, exceptions, health checks
│   ├── shared/         # Types, base models, utilities
│   ├── ingestion/      # [Week 1] Log collection
│   ├── normalization/  # [Week 1] Log parsing & normalisation
│   ├── features/       # [Week 1] Feature engineering
│   ├── detection/      # [Week 2] Isolation Forest
│   ├── explainability/ # [Week 2] SHAP explanations
│   ├── mitre/          # [Week 2] MITRE ATT&CK mapping
│   ├── graph/          # [Week 2] Attack graph reasoning
│   ├── llm/            # [Week 3] Claude enrichment
│   ├── response/       # [Week 3] Response orchestration
│   ├── audit/          # [Week 3] Audit logging
│   ├── dashboard/      # [Week 4] Metrics API
│   └── api/            # FastAPI application layer
├── tests/
│   ├── unit/           # Fast, isolated unit tests
│   └── integration/    # End-to-end HTTP tests
├── data/               # Data artifacts (gitignored)
├── models/             # Trained model files (gitignored)
├── docker/             # Dockerfiles and compose
├── scripts/            # Developer tooling
├── docs/               # Architecture and developer docs
└── reports/            # Generated reports (gitignored)
```

---

## Development Workflow

| Command | Description |
|---------|-------------|
| `make install` | Set up dev environment |
| `make run` | Start dev server with hot-reload |
| `make test` | Run full test suite |
| `make test-fast` | Run tests (no coverage) |
| `make lint` | Run ruff + mypy |
| `make docker-up` | Start services via Docker |
| `make clean` | Remove generated artifacts |
| `make help` | Show all available targets |

---

## Technology Stack

| Layer | Technology |
|-------|-----------|
| Language | Python 3.11+ |
| Web Framework | FastAPI |
| ML | scikit-learn (Isolation Forest) |
| Explainability | SHAP |
| Graph | NetworkX |
| LLM | Anthropic Claude |
| Logging | structlog (JSON) |
| Config | Pydantic Settings |
| Database | SQLite (dev) → PostgreSQL (prod) |
| Container | Docker |
| Testing | pytest + pytest-cov |
| Linting | ruff + mypy |

---

## Documentation

| Document | Description |
|----------|-------------|
| [docs/architecture.md](docs/architecture.md) | Full system architecture |
| [docs/developer_guide.md](docs/developer_guide.md) | Contributing guide |
| [docs/module_contracts.md](docs/module_contracts.md) | Module interfaces |
| [docs/adr/](docs/adr/) | Architecture Decision Records |

---

## Implementation Timeline

| Week | Module | Status |
|------|--------|--------|
| 0 | Learning + Research | ✅ Complete |
| **1** | **1.1 Repository Foundation** | ✅ **This PR** |
| 1 | 1.2–1.4 Log Pipeline + Features | ⏳ Next |
| 2 | 2.x ML + Graph Engine | ⏳ Planned |
| 3 | 3.x LLM + Response | ⏳ Planned |
| 4 | 4.x Polish + Demo | ⏳ Planned |

---

## License

Proprietary — CyberShield Team. All rights reserved.
