# Dashboard Architecture
## CyberShield Operational Dashboard — Module 7.1

> **Read-only visualization layer.** The dashboard consumes existing backend module
> outputs via FastAPI JSON endpoints. No business logic is duplicated in the frontend.

---

## 1. Architecture Overview

```
Browser
  │  GET /           → FastAPI serves frontend/index.html
  │  GET /static/*   → FastAPI serves frontend/static/{css,js}
  │
  └─► frontend/static/js/dashboard.js
        │
        │  fetch /api/v1/dashboard/*
        │
        └─► backend/api/routes/dashboard.py (read-only router)
              │
              ├─► ContextStore      → AttackContext records (JSONL)
              ├─► OrchestratorStore → OrchestratorRecord records (JSONL)
              └─► MetricService     → MetricSnapshot (latest + history)
```

The dashboard has **two layers**:
1. **Backend API** (`backend/api/routes/dashboard.py`) — 7 read-only endpoints
2. **Frontend** (`frontend/`) — single-page HTML/CSS/JS app

---

## 2. Backend API Endpoints

All endpoints are mounted at `/api/v1/dashboard/`.

| Method | Path | Description | Source |
|--------|------|-------------|--------|
| GET | `/overview` | Platform summary counters | `MetricStore`, `OrchestratorStore` |
| GET | `/incidents` | Recent detection alerts | `ContextStore` |
| GET | `/metrics` | Latest `MetricSnapshot` | `MetricStore` |
| GET | `/chains` | Recent attack chains | `ContextStore` |
| GET | `/context/{id}` | Full `AttackContext` by ID | `ContextStore` |
| GET | `/orchestrator` | Recent `OrchestratorRecord` list | `OrchestratorStore` |
| GET | `/orchestrator/{id}` | Single `OrchestratorRecord` | `OrchestratorStore` |

### Design Rules

- **Read-only**: No POST/PUT/DELETE. No state mutation.
- **No recomputation**: All data is read from existing storage. No re-running pipeline logic.
- **Graceful empty states**: All endpoints return 200 with empty lists if no data is present. Only 404 is returned when a specific ID is requested and not found.
- **Date coverage**: Endpoints load today + yesterday to ensure recently-created records are always visible.

---

## 3. Frontend Component Hierarchy

```
index.html
├── <nav>           Navigation bar (tabs + refresh + clock + status dot)
├── <main>          Panel container
│   ├── #panel-overview      Platform Overview (KPI grid + approval bar + health grid)
│   ├── #panel-incidents     Active Incidents (data table with scores)
│   ├── #panel-chains        Attack Chain View (step-by-step nodes)
│   ├── #panel-graph         Attack Graph (Canvas 2D)
│   ├── #panel-mitre         MITRE ATT&CK (tactic chips + technique table)
│   ├── #panel-shap          SHAP Explainability (feature attribution bars)
│   ├── #panel-context       Attack Context (property cards)
│   ├── #panel-orchestrator  Response Orchestrator (record cards)
│   └── #panel-metrics       Metrics Panel (domain cards)
├── <aside>         Detail Drawer (slide-in for orchestration details)
└── #toast-container Toast notifications
```

---

## 4. Data Flow

### Initial Load

```
DOMContentLoaded
  → refreshAll()
      → loadOverview()      GET /api/v1/dashboard/overview
      → loadIncidents()     GET /api/v1/dashboard/incidents
      → loadChains()        GET /api/v1/dashboard/chains
      → loadOrchestrations() GET /api/v1/dashboard/orchestrator
      → loadMetrics()       GET /api/v1/dashboard/metrics
  → setInterval(refreshAll, 30_000)
```

### Incident Selection Flow

```
User clicks "View" on Incidents table row
  → selectIncident(contextId)
      → apiFetch(/context/{contextId})
      → contextCache[contextId] = data
      → renderContextPanels(ctx)
          → renderGraphPanel(ctx)    — Canvas 2D graph
          → renderMitrePanel(ctx)    — Tactic chips + technique table
          → renderShapPanel(ctx)     — SHAP bar chart
          → renderContextPanel(ctx)  — Property cards
      → showPanel('graph')
```

---

## 5. State Management

State lives in a single `state` object in `dashboard.js`:

```javascript
const state = {
  activePanel:      'overview',      // Current tab
  selectedContextId: null,           // Drives graph/MITRE/SHAP/context panels
  contextCache:     {},              // contextId → ctx payload (avoids re-fetches)
  refreshTimer:     null,            // setInterval handle
  lastRefresh:      null,            // Date of last refresh
};
```

No external state library. No reactive framework. Mutations are explicit and localized to panel renderers.

---

## 6. Rendering Strategy

- **Vanilla JS** — no framework dependency. Chart.js (CDN) for future chart needs.
- **Canvas 2D** — attack graph is drawn directly on `<canvas>` with a circular layout algorithm. Nodes are positioned evenly on a circle with edge arrows drawn between them.
- **DOM manipulation** — `innerHTML` is used for panel content. All user-provided values are escaped via `esc()` before injection.
- **Auto-refresh** — `refreshAll()` runs every 30 seconds. The attack canvas is re-rendered on window resize.
- **Error resilience** — every `apiFetch()` catches exceptions and returns `null`. Renderers handle `null` by showing empty states, not crashing.

---

## 7. Static File Serving

The FastAPI app (`backend/api/app.py`) mounts the frontend at startup:

```python
app.mount("/static", StaticFiles(directory="frontend/static"), name="static")

@app.get("/")
async def serve_dashboard() -> HTMLResponse:
    return HTMLResponse(content=(frontend_dir / "index.html").read_text())
```

Requirements: `jinja2`, `aiofiles` (both installed as pip dependencies).

---

## 8. Dashboard Panels — Data Mapping

| Panel | Backend Source | Key Fields |
|-------|---------------|------------|
| Overview | `MetricSnapshot` + `OrchestratorStore` | KPI values, health status, approval counts |
| Incidents | `ContextStore` (today + yesterday) | alert_id, severity, anomaly_score, confidence |
| Chains | `ContextStore.chain` | technique_sequence, confidence, length |
| Graph | `AttackContext.graph` | nodes, edges — rendered on Canvas |
| MITRE | `AttackContext.mitre` | tactics, techniques, confidence |
| SHAP | `AttackContext.explainability` | top_features, shap_value, direction |
| Context | `AttackContext` (full) | identity, detection, behavioral, completeness |
| Orchestrator | `OrchestratorStore` | playbook, approval, blast_radius, execution |
| Metrics | `MetricStore.load_latest()` | all domains: pipeline/detection/feature/baseline/health |

---

## 9. Testing Strategy

Tests live in `tests/unit/dashboard/test_dashboard_routes.py`.

- Uses `fastapi.testclient.TestClient` — in-process, no network
- All storage classes are patched via `unittest.mock.patch` — no real disk I/O
- Covers: 200 responses, empty states, 404 not-found, sorting, limit params, error resilience, OpenAPI schema

---

## 10. Extension Guidelines

### Adding a new endpoint
1. Add a route function to `backend/api/routes/dashboard.py`
2. Read from an existing storage class — do not add new business logic
3. Add tests in `tests/unit/dashboard/test_dashboard_routes.py`
4. Add a render function in `frontend/static/js/dashboard.js`
5. Add a panel `<section>` in `frontend/index.html` with matching nav tab

### Adding a new panel section
1. Add `<button>` to `.nav-tabs` in `index.html`
2. Add `<section class="panel" id="panel-{name}">` to `<main>`
3. Add panel ID to `PANELS` array in `dashboard.js`
4. Implement `load{Name}()` and `render{Name}()` functions
5. Call `load{Name}()` inside `refreshAll()`

### Styling conventions
- All new components must use existing CSS variables from `:root`
- No inline colors — use variable references
- No new fonts — Inter + JetBrains Mono only
- Dark theme is non-negotiable — no light-mode components
