/**
 * CyberShield Operational Dashboard — dashboard.js
 * Module 7.1 — Vanilla JS, no framework
 *
 * Data flow: fetch JSON from FastAPI /api/v1/dashboard/* → render into DOM
 * No business logic. Read-only. Deterministic rendering.
 */

'use strict';

/* ─────────────────────────────────────────────────────────────
   Constants
───────────────────────────────────────────────────────────── */
const API = '/api/v1/dashboard';
const REFRESH_INTERVAL_MS = 30_000;

/** Panel-to-tab mapping */
const PANELS = [
  'overview', 'incidents', 'chains', 'graph',
  'mitre', 'shap', 'context', 'orchestrator', 'metrics',
];

/* ─────────────────────────────────────────────────────────────
   State
───────────────────────────────────────────────────────────── */
const state = {
  activePanel: 'overview',
  /** Most recently loaded context ID (shared across panels) */
  selectedContextId: null,
  /** Cache: contextId → full context payload */
  contextCache: {},
  refreshTimer: null,
  lastRefresh: null,
};

/* ─────────────────────────────────────────────────────────────
   Utility helpers
───────────────────────────────────────────────────────────── */

/** Safe fetch — returns parsed JSON or null on error */
async function apiFetch(path) {
  try {
    const res = await fetch(`${API}${path}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn(`[dashboard] fetch failed: ${API}${path}`, err.message);
    return null;
  }
}

/** Format ISO timestamp to "HH:MM:SS DD-Mon" */
function fmtTs(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (isNaN(d)) return iso;
  return d.toLocaleString('en-GB', {
    hour: '2-digit', minute: '2-digit', second: '2-digit',
    day: '2-digit', month: 'short',
  });
}

/** Truncate a string with ellipsis */
function trunc(s, max = 24) {
  if (!s) return '—';
  return s.length > max ? s.slice(0, max) + '…' : s;
}

/** Numeric formatter: round to 3 sig figs */
function fmtNum(v) {
  if (v === null || v === undefined) return '—';
  if (typeof v === 'boolean') return v ? 'Yes' : 'No';
  if (typeof v === 'number') {
    if (Number.isInteger(v)) return v.toLocaleString();
    return v.toPrecision(3);
  }
  return String(v);
}

/** Return CSS class for a severity string */
function severityClass(s) {
  if (!s) return 'unknown';
  const l = String(s).toLowerCase();
  if (l === 'critical') return 'critical';
  if (l === 'high')     return 'high';
  if (l === 'medium')   return 'medium';
  if (l === 'low')      return 'low';
  return 'info';
}

/** Return CSS badge class for approval status */
function approvalClass(s) {
  if (!s) return 'badge-unknown';
  const l = String(s).toLowerCase();
  if (l === 'approved') return 'badge-approved';
  if (l === 'rejected') return 'badge-rejected';
  if (l === 'pending')  return 'badge-pending';
  if (l === 'expired')  return 'badge-expired';
  return 'badge-unknown';
}

/** Escape HTML */
function esc(v) {
  return String(v ?? '—')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/** Score bar HTML — value 0..1 */
function scoreBarHtml(v, color = '#ff3d5a') {
  if (v === null || v === undefined) return '<span class="text-dim">—</span>';
  const pct = Math.round(v * 100);
  return `
    <div class="score-bar-wrap">
      <div class="score-bar">
        <div class="score-bar-fill" style="width:${pct}%;background:${color}"></div>
      </div>
      <span class="score-val">${(+v).toFixed(3)}</span>
    </div>`;
}

/* ─────────────────────────────────────────────────────────────
   Toast
───────────────────────────────────────────────────────────── */
function showToast(msg, type = 'info', ms = 3500) {
  const el = document.createElement('div');
  el.className = `toast toast-${type}`;
  el.textContent = msg;
  const c = document.getElementById('toast-container');
  c.appendChild(el);
  setTimeout(() => { el.style.opacity = '0'; el.style.transition = 'opacity 0.3s'; }, ms - 300);
  setTimeout(() => el.remove(), ms);
}

/* ─────────────────────────────────────────────────────────────
   Navigation
───────────────────────────────────────────────────────────── */
function showPanel(name) {
  PANELS.forEach(p => {
    document.getElementById(`panel-${p}`)?.classList.toggle('active', p === name);
    document.getElementById(`tab-${p}`)?.classList.toggle('active', p === name);
  });
  state.activePanel = name;
  // Lazy-load data when switching to panels that depend on selected context
  if (['graph', 'mitre', 'shap', 'context'].includes(name) && state.selectedContextId) {
    renderContextPanels(state.selectedContextId);
  }
}

/* ─────────────────────────────────────────────────────────────
   Clock
───────────────────────────────────────────────────────────── */
function startClock() {
  const el = document.getElementById('nav-time');
  function tick() {
    const now = new Date();
    el.textContent = now.toLocaleTimeString('en-GB', { hour12: false });
  }
  tick();
  setInterval(tick, 1000);
}

/* ─────────────────────────────────────────────────────────────
   Drawer
───────────────────────────────────────────────────────────── */
function openDrawer(title, html) {
  document.getElementById('drawer-title').textContent = title;
  document.getElementById('drawer-body').innerHTML = html;
  document.getElementById('detail-drawer').classList.add('open');
  document.getElementById('drawer-overlay').classList.add('visible');
}

function closeDrawer() {
  document.getElementById('detail-drawer').classList.remove('open');
  document.getElementById('drawer-overlay').classList.remove('visible');
}

/* ─────────────────────────────────────────────────────────────
   1. Overview Panel
───────────────────────────────────────────────────────────── */
async function loadOverview() {
  const data = await apiFetch('/overview');
  const ts = data?.generated_at;
  const el = document.getElementById('overview-updated');
  if (el) el.textContent = ts ? `Updated ${fmtTs(ts)}` : 'No data';

  if (!data) return;

  const m = data.metrics ?? {};

  // KPI values
  const kpis = {
    'kpi-events-val':    fmtNum(m.events_normalized?.value ?? m.events_normalized),
    'kpi-alerts-val':    fmtNum(m.alerts_generated?.value ?? m.alerts_generated),
    'kpi-high-val':      fmtNum(m.high_severity_alerts?.value ?? m.high_severity_alerts),
    'kpi-chains-val':    fmtNum(m.active_chains?.value ?? m.active_chains),
    'kpi-decisions-val': fmtNum(data.orchestration_today?.total ?? 0),
    'kpi-fpr-val': (() => {
      const v = m.false_positive_rate?.value ?? m.false_positive_rate;
      return v !== null && v !== undefined ? (v * 100).toFixed(1) + '%' : '—';
    })(),
  };
  Object.entries(kpis).forEach(([id, val]) => {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
  });

  // Platform status dot
  const ps = data.platform_status;
  const dot = document.getElementById('status-dot');
  if (dot && ps) {
    const overall = String(ps.overall_status ?? ps).toLowerCase();
    dot.className = 'status-dot ' + (
      overall === 'healthy' ? 'ok' :
      overall === 'degraded' ? 'warn' : 'crit'
    );
  }

  // Approval bar
  renderApprovalBar(data.orchestration_today ?? {});

  // Health grid
  renderHealthGrid(data.platform_status);
}

function renderApprovalBar(orch) {
  const total = orch.total || 0;
  const approved = orch.approved || 0;
  const rejected = orch.rejected || 0;
  const pending  = orch.pending  || 0;

  const barEl = document.getElementById('approval-bar');
  const legEl = document.getElementById('approval-legend');
  if (!barEl || !legEl) return;

  if (total === 0) {
    barEl.innerHTML = '<div style="width:100%;height:100%;background:var(--bg-elevated)"></div>';
    legEl.innerHTML = '<span class="text-dim" style="font-size:12px">No response decisions today</span>';
    return;
  }

  const segments = [
    { key: 'Approved', count: approved, color: 'var(--status-ok)' },
    { key: 'Rejected', count: rejected, color: 'var(--status-crit)' },
    { key: 'Pending',  count: pending,  color: 'var(--info)' },
  ];
  barEl.innerHTML = segments
    .filter(s => s.count > 0)
    .map(s => `<div class="approval-bar-segment" style="width:${(s.count/total*100).toFixed(1)}%;background:${s.color}"></div>`)
    .join('');
  legEl.innerHTML = segments
    .map(s => `
      <div class="approval-legend-item">
        <div class="approval-legend-dot" style="background:${s.color}"></div>
        <span>${s.key}: <strong>${s.count}</strong></span>
      </div>`)
    .join('');
}

function renderHealthGrid(ps) {
  const grid = document.getElementById('health-grid');
  if (!grid) return;
  if (!ps || typeof ps !== 'object') {
    grid.innerHTML = '<div class="health-skeleton">Health data not available</div>';
    return;
  }

  // ps has fields: overall_status, components (dict of name→ComponentHealth)
  const components = ps.components ?? {};
  if (Object.keys(components).length === 0) {
    grid.innerHTML = '<div class="health-skeleton">No component health data</div>';
    return;
  }

  grid.innerHTML = Object.entries(components).map(([name, comp]) => {
    const status = String(comp.status ?? comp).toLowerCase();
    const cls = status === 'healthy' ? 'badge-ok' : status === 'degraded' ? 'badge-warn' : 'badge-warn';
    return `
      <div class="health-card">
        <div class="health-component">${esc(name)}</div>
        <div class="health-status ${cls}">${esc(comp.status ?? status).toUpperCase()}</div>
        ${comp.message ? `<div style="font-size:11px;color:var(--text-muted);margin-top:4px">${esc(comp.message)}</div>` : ''}
      </div>`;
  }).join('');
}

/* ─────────────────────────────────────────────────────────────
   2. Incidents Panel
───────────────────────────────────────────────────────────── */
async function loadIncidents() {
  const data = await apiFetch('/incidents');
  const el = document.getElementById('incidents-updated');
  if (el) el.textContent = data ? `${data.count} incidents — ${fmtTs(data.generated_at)}` : 'Load failed';

  const tbody = document.getElementById('incidents-tbody');
  if (!tbody) return;

  const incidents = data?.incidents ?? [];
  if (incidents.length === 0) {
    tbody.innerHTML = '<tr><td colspan="10" class="table-empty">No incidents found for today</td></tr>';
    return;
  }

  tbody.innerHTML = incidents.map(inc => {
    const sev = severityClass(inc.severity);
    const score = inc.anomaly_score;
    const conf  = inc.detection_confidence;
    return `
      <tr>
        <td><span class="mono" style="font-size:11px">${trunc(inc.alert_id, 16)}</span></td>
        <td><span class="mono">${trunc(inc.entity_id, 20)}</span></td>
        <td>${esc(inc.host ?? '—')}</td>
        <td>${esc(inc.user ?? '—')}</td>
        <td style="font-size:11px">${fmtTs(inc.timestamp)}</td>
        <td><span class="badge badge-${sev}">${esc(inc.severity ?? 'UNKNOWN')}</span></td>
        <td>${scoreBarHtml(score)}</td>
        <td>${conf !== null && conf !== undefined ? (conf * 100).toFixed(1) + '%' : '—'}</td>
        <td><span class="badge badge-info">${esc(inc.status ?? 'ACTIVE')}</span></td>
        <td>
          <button class="btn-link" onclick="selectIncident('${esc(inc.context_id)}')">View</button>
        </td>
      </tr>`;
  }).join('');
}

/* ─────────────────────────────────────────────────────────────
   Incident Selection — drives Graph, MITRE, SHAP, Context
───────────────────────────────────────────────────────────── */
async function selectIncident(contextId) {
  if (!contextId || contextId === '—') return;
  state.selectedContextId = contextId;
  showToast(`Loading context ${trunc(contextId, 20)}…`, 'info', 1800);
  await renderContextPanels(contextId);
  showPanel('graph');
}

async function renderContextPanels(contextId) {
  // Use cache if available
  if (!state.contextCache[contextId]) {
    const data = await apiFetch(`/context/${contextId}`);
    if (!data || !data.context) {
      showToast('Context not found', 'error');
      return;
    }
    state.contextCache[contextId] = data.context;
  }
  const ctx = state.contextCache[contextId];

  renderGraphPanel(ctx);
  renderMitrePanel(ctx);
  renderShapPanel(ctx);
  renderContextPanel(ctx);
}

/* ─────────────────────────────────────────────────────────────
   3. Chains Panel
───────────────────────────────────────────────────────────── */
async function loadChains() {
  const data = await apiFetch('/chains');
  const el = document.getElementById('chains-updated');
  if (el) el.textContent = data ? `${data.count} chains — ${fmtTs(data.generated_at)}` : 'Load failed';

  const container = document.getElementById('chains-container');
  if (!container) return;

  const chains = data?.chains ?? [];
  if (chains.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
        <p>No attack chains detected for today</p>
      </div>`;
    return;
  }

  container.innerHTML = chains.map(ch => {
    const chain = ch.chain ?? {};
    const steps = chain.techniques ?? chain.technique_sequence ?? [];
    const stepsHtml = steps.length > 0
      ? steps.map((step, i) => `
          <div class="chain-step">
            <div class="chain-step-node">
              <div class="chain-step-tactic">${esc(step.tactic ?? step.phase ?? '—')}</div>
              <div class="chain-step-technique">${esc(step.technique_id ?? step.id ?? '—')}</div>
              <div class="chain-step-conf">${step.confidence != null ? (step.confidence * 100).toFixed(0) + '%' : ''}</div>
            </div>
            ${i < steps.length - 1 ? '<div class="chain-arrow">→</div>' : ''}
          </div>`).join('')
      : '<span class="text-dim" style="font-size:12px">No technique sequence available</span>';

    return `
      <div class="chain-card">
        <div class="chain-card-header">
          <div>
            <div class="chain-entity">${esc(ch.entity_id ?? '—')}</div>
            <div class="chain-meta">${fmtTs(ch.timestamp)} · Length: ${steps.length}</div>
          </div>
          <button class="btn-link" onclick="selectIncident('${esc(ch.context_id)}')">Inspect</button>
        </div>
        <div class="chain-steps">${stepsHtml}</div>
      </div>`;
  }).join('');
}

/* ─────────────────────────────────────────────────────────────
   4. Attack Graph Panel (Canvas-based)
───────────────────────────────────────────────────────────── */
function renderGraphPanel(ctx) {
  document.getElementById('graph-empty')?.classList.add('hidden');
  document.getElementById('graph-updated').textContent =
    `Context: ${trunc(ctx.context_id, 24)} — ${fmtTs(ctx.created_at)}`;

  const graph = ctx.graph ?? {};
  const nodes = graph.nodes ?? [];
  const edges = graph.edges ?? graph.relationships ?? [];

  drawGraph(nodes, edges);
  renderGraphLegend(nodes);
}

function drawGraph(nodes, edges) {
  const canvas = document.getElementById('graph-canvas');
  if (!canvas) return;
  const wrapper = document.getElementById('graph-wrapper');
  canvas.width  = wrapper.clientWidth  || 800;
  canvas.height = wrapper.clientHeight || 500;

  const ctx2d = canvas.getContext('2d');
  ctx2d.clearRect(0, 0, canvas.width, canvas.height);

  if (nodes.length === 0) {
    ctx2d.fillStyle = 'rgba(84,106,128,0.5)';
    ctx2d.font = '14px Inter, sans-serif';
    ctx2d.textAlign = 'center';
    ctx2d.fillText('No graph nodes in this context', canvas.width / 2, canvas.height / 2);
    return;
  }

  // Layout: circular
  const cx = canvas.width / 2;
  const cy = canvas.height / 2;
  const r  = Math.min(cx, cy) * 0.65;
  const positions = {};
  nodes.forEach((node, i) => {
    const angle = (2 * Math.PI * i / nodes.length) - Math.PI / 2;
    positions[node.id ?? node.node_id ?? i] = {
      x: cx + r * Math.cos(angle),
      y: cy + r * Math.sin(angle),
      node,
    };
  });

  // Draw edges
  ctx2d.strokeStyle = 'rgba(255,255,255,0.10)';
  ctx2d.lineWidth = 1.5;
  edges.forEach(edge => {
    const src = positions[edge.source ?? edge.from];
    const tgt = positions[edge.target ?? edge.to];
    if (!src || !tgt) return;
    ctx2d.beginPath();
    ctx2d.moveTo(src.x, src.y);
    ctx2d.lineTo(tgt.x, tgt.y);
    ctx2d.stroke();

    // Arrowhead
    const angle = Math.atan2(tgt.y - src.y, tgt.x - src.x);
    const ar = 12;
    ctx2d.beginPath();
    ctx2d.moveTo(tgt.x, tgt.y);
    ctx2d.lineTo(tgt.x - ar * Math.cos(angle - 0.4), tgt.y - ar * Math.sin(angle - 0.4));
    ctx2d.lineTo(tgt.x - ar * Math.cos(angle + 0.4), tgt.y - ar * Math.sin(angle + 0.4));
    ctx2d.closePath();
    ctx2d.fillStyle = 'rgba(255,255,255,0.12)';
    ctx2d.fill();
  });

  // Draw nodes
  Object.values(positions).forEach(({ x, y, node }) => {
    const ntype = String(node.type ?? node.node_type ?? 'entity').toLowerCase();
    const color = ntype.includes('host')  ? '#5b8dff' :
                  ntype.includes('user')  ? '#4caf91' :
                  ntype.includes('tech')  ? '#a78bfa' : '#00d4ff';

    // Glow
    const grd = ctx2d.createRadialGradient(x, y, 0, x, y, 28);
    grd.addColorStop(0, color + '33');
    grd.addColorStop(1, 'transparent');
    ctx2d.beginPath();
    ctx2d.arc(x, y, 28, 0, Math.PI * 2);
    ctx2d.fillStyle = grd;
    ctx2d.fill();

    // Circle
    ctx2d.beginPath();
    ctx2d.arc(x, y, 18, 0, Math.PI * 2);
    ctx2d.fillStyle = 'rgba(13,20,33,0.9)';
    ctx2d.fill();
    ctx2d.strokeStyle = color;
    ctx2d.lineWidth = 2;
    ctx2d.stroke();

    // Label
    const label = trunc(node.label ?? node.id ?? 'node', 12);
    ctx2d.fillStyle = '#e8edf5';
    ctx2d.font = '10px JetBrains Mono, monospace';
    ctx2d.textAlign = 'center';
    ctx2d.fillText(label, x, y + 32);
  });
}

function renderGraphLegend(nodes) {
  const types = [...new Set(nodes.map(n => String(n.type ?? n.node_type ?? 'entity').toLowerCase()))];
  const colors = { host: '#5b8dff', user: '#4caf91', technique: '#a78bfa', entity: '#00d4ff' };
  const legEl = document.getElementById('graph-legend');
  if (!legEl) return;
  legEl.innerHTML = types.map(t => `
    <div class="graph-legend-item">
      <div class="graph-legend-dot" style="background:${colors[t] ?? '#00d4ff'}"></div>
      <span>${t}</span>
    </div>`).join('');
}

/* ─────────────────────────────────────────────────────────────
   5. MITRE ATT&CK Panel
───────────────────────────────────────────────────────────── */
function renderMitrePanel(ctx) {
  const empty   = document.getElementById('mitre-empty');
  const content = document.getElementById('mitre-content');
  if (!empty || !content) return;

  document.getElementById('mitre-updated').textContent =
    `Context: ${trunc(ctx.context_id, 24)}`;

  const mitre = ctx.mitre ?? {};
  const tactics    = mitre.tactics    ?? [];
  const techniques = mitre.techniques ?? mitre.mappings ?? [];

  empty.classList.add('hidden');
  content.classList.remove('hidden');

  // Tactic chips
  document.getElementById('mitre-tactics').innerHTML =
    tactics.length > 0
      ? tactics.map(t => `<div class="mitre-tactic-chip">${esc(t.name ?? t)}</div>`).join('')
      : '<span class="text-dim" style="font-size:12px">No tactics mapped</span>';

  // Techniques table
  const tbody = document.getElementById('mitre-tbody');
  if (!tbody) return;
  tbody.innerHTML = techniques.length > 0
    ? techniques.map(t => `
        <tr>
          <td><span class="badge badge-info">${esc(t.technique_id ?? t.id ?? '—')}</span></td>
          <td>${esc(t.name ?? t.technique_name ?? '—')}</td>
          <td>${esc(t.tactic ?? t.phase ?? '—')}</td>
          <td>${t.confidence != null ? (t.confidence * 100).toFixed(1) + '%' : '—'}</td>
        </tr>`).join('')
    : '<tr><td colspan="4" class="table-empty">No technique mappings</td></tr>';
}

/* ─────────────────────────────────────────────────────────────
   6. SHAP Explainability Panel
───────────────────────────────────────────────────────────── */
function renderShapPanel(ctx) {
  const empty   = document.getElementById('shap-empty');
  const content = document.getElementById('shap-content');
  if (!empty || !content) return;

  document.getElementById('shap-updated').textContent =
    `Context: ${trunc(ctx.context_id, 24)}`;

  // explainability lives in ctx.explainability or ctx.shap
  const expl = ctx.explainability ?? ctx.shap ?? {};
  const features = expl.top_features ?? expl.feature_attributions ?? expl.features ?? [];

  empty.classList.add('hidden');
  content.classList.remove('hidden');

  const barsEl = document.getElementById('shap-bars');
  if (!barsEl) return;

  if (features.length === 0) {
    barsEl.innerHTML = '<div class="text-dim" style="font-size:12px;padding:12px">No SHAP features available for this context</div>';
    return;
  }

  // Find max absolute value for relative scaling
  const maxAbs = Math.max(...features.map(f => Math.abs(f.shap_value ?? f.value ?? 0))) || 1;

  barsEl.innerHTML = features.map(f => {
    const val = f.shap_value ?? f.value ?? 0;
    const pos = val >= 0;
    const pct = (Math.abs(val) / maxAbs * 100).toFixed(1);
    const dirClass = pos ? 'shap-direction-pos' : 'shap-direction-neg';
    const barClass = pos ? 'shap-bar-pos'       : 'shap-bar-neg';
    const dir = pos ? '▲ Increases' : '▼ Decreases';

    return `
      <div class="shap-row">
        <div class="shap-feature" title="${esc(f.feature_name ?? f.name ?? '—')}">${esc(f.feature_name ?? f.name ?? '—')}</div>
        <div class="shap-bar-wrap">
          <div class="shap-bar-fill ${barClass}" style="width:${pct}%"></div>
        </div>
        <div class="shap-value">${val >= 0 ? '+' : ''}${val.toFixed ? val.toFixed(4) : val}</div>
        <div class="shap-direction ${dirClass}">${dir}</div>
      </div>`;
  }).join('');
}

/* ─────────────────────────────────────────────────────────────
   7. Attack Context Panel
───────────────────────────────────────────────────────────── */
function renderContextPanel(ctx) {
  const empty   = document.getElementById('context-empty');
  const content = document.getElementById('context-content');
  if (!empty || !content) return;

  document.getElementById('context-updated').textContent =
    `Context ID: ${trunc(ctx.context_id, 32)}`;

  empty.classList.add('hidden');
  content.classList.remove('hidden');

  const identity  = ctx.identity  ?? {};
  const detection = ctx.detection ?? {};
  const behavioral= ctx.behavioral?? {};
  const mitre     = ctx.mitre     ?? {};
  const chain     = ctx.chain     ?? {};
  const graph     = ctx.graph     ?? {};
  const completeness = ctx.completeness ?? {};

  const sections = [
    {
      title: '🆔 Identity',
      rows: [
        ['Alert ID',   identity.alert_id],
        ['Entity ID',  identity.entity_id],
        ['Host',       identity.host],
        ['User',       identity.user],
        ['Source IP',  identity.source_ip],
        ['Created',    fmtTs(ctx.created_at)],
      ],
    },
    {
      title: '🔍 Detection Summary',
      rows: [
        ['Severity',         detection.severity],
        ['Anomaly Score',    detection.anomaly_score?.toFixed?.(4) ?? detection.anomaly_score],
        ['Confidence',       detection.detection_confidence != null ? (detection.detection_confidence * 100).toFixed(1) + '%' : '—'],
        ['Status',           detection.alert_status],
        ['Baseline Available', detection.baseline_available],
        ['Model ID',         trunc(detection.model_id, 20)],
      ],
    },
    {
      title: '📊 Behavioral Summary',
      rows: [
        ['Baseline Available', behavioral.baseline_available],
        ['Deviation Score',    behavioral.deviation_score?.toFixed?.(4) ?? behavioral.deviation_score],
        ['Pattern',            behavioral.pattern_description ?? behavioral.summary],
      ],
    },
    {
      title: '🗺️ MITRE Summary',
      rows: [
        ['Tactics',        (mitre.tactics ?? []).map(t => t.name ?? t).join(', ') || '—'],
        ['Techniques',     (mitre.techniques ?? []).length],
        ['Primary Tactic', mitre.primary_tactic ?? '—'],
      ],
    },
    {
      title: '⛓️ Chain Summary',
      rows: [
        ['Chain Detected',  chain.chain_detected ?? chain.detected],
        ['Chain Length',    chain.chain_length ?? chain.length],
        ['Confidence',      chain.chain_confidence != null ? (chain.chain_confidence * 100).toFixed(1) + '%' : '—'],
        ['Stages',          chain.stage_count ?? chain.stages],
      ],
    },
    {
      title: '🕸️ Graph Summary',
      rows: [
        ['Nodes',       graph.node_count ?? (graph.nodes ?? []).length],
        ['Edges',       graph.edge_count ?? (graph.edges ?? []).length],
        ['Entity Count', graph.entity_count],
      ],
    },
  ];

  const sectionsEl = document.getElementById('context-sections');
  sectionsEl.innerHTML = sections.map(s => `
    <div class="context-card">
      <div class="context-card-title">${s.title}</div>
      ${s.rows.map(([k, v]) => `
        <div class="context-row">
          <span class="context-row-key">${esc(k)}</span>
          <span class="context-row-val">${esc(v)}</span>
        </div>`).join('')}
    </div>`).join('');

  // Completeness bar
  const pct = typeof completeness === 'number'
    ? completeness * 100
    : (completeness.score ?? completeness.value ?? 0) * 100;
  sectionsEl.innerHTML += `
    <div class="context-card context-completeness">
      <div class="context-card-title">✅ Completeness</div>
      <div class="context-row">
        <span class="context-row-key">Score</span>
        <span class="context-row-val">${pct.toFixed(1)}%</span>
      </div>
      <div class="completeness-bar">
        <div class="completeness-fill" style="width:${Math.min(pct, 100).toFixed(1)}%"></div>
      </div>
    </div>`;
}

/* ─────────────────────────────────────────────────────────────
   8. Orchestrator Panel
───────────────────────────────────────────────────────────── */
async function loadOrchestrations() {
  const data = await apiFetch('/orchestrator');
  const el = document.getElementById('orch-updated');
  if (el) el.textContent = data ? `${data.count} records — ${fmtTs(data.generated_at)}` : 'Load failed';

  const container = document.getElementById('orch-container');
  if (!container) return;

  const records = data?.records ?? [];
  if (records.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/></svg>
        <p>No orchestration records for today</p>
      </div>`;
    return;
  }

  container.innerHTML = records.map(rec => {
    const playbook  = rec.playbook  ?? {};
    const approval  = rec.approval  ?? {};
    const blast     = rec.blast_radius ?? {};
    const execution = rec.execution ?? {};

    const status = String(approval.status ?? 'UNKNOWN').toUpperCase();
    const badgeCls = approvalClass(status);

    return `
      <div class="orch-card" onclick="openOrchDrawer(${JSON.stringify(JSON.stringify(rec))})">
        <div class="orch-card-header">
          <div>
            <div class="orch-playbook">${esc(playbook.name ?? rec.playbook_id ?? '—')}</div>
            <div class="orch-meta">${fmtTs(rec.created_at)} · ${trunc(rec.orchestration_id, 20)}</div>
          </div>
          <span class="badge ${badgeCls}">${esc(status)}</span>
        </div>
        <div class="orch-details">
          <div class="orch-detail-block">
            <div class="orch-detail-label">Blast Scope</div>
            <div class="orch-detail-val">${esc(blast.estimated_scope ?? blast.scope ?? '—')}</div>
          </div>
          <div class="orch-detail-block">
            <div class="orch-detail-label">Affected Hosts</div>
            <div class="orch-detail-val">${esc(blast.affected_hosts ?? blast.host_count ?? '—')}</div>
          </div>
          <div class="orch-detail-block">
            <div class="orch-detail-label">Execution</div>
            <div class="orch-detail-val">${esc(execution?.outcome ?? execution?.status ?? 'NOT EXECUTED')}</div>
          </div>
          <div class="orch-detail-block">
            <div class="orch-detail-label">Decided By</div>
            <div class="orch-detail-val">${esc(approval.decided_by ?? '—')}</div>
          </div>
        </div>
      </div>`;
  }).join('');
}

function openOrchDrawer(jsonStr) {
  const rec = JSON.parse(jsonStr);
  const playbook  = rec.playbook  ?? {};
  const approval  = rec.approval  ?? {};
  const blast     = rec.blast_radius ?? {};
  const execution = rec.execution ?? {};
  const audit     = rec.audit_trail ?? [];

  const rows = (obj, keys) => keys.map(([label, val]) =>
    `<div class="context-row">
      <span class="context-row-key">${esc(label)}</span>
      <span class="context-row-val">${esc(val)}</span>
    </div>`).join('');

  const html = `
    <div style="display:flex;flex-direction:column;gap:16px">
      <div class="context-card">
        <div class="context-card-title">📋 Playbook</div>
        ${rows(playbook, [
          ['Name',        playbook.name ?? rec.playbook_id],
          ['Description', playbook.description],
          ['Severity',    playbook.severity_threshold],
          ['Requires Chain', playbook.requires_chain],
        ])}
      </div>
      <div class="context-card">
        <div class="context-card-title">✅ Approval</div>
        ${rows(approval, [
          ['Status',     approval.status],
          ['Decided By', approval.decided_by],
          ['Decided At', fmtTs(approval.decided_at)],
          ['Expires At', fmtTs(approval.expires_at)],
          ['Reason',     approval.reason],
        ])}
      </div>
      <div class="context-card">
        <div class="context-card-title">💥 Blast Radius</div>
        ${rows(blast, [
          ['Scope',   blast.estimated_scope ?? blast.scope],
          ['Hosts',   blast.affected_hosts],
          ['Users',   blast.affected_users],
          ['Assets',  blast.affected_asset_count ?? blast.asset_count],
          ['OT Risk', blast.ot_risk ?? blast.has_ot],
        ])}
      </div>
      ${execution && Object.keys(execution).length > 0 ? `
      <div class="context-card">
        <div class="context-card-title">⚙️ Execution</div>
        ${rows(execution, [
          ['Status',   execution.status ?? execution.outcome],
          ['Executed At', fmtTs(execution.executed_at)],
          ['Duration ms', execution.duration_ms],
          ['Actions',  (execution.simulated_actions ?? []).length],
        ])}
      </div>` : ''}
      <div class="context-card">
        <div class="context-card-title">📜 Audit Trail (${audit.length} events)</div>
        ${audit.slice(-10).reverse().map(evt => `
          <div class="context-row">
            <span class="context-row-key" style="font-size:10px">${fmtTs(evt.timestamp)}<br><span style="color:var(--accent)">${esc(evt.action ?? evt.event_type)}</span></span>
            <span class="context-row-val">${esc(evt.actor ?? evt.detail ?? '')}</span>
          </div>`).join('') || '<div class="text-dim" style="font-size:12px;padding:8px 0">No audit events</div>'}
      </div>
    </div>`;

  openDrawer(`Response: ${playbook.name ?? rec.playbook_id ?? '—'}`, html);
}

/* ─────────────────────────────────────────────────────────────
   9. Metrics Panel
───────────────────────────────────────────────────────────── */
async function loadMetrics() {
  const data = await apiFetch('/metrics');
  const el = document.getElementById('metrics-updated');
  if (el) el.textContent = data ? `Snapshot — ${fmtTs(data.generated_at)}` : 'Load failed';

  const container = document.getElementById('metrics-domains');
  if (!container) return;

  const snap = data?.snapshot;
  if (!snap) {
    container.innerHTML = `
      <div class="empty-state">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>
        <p>No metrics snapshot available yet. Run the pipeline to generate metrics.</p>
      </div>`;
    return;
  }

  // Domain keys to render
  const DOMAIN_KEYS = ['pipeline', 'baseline', 'feature', 'detection', 'response', 'platform_health'];
  const DOMAIN_LABELS = {
    pipeline:        'Pipeline',
    baseline:        'Baseline',
    feature:         'Feature Engine',
    detection:       'Detection',
    response:        'Response',
    platform_health: 'Platform Health',
  };

  const cards = DOMAIN_KEYS
    .filter(k => snap[k] && typeof snap[k] === 'object')
    .map(domain => {
      const domainData = snap[domain];
      const metrics = Object.entries(domainData)
        .filter(([, v]) => v !== null && typeof v === 'object' && 'value' in v)
        .slice(0, 12); // cap per domain

      const rows = metrics.map(([key, mv]) => `
        <div class="metric-row">
          <span class="metric-name">${esc(key.replaceAll('_', ' '))}</span>
          <span class="metric-val">${fmtNum(mv.value)}</span>
        </div>`).join('');

      return `
        <div class="metric-domain-card">
          <div class="metric-domain-header">${esc(DOMAIN_LABELS[domain] ?? domain)}</div>
          ${rows || '<div class="metric-row"><span class="metric-name text-dim">No metrics</span></div>'}
        </div>`;
    });

  container.innerHTML = cards.length > 0
    ? cards.join('')
    : '<div class="empty-state"><p>No domain metrics available in snapshot</p></div>';
}

/* ─────────────────────────────────────────────────────────────
   Refresh — load all active panels
───────────────────────────────────────────────────────────── */
async function refreshAll() {
  const btn = document.getElementById('btn-refresh');
  btn?.classList.add('spinning');

  const loaders = [
    loadOverview(),
    loadIncidents(),
    loadChains(),
    loadOrchestrations(),
    loadMetrics(),
  ];
  await Promise.allSettled(loaders);

  // Re-render context panels if one is selected
  if (state.selectedContextId) {
    // Invalidate cache so we get fresh data
    delete state.contextCache[state.selectedContextId];
    if (['graph', 'mitre', 'shap', 'context'].includes(state.activePanel)) {
      await renderContextPanels(state.selectedContextId);
    }
  }

  state.lastRefresh = new Date();
  btn?.classList.remove('spinning');
}

/* ─────────────────────────────────────────────────────────────
   Init
───────────────────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  startClock();
  refreshAll();

  // Auto-refresh
  state.refreshTimer = setInterval(refreshAll, REFRESH_INTERVAL_MS);

  // Resize graph canvas on window resize
  window.addEventListener('resize', () => {
    if (state.selectedContextId && state.activePanel === 'graph') {
      const ctx = state.contextCache[state.selectedContextId];
      if (ctx) renderGraphPanel(ctx);
    }
  });
});
