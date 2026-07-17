"""
backend.api.routes.dashboard — Dashboard API Router
====================================================
Module 7.1 — Operational Dashboard

Read-only JSON endpoints consumed by the frontend dashboard.
All data is read from existing backend storage layers.
No business logic is duplicated here.

Endpoints
---------
GET /api/v1/dashboard/overview          — Platform-level summary counters
GET /api/v1/dashboard/incidents         — Active detection alerts (recent)
GET /api/v1/dashboard/metrics           — Latest MetricSnapshot
GET /api/v1/dashboard/chains            — Recent attack chains
GET /api/v1/dashboard/context/{id}      — Single AttackContext by ID
GET /api/v1/dashboard/orchestrator/{id} — Single OrchestratorRecord by ID
GET /api/v1/dashboard/orchestrator      — Recent orchestration records
"""

from __future__ import annotations

import contextlib
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from fastapi import APIRouter, HTTPException, Query

from backend.context.storage import ContextStore
from backend.core.config import get_settings
from backend.metrics.service import MetricService
from backend.orchestrator.storage import OrchestratorStore

logger = structlog.get_logger(__name__)

router = APIRouter()

_SETTINGS = get_settings()


def _context_store() -> ContextStore:
    return ContextStore(get_settings().data_dir / "context")


def _orch_store() -> OrchestratorStore:
    return OrchestratorStore(get_settings().data_dir / "orchestrator")


def _metric_service() -> MetricService:
    return MetricService(store_dir=get_settings().data_dir / "metrics")


# ---------------------------------------------------------------------------
# 1. Platform Overview
# ---------------------------------------------------------------------------


@router.get("/overview", summary="Platform overview counters")
async def get_overview() -> dict[str, Any]:
    """
    Return aggregated platform health counters for the overview panel.
    Reads from MetricStore latest snapshot only — no recomputation.
    """
    svc = _metric_service()
    try:
        snapshot = svc.reader.store.load_latest()
    except Exception:
        snapshot = None

    status = svc.get_platform_status()

    # Extract counters from snapshot safely
    def _safe(snap: Any, *path: str) -> Any:
        if snap is None:
            return None
        obj = snap
        for key in path:
            obj = getattr(obj, key, None)
            if obj is None:
                return None
        return getattr(obj, "value", obj)

    # Collect orchestrator counts from today's records
    orch_store = _orch_store()
    today = datetime.now(UTC).date()
    try:
        orch_today = orch_store.load_for_date(today)
    except Exception:
        orch_today = []

    approved = sum(1 for r in orch_today if r.approval.status == "APPROVED")
    rejected = sum(1 for r in orch_today if r.approval.status == "REJECTED")
    pending = sum(1 for r in orch_today if r.approval.status == "PENDING")

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "platform_status": status if isinstance(status, dict) else (status.model_dump(mode="json") if hasattr(status, "model_dump") else {}),
        "snapshot_available": snapshot is not None,
        "metrics": {
            "events_normalized": _safe(snapshot, "pipeline", "events_normalized"),
            "alerts_generated": _safe(snapshot, "detection", "alerts_total"),
            "high_severity_alerts": _safe(snapshot, "detection", "high_severity_count"),
            "active_chains": _safe(snapshot, "detection", "active_chains"),
            "false_positive_rate": _safe(snapshot, "detection", "false_positive_rate"),
            "pipeline_health": _safe(snapshot, "platform_health", "overall_status"),
        },
        "orchestration_today": {
            "total": len(orch_today),
            "approved": approved,
            "rejected": rejected,
            "pending": pending,
        },
    }


# ---------------------------------------------------------------------------
# 2. Active Incident Panel
# ---------------------------------------------------------------------------


@router.get("/incidents", summary="Recent detection alerts")
async def get_incidents(
    limit: int = Query(default=50, ge=1, le=200),
) -> dict[str, Any]:
    """
    Return recent attack contexts (proxy for active incidents).
    Each AttackContext contains alert, entity, severity, scores, and status.
    """
    ctx_store = _context_store()
    today = datetime.now(UTC).date()
    yesterday = (datetime.now(UTC) - timedelta(days=1)).date()

    records: list[Any] = []
    for date in [today, yesterday]:
        with contextlib.suppress(Exception):
            records.extend(ctx_store.load_for_date(date))

    # Sort by timestamp descending, take limit
    records.sort(key=lambda r: r.created_at, reverse=True)
    records = records[:limit]

    incidents = []
    for ctx in records:
        identity = ctx.identity
        detection = ctx.detection
        incidents.append(
            {
                "context_id": ctx.context_id,
                "alert_id": identity.alert_id,
                "entity_id": identity.entity_id,
                "host": identity.host,
                "user": identity.user,
                "timestamp": ctx.created_at.isoformat(),
                "severity": getattr(detection, "severity", None),
                "anomaly_score": getattr(detection, "anomaly_score", None),
                "detection_confidence": getattr(detection, "detection_confidence", None),
                "status": getattr(detection, "alert_status", "ACTIVE"),
            }
        )

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "count": len(incidents),
        "incidents": incidents,
    }


# ---------------------------------------------------------------------------
# 3. Metrics Panel
# ---------------------------------------------------------------------------


@router.get("/metrics", summary="Latest MetricSnapshot")
async def get_metrics() -> dict[str, Any]:
    """
    Return the latest persisted MetricSnapshot for all domains.
    Reads from MetricStore — no recomputation.
    """
    svc = _metric_service()
    try:
        snapshot = svc.reader.store.load_latest()
    except Exception:
        return {"generated_at": datetime.now(UTC).isoformat(), "snapshot": None}

    if snapshot is None:
        return {"generated_at": datetime.now(UTC).isoformat(), "snapshot": None}

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "snapshot": snapshot.model_dump(mode="json"),
    }


# ---------------------------------------------------------------------------
# 4. Attack Chains Panel
# ---------------------------------------------------------------------------


@router.get("/chains", summary="Recent attack chains")
async def get_chains(
    limit: int = Query(default=20, ge=1, le=100),
) -> dict[str, Any]:
    """
    Return recent AttackContexts that have chain data (attack chain view).
    """
    ctx_store = _context_store()
    today = datetime.now(UTC).date()
    yesterday = (datetime.now(UTC) - timedelta(days=1)).date()

    records: list[Any] = []
    for date in [today, yesterday]:
        with contextlib.suppress(Exception):
            records.extend(ctx_store.load_for_date(date))

    records.sort(key=lambda r: r.created_at, reverse=True)
    records = records[:limit]

    chains = []
    for ctx in records:
        chain_summary = getattr(ctx, "chain", None)
        if chain_summary is None:
            continue
        chains.append(
            {
                "context_id": ctx.context_id,
                "entity_id": ctx.identity.entity_id,
                "timestamp": ctx.created_at.isoformat(),
                "chain": chain_summary.model_dump(mode="json")
                if hasattr(chain_summary, "model_dump")
                else chain_summary,
            }
        )

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "count": len(chains),
        "chains": chains,
    }


# ---------------------------------------------------------------------------
# 5. Context Detail (Attack Graph, SHAP, MITRE, Orchestrator together)
# ---------------------------------------------------------------------------


@router.get("/context/{context_id}", summary="Full AttackContext by ID")
async def get_context(context_id: str) -> dict[str, Any]:
    """
    Return the full AttackContext for a specific context ID.
    Contains graph, MITRE, chain, detection, behavioral, explainability summaries.
    """
    ctx_store = _context_store()
    try:
        ctx = ctx_store.load(context_id)
    except Exception as exc:
        raise HTTPException(status_code=404, detail=f"Context {context_id} not found") from exc

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "context": ctx.model_dump(mode="json"),
    }


# ---------------------------------------------------------------------------
# 6. Orchestrator Panel
# ---------------------------------------------------------------------------


@router.get("/orchestrator", summary="Recent orchestration records")
async def get_orchestrations(
    limit: int = Query(default=20, ge=1, le=100),
) -> dict[str, Any]:
    """
    Return recent OrchestratorRecord entries — playbook, approval, blast radius, execution.
    """
    orch_store = _orch_store()
    today = datetime.now(UTC).date()
    yesterday = (datetime.now(UTC) - timedelta(days=1)).date()

    records: list[Any] = []
    for date in [today, yesterday]:
        with contextlib.suppress(Exception):
            records.extend(orch_store.load_for_date(date))

    records.sort(key=lambda r: r.created_at, reverse=True)
    records = records[:limit]

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "count": len(records),
        "records": [r.model_dump(mode="json") for r in records],
    }


@router.get("/orchestrator/{orchestration_id}", summary="Single orchestration record")
async def get_orchestration(orchestration_id: str) -> dict[str, Any]:
    """Return a specific OrchestratorRecord by its ID."""
    orch_store = _orch_store()
    try:
        record = orch_store.load(orchestration_id)
    except Exception as exc:
        raise HTTPException(
            status_code=404, detail=f"Orchestration {orchestration_id} not found"
        ) from exc

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "record": record.model_dump(mode="json"),
    }
