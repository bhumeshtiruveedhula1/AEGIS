"""
backend.api.routes.ingestion — Live Single-Event Ingestion Endpoint
====================================================================
Module 8.1 — Live Event Ingestion API

Accepts one synthetic attack event via POST /api/v1/ingest and wires it
through the real detection / context / orchestration pipeline.

Pipeline (per request)
----------------------
1.  Record ingestion_timestamp (MTTD start)
2.  Parse IngestRequest → CanonicalEvent
3.  FeaturePipeline.process_event() → list[FeatureRecord]
4.  Select the user_host FeatureRecord (primary detection dimension)
5.  DetectionService.score_event(record) → DetectionAlert | None
6.  If alert fires:
    a.  MitreService.map_alert()             → MappedAttack
    b.  AttackGraphService.build_graph()     → (graph, snapshot)  [best-effort]
    c.  AttackChainService.detect_from_snapshot() → ChainReport   [best-effort]
    d.  AttackContextService.build_context() → AttackContext (auto-persisted)
    e.  OrchestratorService.orchestrate()   → OrchestratorRecord
    f.  Record alert_emission_timestamp; log MTTD
7.  Return IngestResponse

Constraints
-----------
- DetectionService, OrchestratorService, and ChainDetection internals are
  NOT modified — only their existing public methods are called.
- backend/response/ is not touched.
- Each service is instantiated per-request (all are stateless init,
  cheap to construct, and thread-safe within a single call).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog
from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field

from backend.attack_graph.service import AttackGraphService
from backend.chain_detection.service import AttackChainService
from backend.context.service import AttackContextService
from backend.detection.exceptions import ModelNotTrainedError
from backend.detection.service import DetectionService
from backend.features.pipeline import FeaturePipeline
from backend.mitre.service import MitreService
from backend.normalization.models import CanonicalEvent
from backend.orchestrator.service import OrchestratorService

logger = structlog.get_logger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Input / Output models
# ---------------------------------------------------------------------------


class IngestRequest(BaseModel):
    """
    Synthetic attack event body — matches the shape produced by
    backend/synthetic_attack (fields: event_type, mitre_technique_hint,
    source_ip, target_host, timestamp, synthetic=True, etc.).

    Fields that are not present in the synthetic payload default to safe
    sentinel values so CanonicalEvent construction always succeeds.
    """

    model_config = ConfigDict(extra="allow")

    # --- Core identity (required in CanonicalEvent) ---
    event_type: str = Field(description="Normalised event type, e.g. 'UserLogon'.")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp of the event.",
    )
    source: str = Field(default="synthetic", description="Log source identifier.")
    host: str = Field(default="unknown-host", description="Target / monitored host.")
    # Alias: the synthetic generator uses 'target_host' for the host field
    target_host: str | None = Field(default=None, description="Alias for host.")
    user: str = Field(default="unknown-user", description="Username.")
    resource: str = Field(default="", description="Target resource.")
    action: str = Field(default="unknown", description="Action performed.")
    result: str = Field(default="unknown", description="success | failure | unknown.")

    # --- Network (optional) ---
    src_ip: str | None = Field(default=None, alias="source_ip")
    dst_ip: str | None = Field(default=None)
    port: int | None = Field(default=None)
    protocol: str | None = Field(default=None)

    # --- Process (optional) ---
    process: str | None = Field(default=None)
    parent_process: str | None = Field(default=None)
    command_line: str | None = Field(default=None)

    # --- Auth (optional) ---
    logon_type: str | None = Field(default=None)
    auth_package: str | None = Field(default=None)
    windows_event_id: int | None = Field(default=None)

    # --- Synthetic metadata ---
    mitre_technique_hint: str | None = Field(
        default=None,
        description="MITRE ATT&CK technique ID hint, e.g. 'T1110'.",
    )
    synthetic: bool = Field(default=False)


class IngestResponse(BaseModel):
    """JSON response from POST /api/v1/ingest."""

    alert_fired: bool = Field(description="True if the event scored above threshold.")
    context_id: str | None = Field(default=None, description="Persisted AttackContext ID.")
    alert_id: str | None = Field(default=None, description="DetectionAlert ID.")
    mitre_technique: str | None = Field(
        default=None,
        description="Primary MITRE technique ID if mapped.",
    )
    chain_id: str | None = Field(
        default=None,
        description="AttackChain ID if the event correlated into a chain.",
    )
    orchestration_id: str | None = Field(
        default=None,
        description="OrchestratorRecord ID.",
    )
    time_to_alert_ms: float | None = Field(
        default=None,
        description="Mean time to detect (ingestion → alert emission) in milliseconds.",
    )
    detail: str = Field(default="ok", description="Informational message.")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _to_canonical(body: IngestRequest) -> CanonicalEvent:
    """
    Convert an IngestRequest to a CanonicalEvent for the feature pipeline.

    Maps synthetic-generator field names (source_ip, target_host) to the
    canonical schema. Extra fields are stored in extra_fields.
    """
    resolved_host = body.target_host or body.host

    extra: dict[str, Any] = {}
    if body.mitre_technique_hint:
        extra["mitre_technique_hint"] = body.mitre_technique_hint
    if body.synthetic:
        extra["synthetic"] = True

    return CanonicalEvent(
        timestamp=body.timestamp,
        source=body.source,
        event_type=body.event_type,
        host=resolved_host,
        user=body.user,
        resource=body.resource or resolved_host,
        action=body.action,
        result=body.result,
        src_ip=body.src_ip,
        dst_ip=body.dst_ip,
        port=body.port,
        protocol=body.protocol,
        process=body.process,
        parent_process=body.parent_process,
        command_line=body.command_line,
        logon_type=body.logon_type,
        auth_package=body.auth_package,
        windows_event_id=body.windows_event_id,
        extra_fields=extra,
    )


def _select_feature_record(records: list):
    """
    Return the user_host FeatureRecord if present, else the first record.
    user_host is the primary detection dimension for the trained IF model.
    """
    for r in records:
        if r.entity_key.entity_type == "user_host":
            return r
    return records[0] if records else None


# ---------------------------------------------------------------------------
# Route
# ---------------------------------------------------------------------------


@router.post(
    "/",
    response_model=IngestResponse,
    summary="Ingest one synthetic attack event",
    description=(
        "Accepts a single synthetic attack event, runs it through the "
        "detection / context / orchestration pipeline, and returns whether "
        "an alert fired and the associated context / chain IDs."
    ),
)
async def ingest_event(request: Request, body: IngestRequest) -> IngestResponse:
    """
    POST /api/v1/ingest — live single-event ingestion.

    Returns 200 in all cases (even when no model is loaded or the event
    scores as normal). Check alert_fired in the response body.
    """
    ingestion_ts = datetime.now(UTC)

    # Read app-level settings injected by create_app() so that test
    # fixtures can override models_dir / data_dir without touching env vars.
    app_settings = getattr(request.app.state, "settings", None)
    models_dir = getattr(app_settings, "models_dir", None)
    data_dir = getattr(app_settings, "data_dir", None)

    log = logger.bind(
        event_type=body.event_type,
        user=body.user,
        host=body.target_host or body.host,
        mitre_hint=body.mitre_technique_hint,
    )
    log.info("ingest_event_received")

    # --- Step 2: Convert to CanonicalEvent ---
    try:
        canonical = _to_canonical(body)
    except Exception as exc:
        log.warning("ingest_canonical_conversion_failed", error=str(exc))
        return IngestResponse(
            alert_fired=False,
            detail=f"Event parsing failed: {exc}",
        )

    # --- Step 3: Feature extraction ---
    try:
        pipeline = FeaturePipeline()
        records = pipeline.process_event(canonical)
    except Exception as exc:
        log.warning("ingest_feature_extraction_failed", error=str(exc))
        return IngestResponse(
            alert_fired=False,
            detail=f"Feature extraction failed: {exc}",
        )

    if not records:
        log.info("ingest_no_feature_records", detail="Empty feature record list.")
        return IngestResponse(alert_fired=False, detail="No feature records produced.")

    # --- Step 4: Select primary record (user_host dimension) ---
    record = _select_feature_record(records)
    if record is None:
        return IngestResponse(alert_fired=False, detail="No usable feature record.")

    # --- Step 5: Anomaly detection ---
    try:
        det_svc = DetectionService(models_dir=models_dir)
        alert = det_svc.score_event(record)
    except ModelNotTrainedError:
        log.info(
            "ingest_no_model",
            detail="No trained model found. Returning alert_fired=False.",
        )
        return IngestResponse(
            alert_fired=False,
            detail="No trained detection model available. Train a model first.",
        )
    except Exception as exc:
        log.warning("ingest_scoring_error", error=str(exc))
        return IngestResponse(
            alert_fired=False,
            detail=f"Scoring error: {exc}",
        )

    if alert is None or not alert.is_alert:
        log.info("ingest_event_normal", detail="Event scored as normal (below threshold).")
        return IngestResponse(alert_fired=False, detail="Event scored as normal.")

    log.info(
        "ingest_alert_fired",
        alert_id=alert.alert_id,
        anomaly_score=alert.anomaly_score,
        entity_key=str(alert.entity_key),
    )

    # --- Step 6a: MITRE ATT&CK mapping (best-effort) ---
    mapped = None
    primary_technique: str | None = None
    try:
        mapped = MitreService().map_alert(alert)
        if mapped and mapped.techniques:
            primary_technique = mapped.techniques[0].technique_id
        log.info("ingest_mitre_mapped", technique=primary_technique)
    except Exception as exc:
        log.warning("ingest_mitre_failed", error=str(exc))

    # --- Step 6b/c: Attack graph + chain detection (best-effort) ---
    chain = None
    chain_id: str | None = None
    if mapped is not None:
        try:
            graph_svc = AttackGraphService(
                store_dir=(data_dir / "attack_graph" if data_dir else None),
                persist=False,
            )
            _graph, snapshot = graph_svc.build_graph([mapped])
            chain_svc = AttackChainService(
                store_dir=(data_dir / "chain_detection" if data_dir else None),
                persist=False,
                min_chain_length=1,
            )
            chain_report = chain_svc.detect_from_snapshot(snapshot, persist=False)
            if chain_report.chains:
                chain = chain_report.chains[0]
                chain_id = chain.chain_id
                log.info("ingest_chain_detected", chain_id=chain_id)
        except Exception as exc:
            log.warning("ingest_chain_detection_failed", error=str(exc))

    # --- Step 6d: Build and persist AttackContext ---
    try:
        ctx_svc = AttackContextService(
            store_dir=(data_dir / "context" if data_dir else None),
            persist=True,
        )
        ctx = ctx_svc.build_context(
            alert=alert,
            mapped=mapped,
            chain=chain,
            feature_record=record,
        )
        log.info("ingest_context_persisted", context_id=ctx.context_id)
    except Exception as exc:
        log.error("ingest_context_build_failed", error=str(exc))
        return IngestResponse(
            alert_fired=True,
            alert_id=alert.alert_id,
            mitre_technique=primary_technique,
            chain_id=chain_id,
            detail=f"Context build failed: {exc}",
        )

    # --- Step 6e: Orchestrate ---
    orch_id: str | None = None
    try:
        orch_record = OrchestratorService(
            store_dir=(data_dir / "orchestrator" if data_dir else None),
        ).orchestrate(ctx)
        orch_id = orch_record.orchestration_id
        log.info("ingest_orchestrated", orchestration_id=orch_id)
    except Exception as exc:
        log.warning("ingest_orchestration_failed", error=str(exc))

    # --- Step 6f: MTTD ---
    alert_emission_ts = datetime.now(UTC)
    mttd_ms = (alert_emission_ts - ingestion_ts).total_seconds() * 1000

    log.info(
        "mttd_recorded",
        ingestion_timestamp=ingestion_ts.isoformat(),
        alert_emission_timestamp=alert_emission_ts.isoformat(),
        mttd_ms=round(mttd_ms, 2),
        alert_id=alert.alert_id,
        context_id=ctx.context_id,
    )

    return IngestResponse(
        alert_fired=True,
        context_id=ctx.context_id,
        alert_id=alert.alert_id,
        mitre_technique=primary_technique,
        chain_id=chain_id,
        orchestration_id=orch_id,
        time_to_alert_ms=round(mttd_ms, 2),
        detail="ok",
    )
