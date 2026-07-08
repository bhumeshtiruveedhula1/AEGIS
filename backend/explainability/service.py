"""
backend.explainability.service — Explainability Service
========================================================
Module 3.2 — SHAP Explainability Layer

ExplainabilityService is the ONLY public entry point for all explanation
operations.  Application code and pipeline orchestrators call this service;
never SHAPExplainer or ExplanationStore directly.

Responsibilities
----------------
1. Initialize SHAPExplainer from a loaded _DetectionPipeline.
2. explain_alert()        → single ExplanationResult (streaming mode)
3. explain_detection_result() → ExplainabilityReport (batch mode)
4. explain_stream()       → Iterator[ExplanationResult] (live pipelines)
5. Persist results via ExplanationStore.
6. Expose status for health endpoints.

Architecture
------------
ExplainabilityService
  └── SHAPExplainer      ← SHAP computation only
  └── ExplanationStore   ← persistence only

Usage
-----
    from backend.explainability.service import ExplainabilityService
    from backend.detection.service import DetectionService

    det_svc = DetectionService()
    expl_svc = ExplainabilityService()
    expl_svc.initialize_from_detection_service(det_svc)

    # Single alert
    alert = det_svc.score_event(feature_record)
    if alert:
        explanation = expl_svc.explain_alert(alert, feature_record)

    # Batch
    detection_result = det_svc.score_batch_from_features()
    report = expl_svc.explain_detection_result(detection_result, feature_records)
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, Iterator

import structlog

from backend.core.config import get_settings
from backend.detection.models import DetectionAlert, DetectionResult
from backend.detection.service import DetectionService
from backend.explainability.exceptions import ExplainerNotInitializedError
from backend.explainability.explainer import SHAPExplainer
from backend.explainability.models import ExplainabilityReport, ExplanationResult
from backend.explainability.storage import ExplanationStore
from backend.features.models import FeatureRecord

logger = structlog.get_logger(__name__)


class ExplainabilityService:
    """
    Top-level orchestrator for the SHAP explainability subsystem.

    Parameters
    ----------
    store_dir    : Override the explanations storage directory.
                   Defaults to settings.data_dir / "explanations".
    persist      : If True, automatically persist each ExplanationResult
                   and ExplainabilityReport to ExplanationStore.
                   Set False in tests or when persistence is handled externally.
    top_n        : Number of top features to capture per explanation.
    """

    def __init__(
        self,
        *,
        store_dir: Path | None = None,
        persist: bool = True,
        top_n: int = 5,
    ) -> None:
        settings = get_settings()
        resolved_store_dir = store_dir or (settings.data_dir / "explanations")
        self._store = ExplanationStore(store_dir=resolved_store_dir)
        self._persist = persist
        self._top_n = top_n
        self._explainer: SHAPExplainer | None = None

        logger.info(
            "explainability_service_initialized",
            persist=persist,
            top_n=top_n,
            store_dir=str(resolved_store_dir),
        )

    # ── Initialization ────────────────────────────────────────────────────────

    def initialize_from_detection_service(
        self,
        detection_service: DetectionService,
    ) -> None:
        """
        Initialize the SHAPExplainer from a loaded DetectionService.

        The DetectionService must have a model loaded (is_model_loaded=True).
        Reads the pipeline and model_id directly — no re-loading from disk.

        Parameters
        ----------
        detection_service : A DetectionService with a model loaded.

        Raises
        ------
        ValueError if detection_service has no model loaded.
        """
        if not detection_service.is_model_loaded:
            raise ValueError(
                "DetectionService has no model loaded. "
                "Call train_from_features() or reload_model() first."
            )
        pipeline = detection_service._scorer._pipeline  # type: ignore[union-attr]
        model_id = detection_service.current_model_id  # type: ignore[assignment]

        self._explainer = SHAPExplainer(
            pipeline=pipeline,
            model_id=model_id,
            top_n=self._top_n,
        )
        logger.info(
            "explainability_initialized_from_detection_service",
            model_id=model_id,
        )

    def initialize_from_pipeline(
        self,
        pipeline: object,
        model_id: str,
    ) -> None:
        """
        Initialize from a raw _DetectionPipeline and model_id.
        Use when composing services outside of DetectionService.
        """
        self._explainer = SHAPExplainer(
            pipeline=pipeline,
            model_id=model_id,
            top_n=self._top_n,
        )
        logger.info(
            "explainability_initialized_from_pipeline",
            model_id=model_id,
        )

    # ── Status ────────────────────────────────────────────────────────────────

    @property
    def is_initialized(self) -> bool:
        """True if SHAPExplainer is ready for use."""
        return self._explainer is not None

    @property
    def current_model_id(self) -> str | None:
        return self._explainer.model_id if self._explainer else None

    def get_status(self) -> dict:
        """Compact status dict for health endpoints."""
        return {
            "initialized": self.is_initialized,
            "model_id": self.current_model_id,
            "persist": self._persist,
            "top_n": self._top_n,
        }

    # ── Single Alert API ──────────────────────────────────────────────────────

    def explain_alert(
        self,
        alert: DetectionAlert,
        feature_record: FeatureRecord,
        *,
        persist: bool | None = None,
    ) -> ExplanationResult:
        """
        Explain a single DetectionAlert using SHAP TreeExplainer.

        Parameters
        ----------
        alert          : The DetectionAlert to explain.
        feature_record : Corresponding FeatureRecord (same event).
        persist        : Override the service-level persist flag for this call.

        Returns
        -------
        ExplanationResult — fully populated SHAP explanation.

        Raises
        ------
        ExplainerNotInitializedError if service not yet initialized.
        """
        self._require_explainer()
        result = self._explainer.explain_alert(alert, feature_record)  # type: ignore[union-attr]

        should_persist = persist if persist is not None else self._persist
        if should_persist:
            self._store.save_explanation(result)

        logger.info(
            "alert_explained",
            explanation_id=result.explanation_id,
            alert_id=alert.alert_id,
            top_features=result.top_features[:3],
            total_abs_shap=round(result.total_abs_shap, 4),
        )
        return result

    # ── Batch API ─────────────────────────────────────────────────────────────

    def explain_detection_result(
        self,
        detection_result: DetectionResult,
        feature_records: list[FeatureRecord],
        *,
        persist: bool | None = None,
    ) -> ExplainabilityReport:
        """
        Explain all alerts in a DetectionResult batch.

        Builds a parallel list from detection_result.alerts and matches
        feature_records by event_id.  Unmatched alerts are skipped and logged.

        Parameters
        ----------
        detection_result : Output of DetectionService.score_batch_from_features().
        feature_records  : All FeatureRecord objects used during that scoring pass.
        persist          : Override persist flag.

        Returns
        -------
        ExplainabilityReport — aggregate of all ExplanationResults.

        Raises
        ------
        ExplainerNotInitializedError if service not yet initialized.
        """
        self._require_explainer()

        alerts = detection_result.alerts
        if not alerts:
            logger.info(
                "no_alerts_to_explain",
                run_id=detection_result.run_id,
            )
            return ExplainabilityReport(
                run_id=detection_result.run_id,
                model_id=detection_result.model_id,
                explanations=[],
            )

        # Build event_id → FeatureRecord lookup
        record_index: dict[str, FeatureRecord] = {
            r.event_id: r for r in feature_records
        }

        matched_alerts: list[DetectionAlert] = []
        matched_records: list[FeatureRecord] = []
        unmatched = 0

        for alert in alerts:
            rec = record_index.get(alert.event_id)
            if rec is None:
                unmatched += 1
                logger.warning(
                    "alert_record_unmatched",
                    alert_id=alert.alert_id,
                    event_id=alert.event_id,
                )
                continue
            matched_alerts.append(alert)
            matched_records.append(rec)

        explanations = self._explainer.explain_batch(  # type: ignore[union-attr]
            matched_alerts, matched_records
        )

        should_persist = persist if persist is not None else self._persist
        if should_persist and explanations:
            self._store.save_batch(explanations)

        report = ExplainabilityReport(
            run_id=detection_result.run_id,
            model_id=detection_result.model_id,
            explanations=explanations,
            errors=unmatched + (len(matched_alerts) - len(explanations)),
        )

        if should_persist:
            self._store.save_report(report)

        logger.info(
            "detection_result_explained",
            report_id=report.report_id,
            run_id=detection_result.run_id,
            alerts_explained=report.alerts_explained,
            errors=report.errors,
            top_global_features=report.top_global_features[:3],
        )
        return report

    def explain_alerts_batch(
        self,
        alerts: list[DetectionAlert],
        feature_records: list[FeatureRecord],
        *,
        persist: bool | None = None,
    ) -> list[ExplanationResult]:
        """
        Directly explain a list of DetectionAlert objects.
        Parallel lists — index i of alerts corresponds to index i of feature_records.

        Returns
        -------
        list[ExplanationResult] in input order.
        """
        self._require_explainer()
        results = self._explainer.explain_batch(alerts, feature_records)  # type: ignore[union-attr]

        should_persist = persist if persist is not None else self._persist
        if should_persist and results:
            self._store.save_batch(results)

        return results

    # ── Streaming API ─────────────────────────────────────────────────────────

    def explain_stream(
        self,
        alert_record_pairs: Iterable[tuple[DetectionAlert, FeatureRecord]],
        *,
        persist: bool | None = None,
    ) -> Iterator[ExplanationResult]:
        """
        Streaming explanation over an iterable of (alert, record) pairs.

        Yields ExplanationResult for each pair. Errors on individual pairs
        are logged and skipped — never fatal.

        Parameters
        ----------
        alert_record_pairs : Iterable of (DetectionAlert, FeatureRecord) tuples.
        persist            : Override persist flag.

        Yields
        ------
        ExplanationResult objects in arrival order.

        Usage
        -----
            for expl in service.explain_stream(
                zip(alert_stream, record_stream)
            ):
                downstream_sink.publish(expl)
        """
        self._require_explainer()
        should_persist = persist if persist is not None else self._persist
        emitted = 0

        for alert, record in alert_record_pairs:
            try:
                result = self._explainer.explain_alert(alert, record)  # type: ignore[union-attr]
                if should_persist:
                    self._store.save_explanation(result)
                emitted += 1
                yield result
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "stream_explain_error",
                    alert_id=alert.alert_id,
                    error=str(exc),
                )

        logger.info("stream_explanation_complete", emitted=emitted)

    # ── Storage query delegation ──────────────────────────────────────────────

    def load_explanations_for_date(
        self, date=None
    ) -> list[ExplanationResult]:
        """Load persisted explanations for a given date (defaults to today)."""
        return self._store.load_explanations_for_date(date)

    def load_report(self, report_id: str) -> ExplainabilityReport:
        """Load a persisted ExplainabilityReport by ID."""
        return self._store.load_report(report_id)

    def list_reports(self) -> list[str]:
        """Return all persisted report IDs."""
        return self._store.list_reports()

    # ── Internal ──────────────────────────────────────────────────────────────

    def _require_explainer(self) -> None:
        """Raise ExplainerNotInitializedError if not yet initialized."""
        if self._explainer is None:
            raise ExplainerNotInitializedError(
                "ExplainabilityService is not initialized. "
                "Call initialize_from_detection_service() or initialize_from_pipeline().",
                context={},
            )
