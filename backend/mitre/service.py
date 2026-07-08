"""
backend.mitre.service — MITRE Mapping Service
=============================================
Module 3.3 — MITRE ATT&CK Mapper

MitreService is the ONLY public entry point for all ATT&CK mapping operations.
Orchestrates MitreMapper + MappingStore.

Usage
-----
    from backend.mitre.service import MitreService
    from backend.detection.models import DetectionAlert, DetectionResult
    from backend.explainability.models import ExplanationResult

    svc = MitreService()

    # Single alert (with or without explanation)
    mapping = svc.map_alert(alert, explanation)

    # Batch (from DetectionResult + matching ExplanationResults)
    report = svc.map_detection_result(detection_result, explanations)

    # Streaming
    for mapped in svc.map_stream(zip(alerts, explanations)):
        downstream_sink.publish(mapped)
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, Iterator

import structlog

from backend.core.config import get_settings
from backend.detection.models import DetectionAlert, DetectionResult
from backend.explainability.models import ExplanationResult
from backend.mitre.mapper import MitreMapper
from backend.mitre.models import MappedAttack, MappingReport
from backend.mitre.storage import MappingStore

logger = structlog.get_logger(__name__)


class MitreService:
    """
    Top-level orchestrator for MITRE ATT&CK mapping.

    Parameters
    ----------
    store_dir     : Override storage directory (defaults to settings.data_dir / "mitre").
    persist       : Auto-persist each MappedAttack and MappingReport.
    min_confidence: Minimum confidence threshold for technique inclusion.
    max_techniques: Maximum techniques per MappedAttack.
    """

    def __init__(
        self,
        *,
        store_dir: Path | None = None,
        persist: bool = True,
        min_confidence: float = 0.10,
        max_techniques: int = 8,
    ) -> None:
        settings = get_settings()
        resolved_dir = store_dir or (settings.data_dir / "mitre")
        self._store = MappingStore(store_dir=resolved_dir)
        self._mapper = MitreMapper(
            min_confidence=min_confidence,
            max_techniques=max_techniques,
        )
        self._persist = persist
        logger.info(
            "mitre_service_initialized",
            persist=persist,
            min_confidence=min_confidence,
            store_dir=str(resolved_dir),
        )

    # ── Status ────────────────────────────────────────────────────────────────

    def get_status(self) -> dict:
        return {
            "kb_techniques": self._mapper._kb.technique_count,
            "kb_tactics": self._mapper._kb.tactic_count,
            "kb_version": self._mapper._kb.version,
            "persist": self._persist,
        }

    # ── Single Alert ──────────────────────────────────────────────────────────

    def map_alert(
        self,
        alert: DetectionAlert,
        explanation: ExplanationResult | None = None,
        *,
        persist: bool | None = None,
    ) -> MappedAttack:
        """
        Map one DetectionAlert to ATT&CK techniques.

        Parameters
        ----------
        alert       : DetectionAlert from Module 2.4.
        explanation : ExplanationResult from Module 3.2 (highly recommended).
        persist     : Override service-level persist flag.

        Returns
        -------
        MappedAttack — always returned, even if techniques list is empty.
        """
        result = self._mapper.map_alert(alert, explanation)

        should_persist = persist if persist is not None else self._persist
        if should_persist:
            self._store.save_mapping(result)

        logger.info(
            "alert_mapped",
            mapping_id=result.mapping_id,
            alert_id=alert.alert_id,
            techniques=len(result.techniques),
            primary=(result.primary_technique.technique.technique_id
                     if result.primary_technique else None),
        )
        return result

    # ── Batch from DetectionResult ────────────────────────────────────────────

    def map_detection_result(
        self,
        detection_result: DetectionResult,
        explanations: list[ExplanationResult] | None = None,
        *,
        persist: bool | None = None,
    ) -> MappingReport:
        """
        Map all alerts in a DetectionResult to a MappingReport.

        Matches explanations to alerts by alert_id.
        Unmatched alerts are mapped without SHAP evidence (graceful degradation).

        Parameters
        ----------
        detection_result : Output of DetectionService.score_batch_from_features().
        explanations     : Optional list of ExplanationResult from Module 3.2.
        persist          : Override persist flag.

        Returns
        -------
        MappingReport — includes per-alert MappedAttack and aggregate statistics.
        """
        alerts = detection_result.alerts
        expl_index: dict[str, ExplanationResult] = {}
        if explanations:
            expl_index = {e.alert_id: e for e in explanations}

        mappings: list[MappedAttack] = []
        errors = 0
        for alert in alerts:
            expl = expl_index.get(alert.alert_id)
            try:
                m = self._mapper.map_alert(alert, expl)
                mappings.append(m)
            except Exception as exc:  # noqa: BLE001
                errors += 1
                logger.warning(
                    "map_detection_result_error",
                    alert_id=alert.alert_id,
                    error=str(exc),
                )

        should_persist = persist if persist is not None else self._persist
        if should_persist and mappings:
            self._store.save_batch(mappings)

        report = MappingReport(
            run_id=detection_result.run_id,
            model_id=detection_result.model_id,
            mappings=mappings,
            errors=errors,
        )

        if should_persist:
            self._store.save_report(report)

        logger.info(
            "detection_result_mapped",
            report_id=report.report_id,
            run_id=detection_result.run_id,
            total_alerts=len(alerts),
            mapped=report.statistics.total_mapped,
            mapping_rate=report.statistics.mapping_rate,
        )
        return report

    def map_alerts_batch(
        self,
        alerts: list[DetectionAlert],
        explanations: list[ExplanationResult] | None = None,
        *,
        persist: bool | None = None,
    ) -> list[MappedAttack]:
        """
        Directly map a list of alerts. Parallel lists — index i matches.

        Returns
        -------
        list[MappedAttack] in input order.
        """
        expl_index: dict[str, ExplanationResult] = {}
        if explanations:
            expl_index = {e.alert_id: e for e in explanations}

        results = self._mapper.map_batch(
            alerts,
            [expl_index.get(a.alert_id) for a in alerts] if expl_index else None,
        )

        should_persist = persist if persist is not None else self._persist
        if should_persist and results:
            self._store.save_batch(results)

        return results

    # ── Streaming ─────────────────────────────────────────────────────────────

    def map_stream(
        self,
        pairs: Iterable[tuple[DetectionAlert, ExplanationResult | None]],
        *,
        persist: bool | None = None,
    ) -> Iterator[MappedAttack]:
        """
        Streaming mapping over (alert, explanation_or_None) pairs.

        Yields MappedAttack objects. Per-pair errors are logged and skipped.

        Usage
        -----
            for mapped in service.map_stream(zip(alert_stream, expl_stream)):
                attack_graph_module.ingest(mapped)
        """
        should_persist = persist if persist is not None else self._persist
        for result in self._mapper.map_stream(pairs):
            if should_persist:
                self._store.save_mapping(result)
            yield result

    # ── Storage delegation ────────────────────────────────────────────────────

    def load_mappings_for_date(self, date=None) -> list[MappedAttack]:
        return self._store.load_mappings_for_date(date)

    def load_report(self, report_id: str) -> MappingReport:
        return self._store.load_report(report_id)

    def list_reports(self) -> list[str]:
        return self._store.list_reports()
