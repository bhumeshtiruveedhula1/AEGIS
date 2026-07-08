"""
backend.synthetic_attack.service — Synthetic Attack Service
============================================================
Module 3.X — Synthetic Attack Generation

SyntheticAttackService is the single public entry point for all attack generation.
Orchestrates: templates → scheduler → generator → storage.

Usage
-----
    from backend.synthetic_attack.service import SyntheticAttackService
    from backend.synthetic_attack.models import AttackScenario

    svc = SyntheticAttackService()

    # Generate from built-in template
    report = svc.generate(
        template_id="brute_force_auth",
        target_host="workstation-01",
        attacker_user="alice",
    )

    # Extract CanonicalEvents for injection into the detection pipeline
    events = svc.get_canonical_events(report)

    # Stream multiple scenarios
    for execution in svc.generate_stream([scenario_1, scenario_2]):
        events = svc.get_execution_events(execution)
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Iterable

import structlog

from backend.core.config import get_settings
from backend.normalization.models import CanonicalEvent
from backend.synthetic_attack.exceptions import TemplateNotFoundError
from backend.synthetic_attack.generator import AttackGenerator
from backend.synthetic_attack.models import (
    AttackExecution,
    AttackScenario,
    GenerationReport,
)
from backend.synthetic_attack.scheduler import AttackScheduler
from backend.synthetic_attack.storage import SyntheticAttackStore
from backend.synthetic_attack.templates import (
    get_all_templates,
    get_template,
    list_template_ids,
)

logger = structlog.get_logger(__name__)


class SyntheticAttackService:
    """
    Orchestrates attack template selection, scheduling, generation, and persistence.

    Parameters
    ----------
    store_dir   : Override storage root (default: settings.data_dir / "synthetic_attack").
    persist     : Auto-persist executions and report. Default True.
    seed        : RNG seed for deterministic generation. None = non-deterministic.
    """

    def __init__(
        self,
        *,
        store_dir: Path | None = None,
        persist: bool = True,
        seed: int | None = None,
    ) -> None:
        settings = get_settings()
        resolved = store_dir or (settings.data_dir / "synthetic_attack")
        self._store = SyntheticAttackStore(store_dir=resolved)
        self._scheduler = AttackScheduler()
        self._generator = AttackGenerator(seed=seed)
        self._persist = persist
        logger.info(
            "synthetic_attack_service_initialized",
            persist=persist,
            store_dir=str(resolved),
        )

    # ── Status / Template API ─────────────────────────────────────────────────

    def get_status(self) -> dict:
        return {
            "persist": self._persist,
            "available_templates": list_template_ids(),
            "stored_reports": len(self._store.list_reports()),
        }

    def list_templates(self) -> list[str]:
        """Return all available template IDs."""
        return list_template_ids()

    def get_template_info(self, template_id: str) -> dict:
        """Return metadata for one template."""
        tpl = get_template(template_id)
        if tpl is None:
            raise TemplateNotFoundError(
                f"Template {template_id!r} not found.",
                context={"template_id": template_id},
            )
        return {
            "template_id": tpl.template_id,
            "name": tpl.name,
            "description": tpl.description,
            "domain": tpl.domain if isinstance(tpl.domain, str) else tpl.domain.value,
            "mitre_techniques": tpl.mitre_techniques,
            "mitre_tactics": tpl.mitre_tactics,
            "stage_count": len(tpl.stages),
            "tags": tpl.tags,
        }

    # ── Primary API ───────────────────────────────────────────────────────────

    def generate(
        self,
        template_id: str,
        target_host: str,
        attacker_user: str,
        *,
        source_ip: str = "10.0.0.100",
        target_ip: str = "",
        target_user: str = "",
        domain: str = "CORP",
        start_time: datetime | None = None,
        compress_time: bool = True,
        tags: list[str] | None = None,
        persist: bool | None = None,
    ) -> GenerationReport:
        """
        Generate a complete attack scenario from a built-in template.

        Parameters
        ----------
        template_id   : One of list_templates() IDs.
        target_host   : The target host name (e.g. 'workstation-01').
        attacker_user : The attacker's username.
        compress_time : Collapse all delays to zero (ideal for testing).

        Returns
        -------
        GenerationReport with all generated events.
        """
        tpl = get_template(template_id)
        if tpl is None:
            raise TemplateNotFoundError(
                f"Template {template_id!r} not found.",
                context={"template_id": template_id},
            )

        scenario = AttackScenario(
            template_id=template_id,
            name=f"{tpl.name} — {target_host}",
            target_host=target_host,
            attacker_user=attacker_user,
            source_ip=source_ip,
            target_ip=target_ip,
            target_user=target_user,
            domain=domain,
            start_time=start_time or datetime.now(UTC),
            compress_time=compress_time,
            tags=tags or [],
        )
        return self._execute_single(scenario, persist=persist)

    def generate_scenario(
        self,
        scenario: AttackScenario,
        *,
        persist: bool | None = None,
    ) -> GenerationReport:
        """
        Generate from a fully-configured AttackScenario.
        Gives full control over entity bindings and stage overrides.
        """
        return self._execute_single(scenario, persist=persist)

    def generate_batch(
        self,
        scenarios: list[AttackScenario],
        *,
        persist: bool | None = None,
    ) -> GenerationReport:
        """
        Generate multiple scenarios in one report.
        All executions share a single GenerationReport.
        """
        executions: list[AttackExecution] = []

        for scenario in scenarios:
            tpl = self._resolve_template(scenario.template_id)
            schedule = self._scheduler.schedule(scenario, tpl)
            execution = self._generator.generate(scenario, tpl, schedule)
            executions.append(execution)

        should_persist = persist if persist is not None else self._persist
        if should_persist:
            self._store.save_executions_batch(executions)

        report = GenerationReport(
            executions=executions,
            domains_covered=list({
                (self._resolve_template(e.template_id).domain
                 if isinstance(self._resolve_template(e.template_id).domain, str)
                 else self._resolve_template(e.template_id).domain.value)
                for e in executions
            }),
        )
        if should_persist:
            self._store.save_report(report)

        logger.info(
            "batch_generation_complete",
            report_id=report.report_id,
            total_events=report.total_events,
            scenarios=len(scenarios),
        )
        return report

    def generate_stream(
        self,
        scenarios: Iterable[AttackScenario],
        *,
        persist: bool | None = None,
    ) -> Iterable[AttackExecution]:
        """
        Generate and yield one AttackExecution per scenario.
        Memory-efficient for large scenario sets.
        """
        should_persist = persist if persist is not None else self._persist
        for scenario in scenarios:
            tpl = self._resolve_template(scenario.template_id)
            schedule = self._scheduler.schedule(scenario, tpl)
            execution = self._generator.generate(scenario, tpl, schedule)
            if should_persist:
                self._store.save_execution(execution)
            yield execution

    # ── CanonicalEvent extraction ─────────────────────────────────────────────

    def get_canonical_events(self, report: GenerationReport) -> list[CanonicalEvent]:
        """Extract all CanonicalEvents from a GenerationReport, ordered by timestamp."""
        all_events: list[CanonicalEvent] = []
        for execution in report.executions:
            all_events.extend(self.get_execution_events(execution))
        all_events.sort(key=lambda e: e.timestamp)
        return all_events

    def get_execution_events(self, execution: AttackExecution) -> list[CanonicalEvent]:
        """Extract CanonicalEvents from a single AttackExecution."""
        return self._generator.events_from_execution(execution)

    # ── Query API ─────────────────────────────────────────────────────────────

    def load_report(self, report_id: str) -> GenerationReport:
        return self._store.load_report(report_id)

    def list_reports(self) -> list[str]:
        return self._store.list_reports()

    def load_executions_for_date(self, date: datetime | None = None) -> list[AttackExecution]:
        return self._store.load_executions_for_date(date)

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _execute_single(
        self, scenario: AttackScenario, *, persist: bool | None
    ) -> GenerationReport:
        tpl = self._resolve_template(scenario.template_id)
        schedule = self._scheduler.schedule(scenario, tpl)
        execution = self._generator.generate(scenario, tpl, schedule)

        should_persist = persist if persist is not None else self._persist
        if should_persist:
            self._store.save_execution(execution)

        report = GenerationReport(
            executions=[execution],
            domains_covered=[tpl.domain if isinstance(tpl.domain, str) else tpl.domain.value],
        )
        if should_persist:
            self._store.save_report(report)

        return report

    def _resolve_template(self, template_id: str):
        tpl = get_template(template_id)
        if tpl is None:
            raise TemplateNotFoundError(
                f"Template {template_id!r} not found.",
                context={"template_id": template_id},
            )
        return tpl
