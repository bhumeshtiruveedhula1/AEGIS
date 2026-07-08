"""
backend.synthetic_attack.scheduler — Attack Sequence Scheduler
==============================================================
Module 3.X — Synthetic Attack Generation

AttackScheduler computes realistic stage start times from an AttackScenario + template.

Responsibilities
----------------
- Ordering stages by index (template order = kill chain order)
- Applying inter-stage delays
- Multi-stage timing with optional time compression for testing
- Producing a stage_id → start_time mapping consumed by AttackGenerator

Design constraints
------------------
- No event generation (that's generator.py)
- No I/O, no storage
- Deterministic: same scenario + template → same schedule
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import structlog

from backend.synthetic_attack.exceptions import SchedulingError
from backend.synthetic_attack.models import AttackScenario, AttackStage, AttackTemplate

logger = structlog.get_logger(__name__)


class AttackScheduler:
    """
    Computes stage start times for an attack scenario.
    Returns a dict mapping stage_id → start datetime.
    """

    def schedule(
        self,
        scenario: AttackScenario,
        template: AttackTemplate,
    ) -> dict[str, datetime]:
        """
        Compute start times for all stages in a template.

        Parameters
        ----------
        scenario : The attack scenario, provides start_time and compress_time.
        template : The template containing ordered stages.

        Returns
        -------
        dict[str, datetime] : stage_id → computed start time (UTC).
        """
        if not template.stages:
            raise SchedulingError(
                f"Template {template.template_id!r} has no stages.",
                context={"template_id": template.template_id},
            )

        try:
            schedule: dict[str, datetime] = {}
            current = scenario.start_time
            if current.tzinfo is None:
                current = current.replace(tzinfo=UTC)

            for stage in template.stages:
                # Apply delay from previous stage (or 0 if first stage)
                delay = 0.0 if scenario.compress_time else stage.delay_seconds
                current = current + timedelta(seconds=delay)
                schedule[stage.stage_id] = current

                # Advance cursor: assume all events in this stage occur during its delay window
                # (generator handles intra-stage spreading)
                window = max(stage.delay_seconds, 1.0) if not scenario.compress_time else 0.0
                current = current + timedelta(seconds=window)

            logger.debug(
                "attack_schedule_computed",
                scenario_id=scenario.scenario_id,
                template_id=template.template_id,
                stages=len(schedule),
            )
            return schedule

        except SchedulingError:
            raise
        except Exception as exc:
            raise SchedulingError(
                f"Scheduling failed for scenario {scenario.scenario_id}: {exc}",
                context={"scenario_id": scenario.scenario_id, "cause": str(exc)},
            ) from exc

    def schedule_multi(
        self,
        scenarios: list[tuple[AttackScenario, AttackTemplate]],
    ) -> list[dict[str, datetime]]:
        """Schedule multiple scenarios. Returns one schedule dict per scenario."""
        return [self.schedule(scen, tpl) for scen, tpl in scenarios]

    def compute_total_duration_seconds(
        self,
        template: AttackTemplate,
        compress: bool = False,
    ) -> float:
        """
        Estimate total wall-clock duration of an attack template.

        Parameters
        ----------
        template : The template to estimate.
        compress : If True, returns 0 (compressed time = instant).
        """
        if compress or not template.stages:
            return 0.0
        return sum(
            max(s.delay_seconds, 0.0)
            for s in template.stages
        )
