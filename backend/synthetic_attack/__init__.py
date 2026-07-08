"""backend.synthetic_attack — Synthetic Attack Generation Module."""

from backend.synthetic_attack.exceptions import (
    GenerationError,
    SchedulingError,
    ScenarioValidationError,
    StorageError,
    SyntheticAttackError,
    TemplateNotFoundError,
)
from backend.synthetic_attack.generator import AttackGenerator
from backend.synthetic_attack.models import (
    SYNTHETIC_SCHEMA_VERSION,
    AttackDomain,
    AttackExecution,
    AttackScenario,
    AttackStage,
    AttackTemplate,
    GenerationReport,
)
from backend.synthetic_attack.scheduler import AttackScheduler
from backend.synthetic_attack.service import SyntheticAttackService
from backend.synthetic_attack.storage import SyntheticAttackStore
from backend.synthetic_attack.templates import (
    get_all_templates,
    get_template,
    list_template_ids,
)

__all__ = [
    "SyntheticAttackService",
    "AttackGenerator",
    "AttackScheduler",
    "SyntheticAttackStore",
    "AttackTemplate",
    "AttackScenario",
    "AttackStage",
    "AttackDomain",
    "AttackExecution",
    "GenerationReport",
    "SYNTHETIC_SCHEMA_VERSION",
    "get_template",
    "get_all_templates",
    "list_template_ids",
    "SyntheticAttackError",
    "TemplateNotFoundError",
    "GenerationError",
    "SchedulingError",
    "StorageError",
    "ScenarioValidationError",
]
