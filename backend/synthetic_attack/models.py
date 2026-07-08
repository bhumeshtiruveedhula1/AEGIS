"""
backend.synthetic_attack.models — Synthetic Attack Data Models
===============================================================
Module 3.X — Synthetic Attack Generation

Pure data models. No generation logic.

Hierarchy
---------
AttackTemplate
  └── stages: [AttackStage]  ← defines what to generate

AttackScenario
  └── template_id + overrides ← a configured instantiation

AttackExecution
  └── scenario + events: [CanonicalEvent] ← the generated output

GenerationReport
  └── executions[] + statistics ← batch reporting

Schema Version: 1.0.0
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import ConfigDict, Field

from backend.shared.models import CyberShieldBaseModel
from backend.shared.utils.id_utils import generate_id

SYNTHETIC_SCHEMA_VERSION = "1.0.0"


# ---------------------------------------------------------------------------
# AttackDomain — broad category of the attack
# ---------------------------------------------------------------------------

class AttackDomain(str, Enum):
    IT = "it"                    # Standard IT attacks
    AUTHENTICATION = "auth"      # Authentication / credential attacks
    PROCESS = "process"          # Process / execution attacks
    NETWORK = "network"          # Network lateral movement / exfil
    OT_ICS = "ot_ics"            # Operational Technology / ICS attacks


# ---------------------------------------------------------------------------
# AttackStage — one step inside a template
# ---------------------------------------------------------------------------

class AttackStage(CyberShieldBaseModel):
    """
    Defines one logical step in an attack template.
    Does NOT contain generated events — only the description of what to generate.
    """

    model_config = ConfigDict(protected_namespaces=())

    stage_id: str = Field(default_factory=lambda: f"stg-{generate_id()}")
    name: str
    description: str = Field(default="")
    source: str = Field(..., description="CanonicalEvent.source value, e.g. 'windows'")
    event_type: str = Field(..., description="CanonicalEvent.event_type, e.g. 'authentication'")
    action: str = Field(..., description="e.g. 'logon_failure'")
    result: str = Field(default="success")
    event_count: int = Field(default=1, ge=1, le=1000)
    delay_seconds: float = Field(
        default=0.0, ge=0.0,
        description="Seconds after previous stage before this stage starts"
    )
    # Field templates — use {entity} substitution tokens
    host_template: str = Field(default="{target_host}")
    user_template: str = Field(default="{attacker_user}")
    resource_template: str = Field(default="")
    # Optional OT/ICS fields
    modbus_register: int | None = Field(default=None)
    modbus_value: int | None = Field(default=None)
    modbus_function_code: int | None = Field(default=None)
    # Optional process fields
    process_template: str = Field(default="")
    command_line_template: str = Field(default="")
    # Optional network fields
    src_ip_template: str = Field(default="")
    dst_ip_template: str = Field(default="")
    port: int | None = Field(default=None)
    protocol: str = Field(default="")
    # MITRE hint — the technique this stage corresponds to
    mitre_technique_hint: str = Field(default="", description="e.g. T1110")
    mitre_tactic_hint: str = Field(default="", description="e.g. TA0006")
    # Extra context carried through to CanonicalEvent.extra_fields
    extra_context: dict[str, Any] = Field(default_factory=dict)
    # Hint fields used during generation to populate specific CanonicalEvent columns
    logon_type_hint: str = Field(default="")
    auth_package_hint: str = Field(default="")
    windows_event_id_hint: int | None = Field(default=None)
    bytes_out_hint: int = Field(default=0, ge=0)


# ---------------------------------------------------------------------------
# AttackTemplate — a reusable multi-stage attack blueprint
# ---------------------------------------------------------------------------

class AttackTemplate(CyberShieldBaseModel):
    """
    A reusable blueprint for a multi-stage attack scenario.
    Templates are defined in templates.py and referenced by ID.
    """

    model_config = ConfigDict(protected_namespaces=())

    template_id: str = Field(..., description="Stable unique identifier, e.g. 'brute_force_auth'")
    name: str
    description: str = Field(default="")
    domain: AttackDomain
    mitre_techniques: list[str] = Field(
        default_factory=list,
        description="ATT&CK technique IDs this template exercises"
    )
    mitre_tactics: list[str] = Field(default_factory=list)
    stages: list[AttackStage] = Field(default_factory=list, min_length=1)
    version: str = Field(default="1.0.0")
    tags: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# AttackScenario — a configured instantiation of a template
# ---------------------------------------------------------------------------

class AttackScenario(CyberShieldBaseModel):
    """
    A configured instantiation of an AttackTemplate.
    Binds entity values (target_host, attacker_user, etc.) and overrides.
    """

    model_config = ConfigDict(protected_namespaces=())

    scenario_id: str = Field(default_factory=lambda: f"scen-{generate_id()}")
    schema_version: str = Field(default=SYNTHETIC_SCHEMA_VERSION)
    template_id: str
    name: str = Field(default="")
    description: str = Field(default="")
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    # Entity bindings — substituted into stage templates
    target_host: str = Field(..., description="e.g. 'workstation-01'")
    attacker_user: str = Field(..., description="e.g. 'alice'")
    target_user: str = Field(default="", description="Victim user if different from attacker")
    source_ip: str = Field(default="10.0.0.100")
    target_ip: str = Field(default="")
    domain: str = Field(default="CORP")
    # Timing
    start_time: datetime = Field(default_factory=lambda: datetime.now(UTC))
    compress_time: bool = Field(
        default=False,
        description="If True, collapse all stage delays to zero for fast testing"
    )
    # Stage-level overrides (stage_id → field overrides)
    stage_overrides: dict[str, dict[str, Any]] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)

    @property
    def entity_map(self) -> dict[str, str]:
        return {
            "target_host": self.target_host,
            "attacker_user": self.attacker_user,
            "target_user": self.target_user or self.attacker_user,
            "source_ip": self.source_ip,
            "target_ip": self.target_ip or self.target_host,
            "domain": self.domain,
        }


# ---------------------------------------------------------------------------
# AttackExecution — the result of generating events from a scenario
# ---------------------------------------------------------------------------

class AttackExecution(CyberShieldBaseModel):
    """
    Records the outcome of generating a scenario's events.
    Contains generated CanonicalEvents as serialised dicts (to avoid circular deps).
    """

    model_config = ConfigDict(protected_namespaces=())

    execution_id: str = Field(default_factory=lambda: f"exec-{generate_id()}")
    schema_version: str = Field(default=SYNTHETIC_SCHEMA_VERSION)
    scenario_id: str
    template_id: str
    executed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    # Event count per stage
    stage_event_counts: dict[str, int] = Field(default_factory=dict)
    total_events: int = Field(default=0, ge=0)
    # Time range of generated events
    first_event_time: datetime | None = Field(default=None)
    last_event_time: datetime | None = Field(default=None)
    # Serialised CanonicalEvents (list of dicts — avoids import cycle in models)
    event_payloads: list[dict[str, Any]] = Field(default_factory=list)
    success: bool = Field(default=True)
    error_message: str = Field(default="")
    tags: list[str] = Field(default_factory=list)

    def to_summary(self) -> dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "scenario_id": self.scenario_id,
            "template_id": self.template_id,
            "total_events": self.total_events,
            "success": self.success,
            "executed_at": self.executed_at.isoformat(),
        }


# ---------------------------------------------------------------------------
# GenerationReport — batch result across multiple executions
# ---------------------------------------------------------------------------

class GenerationReport(CyberShieldBaseModel):
    """Full report for a batch generation run."""

    model_config = ConfigDict(protected_namespaces=())

    report_id: str = Field(default_factory=lambda: f"synrpt-{generate_id()}")
    schema_version: str = Field(default=SYNTHETIC_SCHEMA_VERSION)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    executions: list[AttackExecution] = Field(default_factory=list)
    total_events: int = Field(default=0)
    total_scenarios: int = Field(default=0)
    successful: int = Field(default=0)
    failed: int = Field(default=0)
    domains_covered: list[str] = Field(default_factory=list)

    def model_post_init(self, __context: Any) -> None:
        if self.executions:
            self.total_events = sum(e.total_events for e in self.executions)
            self.total_scenarios = len(self.executions)
            self.successful = sum(1 for e in self.executions if e.success)
            self.failed = self.total_scenarios - self.successful

    def to_summary(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "total_scenarios": self.total_scenarios,
            "total_events": self.total_events,
            "successful": self.successful,
            "failed": self.failed,
        }
