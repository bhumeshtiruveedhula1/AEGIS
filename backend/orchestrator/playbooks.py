"""
backend.orchestrator.playbooks — Response Playbook Registry
============================================================
Module 6.1 — Response Orchestrator

Provides deterministic playbook definitions and selection logic.

Selection algorithm
-------------------
1. Filter candidates by severity_threshold ≤ context.detection.anomaly_score.
2. If context has a chain, prefer playbooks with requires_chain=True.
3. Match trigger_tactics against context.mitre.all_tactic_ids.
4. Match trigger_techniques against context.mitre.all_technique_ids.
5. Score by (tactic_matches + technique_matches) — pick highest.
6. Tie-break: prefer higher severity_threshold (more specific).
7. If no match: return the `observe_only` fallback.

No randomness. No external calls. Pure function.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from backend.context.models import AttackContext

from backend.orchestrator.exceptions import PlaybookNotFoundError
from backend.orchestrator.models import PlaybookAction, ResponsePlaybook

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Built-in playbook definitions
# ---------------------------------------------------------------------------

_OBSERVE_ONLY = ResponsePlaybook(
    playbook_id="observe_only",
    name="Observe Only",
    description=(
        "No active response. Document the alert, notify SOC, and continue monitoring. "
        "Used for low-confidence detections or when no specific playbook matches."
    ),
    severity_threshold=0.0,
    requires_chain=False,
    requires_mitre=False,
    trigger_tactics=[],
    trigger_techniques=[],
    tags=["fallback", "low-severity"],
    actions=[
        PlaybookAction(
            action_type="observe_only",
            description="Record alert in SOC queue for manual review.",
            rollback_description="N/A — no action taken.",
        ),
        PlaybookAction(
            action_type="notify_soc",
            description="Send structured alert summary to SOC analyst queue.",
            rollback_description="N/A — notification only.",
        ),
    ],
)

_ISOLATE_HOST = ResponsePlaybook(
    playbook_id="isolate_host",
    name="Host Isolation",
    description=(
        "Isolate the compromised host from the network to contain lateral movement. "
        "Triggered by confirmed lateral movement or high-confidence execution techniques."
    ),
    severity_threshold=0.6,
    requires_chain=True,
    requires_mitre=True,
    trigger_tactics=["TA0008", "TA0003"],  # Lateral Movement, Persistence
    trigger_techniques=["T1021", "T1059", "T1078"],
    tags=["containment", "lateral-movement"],
    actions=[
        PlaybookAction(
            action_type="collect_forensics",
            description="Capture process list, active connections, and running services on target host.",
            rollback_description="Delete local forensic artefacts after 30 days.",
            estimated_duration_s=30,
        ),
        PlaybookAction(
            action_type="isolate_host",
            description="Block all egress/ingress for host (simulated — no real network change).",
            parameters={"scope": "full_isolation", "direction": "bidirectional"},
            rollback_description="Remove isolation rule after investigation completes.",
            estimated_duration_s=5,
        ),
        PlaybookAction(
            action_type="notify_soc",
            description="Alert SOC with isolation details and forensic artefact location.",
            rollback_description="N/A — notification only.",
        ),
    ],
)

_BLOCK_ACCOUNT = ResponsePlaybook(
    playbook_id="block_account",
    name="Account Disable",
    description=(
        "Disable the compromised user account to prevent credential abuse. "
        "Triggered by brute force, credential dumping, or account manipulation techniques."
    ),
    severity_threshold=0.55,
    requires_chain=False,
    requires_mitre=True,
    trigger_tactics=["TA0006", "TA0001"],  # Credential Access, Initial Access
    trigger_techniques=["T1110", "T1003", "T1078", "T1098"],
    tags=["credential", "account"],
    actions=[
        PlaybookAction(
            action_type="investigate",
            description="Review authentication logs for account in last 24h.",
            rollback_description="N/A — read-only investigation.",
            estimated_duration_s=10,
        ),
        PlaybookAction(
            action_type="block_account",
            description="Disable account in directory service (simulated — no real AD change).",
            parameters={"duration_h": 24, "notify_user": False},
            rollback_description="Re-enable account after investigation clears the entity.",
            estimated_duration_s=5,
        ),
        PlaybookAction(
            action_type="notify_soc",
            description="Notify SOC with account details and triggering alert.",
            rollback_description="N/A — notification only.",
        ),
    ],
)

_INVESTIGATE_LATERAL = ResponsePlaybook(
    playbook_id="investigate_lateral",
    name="Lateral Movement Investigation",
    description=(
        "Collect forensic evidence and investigate potential lateral movement "
        "without active containment. Used when chain is present but confidence "
        "is insufficient for isolation."
    ),
    severity_threshold=0.45,
    requires_chain=True,
    requires_mitre=True,
    trigger_tactics=["TA0008", "TA0007"],  # Lateral Movement, Discovery
    trigger_techniques=["T1021", "T1018", "T1049", "T1135"],
    tags=["investigation", "lateral-movement"],
    actions=[
        PlaybookAction(
            action_type="collect_forensics",
            description="Capture network connections and SMB/RDP session logs.",
            rollback_description="Delete local artefacts after 30 days.",
            estimated_duration_s=60,
        ),
        PlaybookAction(
            action_type="investigate",
            description="Enumerate peer hosts accessed from the flagged entity in the attack window.",
            rollback_description="N/A — read-only.",
            estimated_duration_s=15,
        ),
        PlaybookAction(
            action_type="notify_soc",
            description="Present investigation summary to SOC for containment decision.",
            rollback_description="N/A.",
        ),
    ],
)

_OT_CONTAINMENT = ResponsePlaybook(
    playbook_id="ot_containment",
    name="OT/ICS Containment",
    description=(
        "Isolate OT/ICS asset and alert operational engineering team. "
        "Triggered when OT indicators (Modbus, SCADA) are present in the attack context."
    ),
    severity_threshold=0.50,
    requires_chain=False,
    requires_mitre=False,
    trigger_tactics=["TA0040", "TA0105"],  # Impact, Inhibit Response Function
    trigger_techniques=["T0800", "T0814", "T0816", "T0836"],
    tags=["ot", "ics", "containment"],
    actions=[
        PlaybookAction(
            action_type="ot_containment",
            description=(
                "Simulated OT containment: isolate network segment, preserve register state, "
                "halt non-critical polling cycles."
            ),
            parameters={"preserve_state": True, "halt_polling": True},
            rollback_description="Restore polling and network segment after engineering review.",
            estimated_duration_s=10,
        ),
        PlaybookAction(
            action_type="collect_forensics",
            description="Capture OT device register snapshots and event logs.",
            rollback_description="N/A — read-only snapshot.",
            estimated_duration_s=20,
        ),
        PlaybookAction(
            action_type="notify_soc",
            description="Alert SOC and OT engineering team with containment status.",
            rollback_description="N/A.",
        ),
    ],
)

# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

# Ordered: most-specific first, fallback last
_ALL_PLAYBOOKS: list[ResponsePlaybook] = [
    _OT_CONTAINMENT,
    _ISOLATE_HOST,
    _BLOCK_ACCOUNT,
    _INVESTIGATE_LATERAL,
    _OBSERVE_ONLY,
]

_PLAYBOOK_BY_ID: dict[str, ResponsePlaybook] = {p.playbook_id: p for p in _ALL_PLAYBOOKS}


class PlaybookRegistry:
    """
    Deterministic playbook registry and selector.

    Stateless — holds only read-only playbook definitions.
    Safe for concurrent use.
    """

    def __init__(self, playbooks: list[ResponsePlaybook] | None = None) -> None:
        self._playbooks = playbooks or list(_ALL_PLAYBOOKS)

    @property
    def playbook_ids(self) -> list[str]:
        return [p.playbook_id for p in self._playbooks]

    def get(self, playbook_id: str) -> ResponsePlaybook:
        """Return playbook by ID. Raises PlaybookNotFoundError if absent."""
        pb = _PLAYBOOK_BY_ID.get(playbook_id)
        if pb is None:
            # Try instance list (custom registry)
            for p in self._playbooks:
                if p.playbook_id == playbook_id:
                    return p
            raise PlaybookNotFoundError(
                f"Playbook {playbook_id!r} not found in registry.",
                context={"playbook_id": playbook_id},
            )
        return pb

    def select(self, context: AttackContext) -> ResponsePlaybook:
        """
        Deterministically select the best playbook for the given AttackContext.

        Returns the `observe_only` fallback if no playbook matches.
        """
        score = context.detection.anomaly_score
        has_chain = context.chain is not None
        has_ot = bool(context.evidence.has_ot_indicators)
        context_tactics: set[str] = set(context.mitre.all_tactic_ids)
        context_techniques: set[str] = set(context.mitre.all_technique_ids)

        best: ResponsePlaybook | None = None
        best_match = -1

        # OT fast-path: if OT indicators present and threshold met, always select ot_containment
        if has_ot:
            ot_pb = next((p for p in self._playbooks if p.playbook_id == "ot_containment"), None)
            if ot_pb is not None and score >= ot_pb.severity_threshold:
                logger.info(
                    "playbook_selected",
                    playbook_id=ot_pb.playbook_id,
                    anomaly_score=round(score, 4),
                    has_chain=has_chain,
                    has_ot=has_ot,
                    tactic_count=len(context_tactics),
                    technique_count=len(context_techniques),
                    match_score=-1,
                )
                return ot_pb

        for pb in self._playbooks:
            # Skip fallback and OT (handled above) in scoring loop
            if pb.playbook_id in ("observe_only", "ot_containment"):
                continue

            # Severity gate
            if score < pb.severity_threshold:
                continue

            # Chain requirement
            if pb.requires_chain and not has_chain:
                continue

            # Compute match score — must have at least one matching tactic or technique
            tactic_hits = len(context_tactics & set(pb.trigger_tactics))
            technique_hits = len(context_techniques & set(pb.trigger_techniques))
            match_score = tactic_hits * 2 + technique_hits  # tactics weighted higher

            # Require at least one overlap — don't select on threshold alone
            if match_score == 0:
                continue

            if match_score > best_match or (
                match_score == best_match
                and best is not None
                and pb.severity_threshold > best.severity_threshold
            ):
                best_match = match_score
                best = pb

        selected = best if best is not None else _OBSERVE_ONLY

        logger.info(
            "playbook_selected",
            playbook_id=selected.playbook_id,
            anomaly_score=round(score, 4),
            has_chain=has_chain,
            has_ot=has_ot,
            tactic_count=len(context_tactics),
            technique_count=len(context_techniques),
            match_score=best_match if best is not None else 0,
        )

        return selected


# Module-level singleton
_registry: PlaybookRegistry | None = None


def get_playbook_registry() -> PlaybookRegistry:
    """Return the module-level PlaybookRegistry singleton."""
    global _registry
    if _registry is None:
        _registry = PlaybookRegistry()
    return _registry
