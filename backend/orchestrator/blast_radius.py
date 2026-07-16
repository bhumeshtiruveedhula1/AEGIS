"""
backend.orchestrator.blast_radius — Blast Radius Analysis
==========================================================
Module 6.1 — Response Orchestrator

Determines affected assets from AttackContext. Read-only.
No graph construction. No inference. No modification of AttackContext.

All data sourced from:
  - context.evidence      (hosts, users, IPs, processes)
  - context.graph         (entity_count, node_count for scope estimate)
  - context.chain         (matched_alert_ids for breadth)
  - context.identity      (primary entity)
  - context.behavioral    (baseline_available)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from backend.context.models import AttackContext

from backend.orchestrator.models import BlastRadiusReport

logger = structlog.get_logger(__name__)

# Thresholds for scope classification
_LATERAL_NODE_THRESHOLD = 3  # ≥3 graph nodes → LATERAL
_MULTI_ENTITY_THRESHOLD = 5  # ≥5 graph nodes → MULTI_ENTITY


def compute_blast_radius(context: AttackContext) -> BlastRadiusReport:
    """
    Extract blast radius from AttackContext without any graph construction.

    Parameters
    ----------
    context : AttackContext — the complete intelligence package.

    Returns
    -------
    BlastRadiusReport — affected assets and estimated scope.
    """
    ev = context.evidence

    # Affected hosts — from evidence + identity
    hosts: list[str] = list(ev.affected_hosts)
    if context.identity.host and context.identity.host not in hosts:
        hosts.append(context.identity.host)

    # Affected users — from evidence + identity
    users: list[str] = list(ev.affected_users)
    if context.identity.user and context.identity.user not in users:
        users.append(context.identity.user)

    # Affected entity IDs — primary entity always included
    entity_ids: list[str] = [context.identity.entity_id]

    # Alert IDs in scope — from chain if present
    alert_ids: list[str] = []
    if context.chain is not None:
        alert_ids = list(context.chain.matched_alert_ids)
    if context.identity.alert_id not in alert_ids:
        alert_ids.append(context.identity.alert_id)

    # Node count from graph (for scope estimate)
    node_count = 0
    if context.graph is not None:
        node_count = context.graph.node_count
        # Entity IDs from graph entity count — we don't have the list, just count
        # so we use the chain for actual IDs; node_count is scope only.

    # Evidence sources used
    evidence_sources: list[str] = ["context.evidence", "context.identity"]
    if context.graph is not None:
        evidence_sources.append("context.graph")
    if context.chain is not None:
        evidence_sources.append("context.chain")

    # OT indicators
    is_ot = ev.has_ot_indicators

    # Scope classification (deterministic rules)
    scope: str
    if is_ot:
        scope = "OT"
    elif node_count >= _MULTI_ENTITY_THRESHOLD or len(alert_ids) > 3:
        scope = "MULTI_ENTITY"
    elif node_count >= _LATERAL_NODE_THRESHOLD or len(hosts) > 1:
        scope = "LATERAL"
    elif node_count > 0 or len(hosts) == 1:
        scope = "SINGLE_HOST"
    else:
        scope = "UNKNOWN"

    # baseline_available from behavioral if present
    baseline_available = True
    if context.behavioral is not None:
        baseline_available = context.behavioral.baseline_available

    report = BlastRadiusReport(
        affected_hosts=hosts,
        affected_users=users,
        affected_entity_ids=entity_ids,
        alert_ids_in_scope=alert_ids,
        estimated_node_count=node_count,
        estimated_scope=scope,  # type: ignore[arg-type]
        evidence_sources=evidence_sources,
        baseline_available=baseline_available,
    )

    logger.info(
        "blast_radius_computed",
        context_id=context.context_id,
        alert_id=context.identity.alert_id,
        scope=scope,
        host_count=len(hosts),
        user_count=len(users),
        alert_count=len(alert_ids),
        node_count=node_count,
        is_ot=is_ot,
    )

    return report
