"""
backend.context.timeline — Attack Timeline Builder
===================================================
Module 4.1 — Attack Context Generation

Produces a deterministic ordered list of TimelineEvent objects
from ChainNodes. No inference. No prediction.

Single responsibility: ordering and translating ChainNode → TimelineEvent.
"""

from __future__ import annotations

from backend.chain_detection.models import AttackChain
from backend.context.models import TimelineEvent


class TimelineBuilder:
    """
    Converts an AttackChain's ordered nodes into a TimelineEvent list.

    The order is defined by ChainNode.step_index (already sorted).
    All values are read directly from the chain — nothing is inferred.
    """

    def build(self, chain: AttackChain) -> list[TimelineEvent]:
        """
        Produce an ordered timeline from an AttackChain.

        Parameters
        ----------
        chain : The attack chain from Module 3.5.

        Returns
        -------
        list[TimelineEvent] sorted by step_index (ascending).
        """
        events: list[TimelineEvent] = []
        for node in chain.nodes:  # nodes are pre-sorted by step_index in AttackChain
            events.append(TimelineEvent(
                step_index=node.step_index,
                timestamp=node.first_seen,
                technique_id=node.technique_id,
                tactic_name=node.tactic_name,
                action=node.technique_name,
                host=node.entity_id,        # entity_id encodes host context
                user=node.entity_id,
                source=node.entity_type,
                result="detected",
                confidence=node.confidence,
                observation_count=node.observation_count,
            ))
        return events

    def build_empty(self) -> list[TimelineEvent]:
        """Return an empty timeline when no chain is available."""
        return []
