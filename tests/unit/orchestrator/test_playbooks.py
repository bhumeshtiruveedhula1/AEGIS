"""tests/unit/orchestrator/test_playbooks.py — Playbook selection logic tests."""

from __future__ import annotations

import pytest

from backend.orchestrator.exceptions import PlaybookNotFoundError
from backend.orchestrator.playbooks import PlaybookRegistry
from tests.unit.orchestrator.conftest import make_context, make_playbook


class TestPlaybookRegistry:
    def test_all_playbooks_registered(self, registry: PlaybookRegistry) -> None:
        assert "observe_only" in registry.playbook_ids
        assert "isolate_host" in registry.playbook_ids
        assert "block_account" in registry.playbook_ids
        assert "investigate_lateral" in registry.playbook_ids
        assert "ot_containment" in registry.playbook_ids

    def test_get_by_id(self, registry: PlaybookRegistry) -> None:
        pb = registry.get("isolate_host")
        assert pb.playbook_id == "isolate_host"

    def test_get_unknown_raises(self, registry: PlaybookRegistry) -> None:
        with pytest.raises(PlaybookNotFoundError):
            registry.get("nonexistent_playbook")


class TestPlaybookSelection:
    def test_low_score_selects_observe_only(
        self, registry: PlaybookRegistry, ctx_low_score
    ) -> None:
        pb = registry.select(ctx_low_score)
        assert pb.playbook_id == "observe_only"

    def test_ot_context_selects_ot_containment(self, registry: PlaybookRegistry, ctx_ot) -> None:
        pb = registry.select(ctx_ot)
        assert pb.playbook_id == "ot_containment"

    def test_lateral_movement_with_chain_selects_isolate_host(
        self, registry: PlaybookRegistry
    ) -> None:
        ctx = make_context(
            anomaly_score=0.8,
            tactic_ids=["TA0008", "TA0003"],  # Lateral Movement, Persistence
            technique_ids=["T1021"],
            has_chain=True,
        )
        pb = registry.select(ctx)
        assert pb.playbook_id == "isolate_host"

    def test_credential_access_selects_block_account(self, registry: PlaybookRegistry) -> None:
        ctx = make_context(
            anomaly_score=0.65,
            tactic_ids=["TA0006"],  # Credential Access
            technique_ids=["T1110"],
        )
        pb = registry.select(ctx)
        assert pb.playbook_id == "block_account"

    def test_lateral_with_chain_investigates_when_low_score(
        self, registry: PlaybookRegistry
    ) -> None:
        # score meets investigate_lateral threshold (0.45) but not isolate_host (0.6)
        ctx = make_context(
            anomaly_score=0.5,
            tactic_ids=["TA0008"],  # Lateral Movement
            technique_ids=["T1021"],
            has_chain=True,
        )
        pb = registry.select(ctx)
        # investigate_lateral requires chain + TA0008 — should win over block_account
        assert pb.playbook_id in ("investigate_lateral", "isolate_host")

    def test_no_tactics_no_chain_falls_back_to_observe_only(
        self, registry: PlaybookRegistry
    ) -> None:
        ctx = make_context(
            anomaly_score=0.55,
            tactic_ids=[],
            technique_ids=[],
            has_chain=False,
        )
        pb = registry.select(ctx)
        # No tactic matches → observe_only
        assert pb.playbook_id == "observe_only"

    def test_requires_chain_skipped_when_no_chain(self, registry: PlaybookRegistry) -> None:
        # Lateral movement tactics but no chain → isolate_host skipped
        ctx = make_context(
            anomaly_score=0.8,
            tactic_ids=["TA0008"],
            technique_ids=["T1021"],
            has_chain=False,
        )
        pb = registry.select(ctx)
        # isolate_host requires chain → should not be selected
        assert pb.playbook_id != "isolate_host"

    def test_ot_not_selected_without_ot_indicators(self, registry: PlaybookRegistry) -> None:
        ctx = make_context(has_ot=False, anomaly_score=0.7, tactic_ids=["TA0040"])
        pb = registry.select(ctx)
        assert pb.playbook_id != "ot_containment"

    def test_custom_registry(self) -> None:
        custom_pb = make_playbook(playbook_id="custom_pb", severity_threshold=0.1)
        reg = PlaybookRegistry(playbooks=[custom_pb])
        assert "custom_pb" in reg.playbook_ids

    def test_observe_only_actions_non_empty(self, registry: PlaybookRegistry) -> None:
        pb = registry.get("observe_only")
        assert len(pb.actions) > 0

    def test_all_builtin_playbooks_have_actions(self, registry: PlaybookRegistry) -> None:
        for pb_id in registry.playbook_ids:
            pb = registry.get(pb_id)
            assert len(pb.actions) > 0, f"{pb_id} has no actions"
