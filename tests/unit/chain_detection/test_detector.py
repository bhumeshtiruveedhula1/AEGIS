"""tests/unit/chain_detection/test_detector.py — AttackChainDetector Tests."""

from __future__ import annotations

import pytest

from backend.chain_detection.detector import (
    MAX_CHAIN_LENGTH,
    MIN_CHAIN_LENGTH,
    MIN_STEP_CONFIDENCE,
    AttackChainDetector,
)
from backend.chain_detection.models import AttackChain

from tests.unit.chain_detection.conftest import (
    make_empty_snapshot,
    make_linear_snapshot,
    make_multi_entity_snapshot,
    make_single_step_snapshot,
)


class TestDetectorInit:
    def test_defaults(self) -> None:
        d = AttackChainDetector()
        assert d._min_length == MIN_CHAIN_LENGTH
        assert d._max_length == MAX_CHAIN_LENGTH
        assert d._min_confidence == MIN_STEP_CONFIDENCE

    def test_custom_params(self) -> None:
        d = AttackChainDetector(min_chain_length=3, max_chain_length=10)
        assert d._min_length == 3
        assert d._max_length == 10


class TestDetectFromSnapshot:
    def test_empty_snapshot_returns_empty(self, empty_snapshot) -> None:
        chains = AttackChainDetector().detect(empty_snapshot)
        assert chains == []

    def test_single_technique_no_chain(self, single_step_snapshot) -> None:
        chains = AttackChainDetector().detect(single_step_snapshot)
        # Single step < MIN_CHAIN_LENGTH — no chains
        assert len(chains) == 0

    def test_linear_chain_detected(self, linear_snapshot) -> None:
        chains = AttackChainDetector().detect(linear_snapshot)
        assert len(chains) >= 1

    def test_chains_are_attack_chains(self, linear_snapshot) -> None:
        chains = AttackChainDetector().detect(linear_snapshot)
        for c in chains:
            assert isinstance(c, AttackChain)

    def test_chains_have_min_length(self, linear_snapshot) -> None:
        d = AttackChainDetector(min_chain_length=2)
        chains = d.detect(linear_snapshot)
        for c in chains:
            assert c.length >= 2

    def test_chains_have_evaluation(self, linear_snapshot) -> None:
        chains = AttackChainDetector().detect(linear_snapshot)
        for c in chains:
            assert c.evaluation is not None
            assert 0.0 <= c.evaluation.confidence <= 1.0

    def test_chain_entity_id_set(self, linear_snapshot) -> None:
        chains = AttackChainDetector().detect(linear_snapshot)
        for c in chains:
            assert c.entity_id != ""

    def test_chain_graph_id_matches_snapshot(self, linear_snapshot) -> None:
        chains = AttackChainDetector().detect(linear_snapshot)
        for c in chains:
            assert c.graph_id == linear_snapshot.graph_id

    def test_nodes_have_technique_ids(self, linear_snapshot) -> None:
        chains = AttackChainDetector().detect(linear_snapshot)
        for c in chains:
            for n in c.nodes:
                assert n.technique_id != ""
                assert n.technique_id != "unknown"

    def test_nodes_step_index_sequential(self, linear_snapshot) -> None:
        chains = AttackChainDetector().detect(linear_snapshot)
        for c in chains:
            for idx, n in enumerate(c.nodes):
                assert n.step_index == idx

    def test_links_connect_consecutive_nodes(self, linear_snapshot) -> None:
        chains = AttackChainDetector().detect(linear_snapshot)
        for c in chains:
            if len(c.nodes) >= 2:
                assert len(c.links) == len(c.nodes) - 1


class TestMultiEntityDetection:
    def test_multi_entity_produces_chains_per_entity(
        self, multi_entity_snapshot
    ) -> None:
        chains = AttackChainDetector().detect(multi_entity_snapshot)
        assert len(chains) >= 2
        entity_ids = {c.entity_id for c in chains}
        assert len(entity_ids) >= 2

    def test_chains_isolated_by_entity(self, multi_entity_snapshot) -> None:
        chains = AttackChainDetector().detect(multi_entity_snapshot)
        for c in chains:
            # All chain nodes must have the same entity_id as the chain
            for n in c.nodes:
                assert n.entity_id == c.entity_id


class TestDeduplication:
    def test_no_duplicate_technique_sequences(self, linear_snapshot) -> None:
        chains = AttackChainDetector().detect(linear_snapshot)
        sigs: set[tuple] = set()
        for c in chains:
            sig = (c.entity_id, tuple(c.technique_ids))
            assert sig not in sigs, f"Duplicate chain detected: {sig}"
            sigs.add(sig)

    def test_repeated_detection_same_result(self, linear_snapshot) -> None:
        d = AttackChainDetector()
        c1 = d.detect(linear_snapshot)
        c2 = d.detect(linear_snapshot)
        assert len(c1) == len(c2)
        for a, b in zip(c1, c2):
            assert a.technique_ids == b.technique_ids
            assert a.entity_id == b.entity_id


class TestChainOrdering:
    def test_chains_sorted_by_entity_then_confidence(
        self, multi_entity_snapshot
    ) -> None:
        chains = AttackChainDetector().detect(multi_entity_snapshot)
        if len(chains) > 1:
            prev_entity = chains[0].entity_id
            prev_conf = chains[0].evaluation.confidence
            for c in chains[1:]:
                if c.entity_id == prev_entity:
                    assert c.evaluation.confidence <= prev_conf
                prev_entity = c.entity_id
                prev_conf = c.evaluation.confidence


class TestMinLengthGate:
    def test_min_length_3_filters_2_step_chains(
        self, linear_snapshot
    ) -> None:
        d = AttackChainDetector(min_chain_length=3)
        chains = d.detect(linear_snapshot)
        for c in chains:
            assert c.length >= 3

    def test_very_high_min_length_yields_empty(
        self, linear_snapshot
    ) -> None:
        d = AttackChainDetector(min_chain_length=100)
        chains = d.detect(linear_snapshot)
        assert chains == []


class TestEvidencePopulated:
    def test_evidence_has_tactic_sequence(self, linear_snapshot) -> None:
        chains = AttackChainDetector().detect(linear_snapshot)
        for c in chains:
            assert len(c.evidence.tactic_sequence) > 0

    def test_evidence_has_technique_ids(self, linear_snapshot) -> None:
        chains = AttackChainDetector().detect(linear_snapshot)
        for c in chains:
            assert len(c.evidence.technique_ids) > 0
