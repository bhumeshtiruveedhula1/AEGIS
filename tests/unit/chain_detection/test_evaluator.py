"""tests/unit/chain_detection/test_evaluator.py — ChainEvaluator Tests."""

from __future__ import annotations

from datetime import timedelta

import pytest

from backend.chain_detection.evaluator import (
    ChainEvaluator,
    _W_OBS,
    _W_STEP,
    _W_TACTIC,
    _W_TIME,
    _FULL_KILL_CHAIN_SIZE,
    _MAX_OBSERVATIONS,
)
from backend.chain_detection.exceptions import EvaluationError
from backend.chain_detection.models import ChainEvaluation

from tests.unit.chain_detection.conftest import (
    BASE_TS,
    _make_chain_node,
    make_chain,
)


class TestEvaluatorInit:
    def test_weights_sum_to_one(self) -> None:
        assert abs(_W_STEP + _W_TACTIC + _W_TIME + _W_OBS - 1.0) < 1e-9


class TestEvaluatorEvaluate:
    def test_returns_chain_evaluation(self) -> None:
        ev = ChainEvaluator()
        chain = make_chain()
        result = ev.evaluate(chain)
        assert isinstance(result, ChainEvaluation)

    def test_confidence_in_unit_interval(self) -> None:
        ev = ChainEvaluator()
        result = ev.evaluate(make_chain())
        assert 0.0 <= result.confidence <= 1.0

    def test_empty_chain_raises(self) -> None:
        ev = ChainEvaluator()
        chain = make_chain()
        chain2 = chain.model_copy(update={"nodes": []})
        with pytest.raises(EvaluationError):
            ev.evaluate(chain2)

    def test_single_node_chain_evaluated(self) -> None:
        ev = ChainEvaluator()
        nodes = [_make_chain_node(step=0)]
        chain = make_chain(nodes=nodes)
        # single node = no links, but evaluator should still work
        result = ev.evaluate(chain)
        assert result.chain_length == 1
        # temporal score = 1.0 (< 2 nodes)
        assert result.temporal_consistency_score == pytest.approx(1.0)

    def test_multi_tactic_detected(self) -> None:
        ev = ChainEvaluator()
        nodes = [
            _make_chain_node("T1110", "TA0006", "Credential Access", step=0),
            _make_chain_node("T1059", "TA0002", "Execution", step=1),
        ]
        chain = make_chain(nodes=nodes)
        result = ev.evaluate(chain)
        assert result.is_multi_tactic is True
        assert result.tactic_count == 2

    def test_single_tactic_not_multi(self) -> None:
        ev = ChainEvaluator()
        nodes = [
            _make_chain_node("T1110", "TA0006", "Credential Access", step=0),
            _make_chain_node("T1078", "TA0006", "Credential Access", step=1),
        ]
        chain = make_chain(nodes=nodes)
        result = ev.evaluate(chain)
        assert result.is_multi_tactic is False
        assert result.tactic_count == 1

    def test_temporally_ordered_score_one(self) -> None:
        ev = ChainEvaluator()
        nodes = [
            _make_chain_node(step=0, ts=BASE_TS),
            _make_chain_node("T1059", "TA0002", "Execution", step=1, ts=BASE_TS + timedelta(hours=1)),
        ]
        chain = make_chain(nodes=nodes)
        result = ev.evaluate(chain)
        assert result.temporal_consistency_score == pytest.approx(1.0)
        assert result.is_temporally_ordered is True

    def test_disordered_temporal_score_less_than_one(self) -> None:
        ev = ChainEvaluator()
        nodes = [
            _make_chain_node(step=0, ts=BASE_TS + timedelta(hours=2)),  # later
            _make_chain_node("T1059", "TA0002", "Execution", step=1, ts=BASE_TS),  # earlier
        ]
        chain = make_chain(nodes=nodes)
        result = ev.evaluate(chain)
        assert result.temporal_consistency_score < 1.0

    def test_deterministic(self) -> None:
        ev = ChainEvaluator()
        chain = make_chain()
        r1 = ev.evaluate(chain)
        r2 = ev.evaluate(chain)
        assert r1.confidence == r2.confidence

    def test_rounded_to_4dp(self) -> None:
        ev = ChainEvaluator()
        result = ev.evaluate(make_chain())
        assert result.confidence == round(result.confidence, 4)

    def test_chain_length_correct(self) -> None:
        ev = ChainEvaluator()
        nodes = [_make_chain_node(step=i) for i in range(4)]
        chain = make_chain(nodes=nodes)
        result = ev.evaluate(chain)
        assert result.chain_length == 4

    def test_higher_confidence_nodes_boost_score(self) -> None:
        ev = ChainEvaluator()
        low_nodes = [
            _make_chain_node(conf=0.2, step=0),
            _make_chain_node("T1059", "TA0002", "Execution", conf=0.2, step=1),
        ]
        high_nodes = [
            _make_chain_node(conf=0.9, step=0),
            _make_chain_node("T1059", "TA0002", "Execution", conf=0.9, step=1),
        ]
        r_low = ev.evaluate(make_chain(nodes=low_nodes))
        r_high = ev.evaluate(make_chain(nodes=high_nodes))
        assert r_high.confidence > r_low.confidence


class TestEvaluatorComponents:
    def test_avg_step_confidence(self) -> None:
        nodes = [
            _make_chain_node(conf=0.8, step=0),
            _make_chain_node("T1059", "TA0002", "Execution", conf=0.6, step=1),
        ]
        avg = ChainEvaluator._avg_step_confidence(nodes)
        assert avg == pytest.approx(0.7)

    def test_tactic_coverage_ratio_capped(self) -> None:
        # 14 distinct tactics → ratio = 1.0
        nodes = []
        for i in range(14):
            n = _make_chain_node(f"T11{i:02d}", f"TA{i:04d}", f"Tactic{i}", step=i)
            nodes.append(n)
        ratio = ChainEvaluator._tactic_coverage_ratio(nodes)
        assert ratio == pytest.approx(1.0)

    def test_tactic_coverage_single_tactic(self) -> None:
        nodes = [_make_chain_node(step=0), _make_chain_node(step=1)]
        ratio = ChainEvaluator._tactic_coverage_ratio(nodes)
        assert ratio == pytest.approx(1 / _FULL_KILL_CHAIN_SIZE)

    def test_temporal_consistency_all_ordered(self) -> None:
        nodes = [
            _make_chain_node(step=0, ts=BASE_TS),
            _make_chain_node("T1059", "TA0002", "Execution", step=1, ts=BASE_TS + timedelta(hours=1)),
            _make_chain_node("T1041", "TA0010", "Exfiltration", step=2, ts=BASE_TS + timedelta(hours=2)),
        ]
        score = ChainEvaluator._temporal_consistency_score(nodes)
        assert score == pytest.approx(1.0)

    def test_temporal_consistency_none_ordered(self) -> None:
        nodes = [
            _make_chain_node(step=0, ts=BASE_TS + timedelta(hours=3)),
            _make_chain_node("T1059", "TA0002", "Execution", step=1, ts=BASE_TS + timedelta(hours=2)),
            _make_chain_node("T1041", "TA0010", "Exfiltration", step=2, ts=BASE_TS + timedelta(hours=1)),
        ]
        score = ChainEvaluator._temporal_consistency_score(nodes)
        assert score == pytest.approx(0.0)

    def test_temporal_consistency_single_node(self) -> None:
        nodes = [_make_chain_node(step=0)]
        score = ChainEvaluator._temporal_consistency_score(nodes)
        assert score == pytest.approx(1.0)

    def test_observation_strength_capped(self) -> None:
        nodes = [_make_chain_node(obs=_MAX_OBSERVATIONS + 100, step=0)]
        strength = ChainEvaluator._observation_strength(nodes)
        assert strength == pytest.approx(1.0)

    def test_observation_strength_normalised(self) -> None:
        nodes = [_make_chain_node(obs=1, step=0), _make_chain_node(obs=1, step=1)]
        strength = ChainEvaluator._observation_strength(nodes)
        assert strength == pytest.approx(2 / _MAX_OBSERVATIONS)


class TestEvaluatorBatch:
    def test_batch_returns_list(self) -> None:
        ev = ChainEvaluator()
        chains = [make_chain(f"c{i}") for i in range(3)]
        results = ev.evaluate_batch(chains)
        assert len(results) == 3

    def test_batch_empty(self) -> None:
        ev = ChainEvaluator()
        assert ev.evaluate_batch([]) == []
