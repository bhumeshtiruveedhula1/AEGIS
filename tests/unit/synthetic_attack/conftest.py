"""tests/unit/synthetic_attack/conftest.py — Shared Fixtures."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from backend.synthetic_attack.models import AttackScenario
from backend.synthetic_attack.service import SyntheticAttackService
from backend.synthetic_attack.storage import SyntheticAttackStore
from backend.synthetic_attack.templates import get_template

BASE_TS = datetime(2024, 6, 10, 10, 0, tzinfo=UTC)


def make_scenario(
    template_id: str = "brute_force_auth",
    target_host: str = "ws01",
    attacker_user: str = "alice",
    compress: bool = True,
) -> AttackScenario:
    return AttackScenario(
        template_id=template_id,
        target_host=target_host,
        attacker_user=attacker_user,
        start_time=BASE_TS,
        compress_time=compress,
    )


@pytest.fixture()
def brute_force_scenario() -> AttackScenario:
    return make_scenario("brute_force_auth")


@pytest.fixture()
def ot_scenario() -> AttackScenario:
    return make_scenario("ot_register_manipulation")


@pytest.fixture()
def kill_chain_scenario() -> AttackScenario:
    return make_scenario("full_kill_chain_it")


@pytest.fixture()
def store(tmp_path: Path) -> SyntheticAttackStore:
    return SyntheticAttackStore(store_dir=tmp_path / "synthetic")


@pytest.fixture()
def svc(tmp_path: Path) -> SyntheticAttackService:
    return SyntheticAttackService(
        store_dir=tmp_path / "synthetic_svc",
        persist=False,
        seed=42,
    )


@pytest.fixture()
def svc_persist(tmp_path: Path) -> SyntheticAttackService:
    return SyntheticAttackService(
        store_dir=tmp_path / "synthetic_persist",
        persist=True,
        seed=42,
    )
