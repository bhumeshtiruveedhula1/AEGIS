"""tests/unit/synthetic_attack/test_all.py — Synthetic Attack Full Test Suite."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from backend.normalization.models import CanonicalEvent
from backend.synthetic_attack.exceptions import (
    GenerationError,
    SchedulingError,
    StorageError,
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

from tests.unit.synthetic_attack.conftest import make_scenario, BASE_TS


# ─────────────────────────────────────────────────────────────────────────────
# Models
# ─────────────────────────────────────────────────────────────────────────────

class TestAttackStage:
    def test_default_id_generated(self) -> None:
        s = AttackStage(name="Test", source="windows", event_type="auth", action="logon")
        assert s.stage_id.startswith("stg-")

    def test_event_count_bounds(self) -> None:
        with pytest.raises(Exception):
            AttackStage(name="t", source="s", event_type="e", action="a", event_count=0)

    def test_default_result_success(self) -> None:
        s = AttackStage(name="t", source="windows", event_type="auth", action="logon")
        assert s.result == "success"

    def test_modbus_fields_optional(self) -> None:
        s = AttackStage(name="t", source="ot", event_type="ot_modbus", action="write")
        assert s.modbus_register is None


class TestAttackScenario:
    def test_entity_map(self) -> None:
        sc = make_scenario()
        em = sc.entity_map
        assert em["target_host"] == "ws01"
        assert em["attacker_user"] == "alice"

    def test_target_user_defaults_to_attacker(self) -> None:
        sc = make_scenario()
        assert sc.entity_map["target_user"] == "alice"

    def test_schema_version(self) -> None:
        sc = make_scenario()
        assert sc.schema_version == SYNTHETIC_SCHEMA_VERSION

    def test_json_round_trip(self) -> None:
        sc = make_scenario()
        reloaded = AttackScenario.model_validate_json(sc.model_dump_json())
        assert reloaded.scenario_id == sc.scenario_id

    def test_unique_ids(self) -> None:
        a = make_scenario()
        b = make_scenario()
        assert a.scenario_id != b.scenario_id


class TestAttackTemplate:
    def test_all_templates_valid(self) -> None:
        for tpl in get_all_templates():
            assert len(tpl.stages) >= 1
            assert tpl.template_id != ""

    def test_domain_is_string(self) -> None:
        tpl = get_template("brute_force_auth")
        assert isinstance(tpl.domain, str)

    def test_mitre_techniques_set(self) -> None:
        tpl = get_template("brute_force_auth")
        assert "T1110" in tpl.mitre_techniques


class TestGenerationReport:
    def test_report_id_prefix(self) -> None:
        r = GenerationReport()
        assert r.report_id.startswith("synrpt-")

    def test_empty_report(self) -> None:
        r = GenerationReport()
        assert r.total_events == 0
        assert r.total_scenarios == 0

    def test_populated_report(self) -> None:
        ex = AttackExecution(scenario_id="s1", template_id="t1", total_events=10)
        r = GenerationReport(executions=[ex])
        assert r.total_events == 10
        assert r.total_scenarios == 1
        assert r.successful == 1
        assert r.failed == 0

    def test_to_summary_keys(self) -> None:
        r = GenerationReport()
        s = r.to_summary()
        for k in ("report_id", "total_scenarios", "total_events", "successful", "failed"):
            assert k in s


# ─────────────────────────────────────────────────────────────────────────────
# Templates
# ─────────────────────────────────────────────────────────────────────────────

class TestTemplates:
    def test_ten_templates_registered(self) -> None:
        assert len(list_template_ids()) == 10

    def test_get_template_returns_correct(self) -> None:
        tpl = get_template("brute_force_auth")
        assert tpl is not None
        assert tpl.template_id == "brute_force_auth"

    def test_get_unknown_template_returns_none(self) -> None:
        assert get_template("does_not_exist") is None

    def test_all_templates_have_mitre_hints(self) -> None:
        for tpl in get_all_templates():
            for stage in tpl.stages:
                assert stage.mitre_technique_hint != "", f"{tpl.template_id} stage {stage.name} missing technique hint"

    def test_ot_template_has_modbus_fields(self) -> None:
        tpl = get_template("ot_register_manipulation")
        modbus_stages = [s for s in tpl.stages if s.modbus_register is not None]
        assert len(modbus_stages) >= 1

    def test_full_kill_chain_has_multiple_tactics(self) -> None:
        tpl = get_template("full_kill_chain_it")
        tactics = {s.mitre_tactic_hint for s in tpl.stages}
        assert len(tactics) >= 3

    def test_all_template_ids_unique(self) -> None:
        ids = list_template_ids()
        assert len(ids) == len(set(ids))


# ─────────────────────────────────────────────────────────────────────────────
# Scheduler
# ─────────────────────────────────────────────────────────────────────────────

class TestAttackScheduler:
    def test_schedule_returns_stage_map(self, brute_force_scenario) -> None:
        tpl = get_template("brute_force_auth")
        sched = AttackScheduler().schedule(brute_force_scenario, tpl)
        assert len(sched) == len(tpl.stages)

    def test_stage_ids_in_schedule(self, brute_force_scenario) -> None:
        tpl = get_template("brute_force_auth")
        sched = AttackScheduler().schedule(brute_force_scenario, tpl)
        for stage in tpl.stages:
            assert stage.stage_id in sched

    def test_start_time_honoured(self, brute_force_scenario) -> None:
        tpl = get_template("brute_force_auth")
        sched = AttackScheduler().schedule(brute_force_scenario, tpl)
        first_stage = tpl.stages[0]
        # First stage with delay=0 starts exactly at scenario start_time
        assert sched[first_stage.stage_id] >= brute_force_scenario.start_time

    def test_stages_are_chronological_compressed(self, brute_force_scenario) -> None:
        tpl = get_template("brute_force_auth")
        sched = AttackScheduler().schedule(brute_force_scenario, tpl)
        times = [sched[s.stage_id] for s in tpl.stages]
        for a, b in zip(times, times[1:]):
            assert b >= a

    def test_compress_collapses_delays(self) -> None:
        sc = make_scenario(compress=True)
        tpl = get_template("brute_force_auth")
        sched = AttackScheduler().schedule(sc, tpl)
        times = list(sched.values())
        # With compress, no delay added — all times should be very close
        spread = (max(times) - min(times)).total_seconds()
        assert spread < 5.0

    def test_empty_template_raises(self) -> None:
        sc = make_scenario()
        # AttackTemplate with min_length=1 will raise Pydantic ValidationError for empty stages
        with pytest.raises(Exception):  # ValidationError or SchedulingError
            tpl = AttackTemplate(
                template_id="empty", name="e", domain=AttackDomain.IT, stages=[]
            )
            AttackScheduler().schedule(sc, tpl)

    def test_total_duration(self) -> None:
        tpl = get_template("brute_force_auth")
        dur = AttackScheduler().compute_total_duration_seconds(tpl)
        assert dur >= 0.0

    def test_compressed_duration_zero(self) -> None:
        tpl = get_template("brute_force_auth")
        dur = AttackScheduler().compute_total_duration_seconds(tpl, compress=True)
        assert dur == 0.0


# ─────────────────────────────────────────────────────────────────────────────
# Generator
# ─────────────────────────────────────────────────────────────────────────────

class TestAttackGenerator:
    def test_generates_canonical_events(self, brute_force_scenario) -> None:
        tpl = get_template("brute_force_auth")
        sched = AttackScheduler().schedule(brute_force_scenario, tpl)
        gen = AttackGenerator(seed=42)
        execution = gen.generate(brute_force_scenario, tpl, sched)
        events = gen.events_from_execution(execution)
        assert all(isinstance(e, CanonicalEvent) for e in events)

    def test_event_count_matches_template(self, brute_force_scenario) -> None:
        tpl = get_template("brute_force_auth")
        sched = AttackScheduler().schedule(brute_force_scenario, tpl)
        gen = AttackGenerator(seed=42)
        execution = gen.generate(brute_force_scenario, tpl, sched)
        expected = sum(s.event_count for s in tpl.stages)
        assert execution.total_events == expected

    def test_entity_substitution(self, brute_force_scenario) -> None:
        tpl = get_template("brute_force_auth")
        sched = AttackScheduler().schedule(brute_force_scenario, tpl)
        gen = AttackGenerator(seed=42)
        execution = gen.generate(brute_force_scenario, tpl, sched)
        events = gen.events_from_execution(execution)
        assert any(e.host == "ws01" for e in events)
        assert any(e.user == "alice" for e in events)

    def test_synthetic_flag_set(self, brute_force_scenario) -> None:
        tpl = get_template("brute_force_auth")
        sched = AttackScheduler().schedule(brute_force_scenario, tpl)
        gen = AttackGenerator(seed=42)
        execution = gen.generate(brute_force_scenario, tpl, sched)
        events = gen.events_from_execution(execution)
        assert all(e.extra_fields.get("synthetic") is True for e in events)

    def test_mitre_hint_in_extra_fields(self, brute_force_scenario) -> None:
        tpl = get_template("brute_force_auth")
        sched = AttackScheduler().schedule(brute_force_scenario, tpl)
        gen = AttackGenerator(seed=42)
        execution = gen.generate(brute_force_scenario, tpl, sched)
        events = gen.events_from_execution(execution)
        assert any(e.extra_fields.get("mitre_technique_hint") == "T1110" for e in events)

    def test_ot_events_have_modbus_fields(self, ot_scenario) -> None:
        tpl = get_template("ot_register_manipulation")
        sched = AttackScheduler().schedule(ot_scenario, tpl)
        gen = AttackGenerator(seed=42)
        execution = gen.generate(ot_scenario, tpl, sched)
        events = gen.events_from_execution(execution)
        modbus_events = [e for e in events if e.modbus_register is not None]
        assert len(modbus_events) >= 1

    def test_deterministic_with_seed(self, brute_force_scenario) -> None:
        tpl = get_template("brute_force_auth")
        sched = AttackScheduler().schedule(brute_force_scenario, tpl)
        g1 = AttackGenerator(seed=99)
        g2 = AttackGenerator(seed=99)
        e1 = g1.generate(brute_force_scenario, tpl, sched)
        e2 = g2.generate(brute_force_scenario, tpl, sched)
        assert e1.total_events == e2.total_events

    def test_event_id_unique(self, brute_force_scenario) -> None:
        tpl = get_template("brute_force_auth")
        sched = AttackScheduler().schedule(brute_force_scenario, tpl)
        gen = AttackGenerator(seed=42)
        execution = gen.generate(brute_force_scenario, tpl, sched)
        events = gen.events_from_execution(execution)
        ids = [e.event_id for e in events]
        assert len(ids) == len(set(ids))

    def test_all_events_have_timestamps(self, brute_force_scenario) -> None:
        tpl = get_template("brute_force_auth")
        sched = AttackScheduler().schedule(brute_force_scenario, tpl)
        gen = AttackGenerator(seed=42)
        execution = gen.generate(brute_force_scenario, tpl, sched)
        events = gen.events_from_execution(execution)
        assert all(isinstance(e.timestamp, datetime) for e in events)

    def test_all_templates_generate_without_error(self) -> None:
        gen = AttackGenerator(seed=0)
        sched_svc = AttackScheduler()
        for tid in list_template_ids():
            sc = make_scenario(tid)
            tpl = get_template(tid)
            sched = sched_svc.schedule(sc, tpl)
            ex = gen.generate(sc, tpl, sched)
            assert ex.total_events > 0


# ─────────────────────────────────────────────────────────────────────────────
# Storage
# ─────────────────────────────────────────────────────────────────────────────

class TestSyntheticAttackStore:
    def test_dirs_created(self, tmp_path: Path) -> None:
        d = tmp_path / "syn"
        SyntheticAttackStore(store_dir=d)
        assert d.exists()
        assert (d / "reports").exists()

    def test_save_and_load_execution(self, store: SyntheticAttackStore) -> None:
        ex = AttackExecution(scenario_id="s1", template_id="t1", total_events=5)
        store.save_execution(ex)
        loaded = store.load_executions_for_date()
        assert any(e.execution_id == ex.execution_id for e in loaded)

    def test_save_batch(self, store: SyntheticAttackStore) -> None:
        execs = [AttackExecution(scenario_id=f"s{i}", template_id="t", total_events=i) for i in range(5)]
        store.save_executions_batch(execs)
        loaded = store.load_executions_for_date()
        assert len(loaded) == 5

    def test_save_report_atomic(self, store: SyntheticAttackStore) -> None:
        r = GenerationReport(executions=[AttackExecution(scenario_id="s1", template_id="t1")])
        store.save_report(r)
        tmp_files = list((store._dir / "reports").glob("*.tmp"))
        assert len(tmp_files) == 0

    def test_load_report_round_trip(self, store: SyntheticAttackStore) -> None:
        r = GenerationReport()
        store.save_report(r)
        loaded = store.load_report(r.report_id)
        assert loaded.report_id == r.report_id

    def test_load_report_not_found_raises(self, store: SyntheticAttackStore) -> None:
        with pytest.raises(StorageError):
            store.load_report("nonexistent-id")

    def test_list_reports(self, store: SyntheticAttackStore) -> None:
        store.save_report(GenerationReport())
        store.save_report(GenerationReport())
        assert len(store.list_reports()) == 2

    def test_list_dates(self, store: SyntheticAttackStore) -> None:
        store.save_execution(AttackExecution(scenario_id="s1", template_id="t1"))
        dates = store.list_execution_dates()
        assert len(dates) == 1
        assert len(dates[0]) == 10

    def test_empty_date_returns_empty(self, store: SyntheticAttackStore) -> None:
        old = datetime(2020, 1, 1, tzinfo=UTC)
        assert store.load_executions_for_date(old) == []


# ─────────────────────────────────────────────────────────────────────────────
# Service
# ─────────────────────────────────────────────────────────────────────────────

class TestSyntheticAttackService:
    def test_get_status(self, svc: SyntheticAttackService) -> None:
        s = svc.get_status()
        assert "available_templates" in s
        assert len(s["available_templates"]) == 10

    def test_list_templates(self, svc: SyntheticAttackService) -> None:
        assert len(svc.list_templates()) == 10

    def test_get_template_info(self, svc: SyntheticAttackService) -> None:
        info = svc.get_template_info("brute_force_auth")
        assert info["template_id"] == "brute_force_auth"
        assert "mitre_techniques" in info
        assert isinstance(info["domain"], str)  # domain serialised as string

    def test_get_unknown_template_raises(self, svc: SyntheticAttackService) -> None:
        with pytest.raises(TemplateNotFoundError):
            svc.get_template_info("nonexistent")

    def test_generate_returns_report(self, svc: SyntheticAttackService) -> None:
        r = svc.generate("brute_force_auth", "ws01", "alice")
        assert isinstance(r, GenerationReport)

    def test_generate_produces_events(self, svc: SyntheticAttackService) -> None:
        r = svc.generate("brute_force_auth", "ws01", "alice")
        assert r.total_events > 0

    def test_generate_unknown_template_raises(self, svc: SyntheticAttackService) -> None:
        with pytest.raises(TemplateNotFoundError):
            svc.generate("fake_template", "ws01", "alice")

    def test_get_canonical_events_returns_list(self, svc: SyntheticAttackService) -> None:
        r = svc.generate("brute_force_auth", "ws01", "alice")
        events = svc.get_canonical_events(r)
        assert all(isinstance(e, CanonicalEvent) for e in events)
        assert len(events) == r.total_events

    def test_events_sorted_by_timestamp(self, svc: SyntheticAttackService) -> None:
        r = svc.generate("brute_force_auth", "ws01", "alice")
        events = svc.get_canonical_events(r)
        for a, b in zip(events, events[1:]):
            assert a.timestamp <= b.timestamp

    def test_all_templates_via_service(self, svc: SyntheticAttackService) -> None:
        for tid in svc.list_templates():
            r = svc.generate(tid, "host1", "user1")
            assert r.total_events > 0

    def test_generate_scenario(self, svc: SyntheticAttackService, brute_force_scenario) -> None:
        r = svc.generate_scenario(brute_force_scenario)
        assert r.total_events > 0

    def test_generate_batch(self, svc: SyntheticAttackService) -> None:
        scenarios = [
            make_scenario("brute_force_auth"),
            make_scenario("credential_stuffing"),
        ]
        r = svc.generate_batch(scenarios)
        assert r.total_scenarios == 2
        assert r.total_events > 0

    def test_generate_stream(self, svc: SyntheticAttackService) -> None:
        scenarios = [make_scenario("brute_force_auth"), make_scenario("network_discovery_scan")]
        executions = list(svc.generate_stream(iter(scenarios)))
        assert len(executions) == 2
        for ex in executions:
            assert ex.total_events > 0

    def test_persist_saves_report(self, svc_persist: SyntheticAttackService) -> None:
        r = svc_persist.generate("brute_force_auth", "ws01", "alice")
        assert r.report_id in svc_persist.list_reports()

    def test_no_persist_no_reports(self, svc: SyntheticAttackService) -> None:
        svc.generate("brute_force_auth", "ws01", "alice")
        assert svc.list_reports() == []

    def test_load_report_after_persist(self, svc_persist: SyntheticAttackService) -> None:
        r = svc_persist.generate("brute_force_auth", "ws01", "alice")
        loaded = svc_persist.load_report(r.report_id)
        assert loaded.report_id == r.report_id

    def test_canonical_events_have_synthetic_flag(self, svc: SyntheticAttackService) -> None:
        r = svc.generate("brute_force_auth", "ws01", "alice")
        events = svc.get_canonical_events(r)
        assert all(e.extra_fields.get("synthetic") is True for e in events)

    def test_ot_events_field_population(self, svc: SyntheticAttackService) -> None:
        r = svc.generate("ot_register_manipulation", "plc01", "attacker")
        events = svc.get_canonical_events(r)
        ot_events = [e for e in events if e.modbus_register is not None]
        assert len(ot_events) >= 1
        for e in ot_events:
            assert e.modbus_function_code is not None
