"""
tests/unit/baseline/test_storage.py
=====================================
Unit tests for BaselineStore — JSON persistence layer.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from backend.baseline.builder import BaselineBuilder
from backend.baseline.exceptions import (
    BaselineNotFoundError,
    BaselineVersionError,
)
from backend.baseline.models import (
    BASELINE_SCHEMA_VERSION,
    BaselineManifest,
    BaselineProfile,
    EntityBaseline,
    EntityKey,
)
from backend.baseline.storage import BaselineStore
from tests.unit.baseline.conftest import make_hospital_batch, make_ot_batch


# ===========================================================================
# save() and load() — profile round-trip
# ===========================================================================

class TestProfileRoundTrip:

    def _build_profile(self) -> BaselineProfile:
        return BaselineBuilder(dimensions={"user"}).build_from_events(
            make_hospital_batch(10)
        )

    def test_save_creates_file(self, tmp_path: Path) -> None:
        store = BaselineStore(baseline_dir=tmp_path)
        profile = self._build_profile()
        path = store.save(profile)
        assert path.exists()

    def test_save_returns_correct_path(self, tmp_path: Path) -> None:
        store = BaselineStore(baseline_dir=tmp_path)
        profile = self._build_profile()
        path = store.save(profile)
        assert profile.profile_id in path.name

    def test_load_returns_same_profile_id(self, tmp_path: Path) -> None:
        store = BaselineStore(baseline_dir=tmp_path)
        profile = self._build_profile()
        store.save(profile)
        loaded = store.load(profile.profile_id)
        assert loaded.profile_id == profile.profile_id

    def test_load_returns_correct_entity_count(self, tmp_path: Path) -> None:
        store = BaselineStore(baseline_dir=tmp_path)
        profile = self._build_profile()
        store.save(profile)
        loaded = store.load(profile.profile_id)
        assert loaded.entity_count == profile.entity_count

    def test_load_missing_profile_raises(self, tmp_path: Path) -> None:
        store = BaselineStore(baseline_dir=tmp_path)
        with pytest.raises(BaselineNotFoundError):
            store.load("nonexistent-profile-id")

    def test_profile_json_is_human_readable(self, tmp_path: Path) -> None:
        store = BaselineStore(baseline_dir=tmp_path)
        profile = self._build_profile()
        path = store.save(profile)
        content = path.read_text(encoding="utf-8")
        # Indented JSON (pretty-printed)
        assert "  " in content
        # Valid JSON
        parsed = json.loads(content)
        assert "profile_id" in parsed

    def test_profile_exists_returns_true_after_save(self, tmp_path: Path) -> None:
        store = BaselineStore(baseline_dir=tmp_path)
        profile = self._build_profile()
        store.save(profile)
        assert store.profile_exists(profile.profile_id)

    def test_profile_exists_returns_false_before_save(self, tmp_path: Path) -> None:
        store = BaselineStore(baseline_dir=tmp_path)
        assert not store.profile_exists("unknown-id")

    def test_load_latest_after_save(self, tmp_path: Path) -> None:
        store = BaselineStore(baseline_dir=tmp_path)
        profile = self._build_profile()
        store.save(profile)
        latest = store.load_latest()
        assert latest.profile_id == profile.profile_id

    def test_load_latest_returns_most_recent(self, tmp_path: Path) -> None:
        store = BaselineStore(baseline_dir=tmp_path)
        p1 = self._build_profile()
        p2 = self._build_profile()
        store.save(p1)
        store.save(p2)
        latest = store.load_latest()
        assert latest.profile_id == p2.profile_id

    def test_load_latest_raises_when_no_profiles(self, tmp_path: Path) -> None:
        store = BaselineStore(baseline_dir=tmp_path)
        with pytest.raises(BaselineNotFoundError):
            store.load_latest()

    def test_list_profiles_returns_all_ids(self, tmp_path: Path) -> None:
        store = BaselineStore(baseline_dir=tmp_path)
        p1 = self._build_profile()
        p2 = self._build_profile()
        store.save(p1)
        store.save(p2)
        ids = store.list_profiles()
        assert p1.profile_id in ids
        assert p2.profile_id in ids

    def test_version_mismatch_raises_on_load(self, tmp_path: Path) -> None:
        store = BaselineStore(baseline_dir=tmp_path)
        profile = self._build_profile()
        path = store.save(profile)

        # Tamper with the version
        data = json.loads(path.read_text(encoding="utf-8"))
        data["baseline_version"] = "99.0.0"
        path.write_text(json.dumps(data), encoding="utf-8")

        with pytest.raises(BaselineVersionError):
            store.load(profile.profile_id)


# ===========================================================================
# save_entity() and load_entity() — per-entity files
# ===========================================================================

class TestEntityRoundTrip:

    def test_save_entity_creates_file(self, tmp_path: Path) -> None:
        store = BaselineStore(baseline_dir=tmp_path)
        key = EntityKey(entity_type="user", entity_id="svc-iis")
        eb = EntityBaseline(entity_key=key, observation_count=10)
        path = store.save_entity(key, eb)
        assert path.exists()

    def test_load_entity_round_trip(self, tmp_path: Path) -> None:
        store = BaselineStore(baseline_dir=tmp_path)
        key = EntityKey(entity_type="user", entity_id="svc-iis")
        eb = EntityBaseline(entity_key=key, observation_count=25)
        store.save_entity(key, eb)
        loaded = store.load_entity(key)
        assert loaded.observation_count == 25
        assert loaded.entity_key == key

    def test_load_entity_missing_raises(self, tmp_path: Path) -> None:
        store = BaselineStore(baseline_dir=tmp_path)
        key = EntityKey(entity_type="host", entity_id="ghost-host")
        with pytest.raises(BaselineNotFoundError):
            store.load_entity(key)

    def test_entity_exists_true_after_save(self, tmp_path: Path) -> None:
        store = BaselineStore(baseline_dir=tmp_path)
        key = EntityKey(entity_type="source", entity_id="ot_node")
        eb = EntityBaseline(entity_key=key)
        store.save_entity(key, eb)
        assert store.entity_exists(key)

    def test_entity_exists_false_before_save(self, tmp_path: Path) -> None:
        store = BaselineStore(baseline_dir=tmp_path)
        key = EntityKey(entity_type="user", entity_id="nobody")
        assert not store.entity_exists(key)

    def test_user_host_key_safe_filename(self, tmp_path: Path) -> None:
        """Double-colon entity_id should not create nested directories."""
        store = BaselineStore(baseline_dir=tmp_path)
        key = EntityKey(entity_type="user_host", entity_id="svc-iis::hospital-server-01")
        eb = EntityBaseline(entity_key=key)
        path = store.save_entity(key, eb)
        assert path.exists()
        assert "::" not in path.name


# ===========================================================================
# save_profile_entities
# ===========================================================================

class TestSaveProfileEntities:

    def test_writes_one_file_per_entity(self, tmp_path: Path) -> None:
        store = BaselineStore(baseline_dir=tmp_path)
        profile = BaselineBuilder(dimensions={"user"}).build_from_events(
            make_hospital_batch(10)
        )
        store.save(profile)
        count = store.save_profile_entities(profile)
        assert count == profile.entity_count


# ===========================================================================
# Manifest
# ===========================================================================

class TestManifest:

    def test_empty_manifest_returned_when_no_file(self, tmp_path: Path) -> None:
        store = BaselineStore(baseline_dir=tmp_path)
        manifest = store.load_manifest()
        assert isinstance(manifest, BaselineManifest)
        assert manifest.latest_profile_id is None

    def test_manifest_updated_after_save(self, tmp_path: Path) -> None:
        store = BaselineStore(baseline_dir=tmp_path)
        profile = BaselineBuilder(dimensions={"user"}).build_from_events(
            make_hospital_batch(5)
        )
        store.save(profile)
        manifest = store.load_manifest()
        assert manifest.latest_profile_id == profile.profile_id
        assert len(manifest.profiles) == 1
