"""tests/unit/replay/test_storage.py — ReplayStore persistence tests."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from backend.replay.exceptions import ReplaySessionNotFoundError

if TYPE_CHECKING:
    from backend.replay.storage import ReplayStore


class TestReplayStoreSave:
    def test_save_creates_index_file(self, store: ReplayStore) -> None:
        from tests.unit.replay.conftest import _make_session
        s = _make_session(2)
        store.save(s)
        assert store.exists(s.session_id)

    def test_save_creates_log_entry(self, store: ReplayStore) -> None:
        from tests.unit.replay.conftest import _make_session
        s = _make_session(2)
        store.save(s)
        assert s.session_id in store.list_ids()

    def test_save_update_overwrites_index(self, store: ReplayStore) -> None:
        from tests.unit.replay.conftest import _make_session
        s = _make_session(2)
        store.save(s)
        s2 = s.model_copy(update={"name": "updated"})
        store.save(s2)
        loaded = store.load(s.session_id)
        assert loaded.name == "updated"

    def test_save_update_does_not_duplicate_log(self, store: ReplayStore) -> None:
        from tests.unit.replay.conftest import _make_session
        s = _make_session(2)
        store.save(s)
        s2 = s.model_copy(update={"name": "v2"})
        store.save(s2)
        ids = store.list_ids()
        assert ids.count(s.session_id) == 1


class TestReplayStoreLoad:
    def test_load_returns_session(self, store: ReplayStore) -> None:
        from tests.unit.replay.conftest import _make_session
        s = _make_session(3)
        store.save(s)
        loaded = store.load(s.session_id)
        assert loaded.session_id == s.session_id
        assert loaded.total_frames == 3

    def test_load_nonexistent_raises(self, store: ReplayStore) -> None:
        with pytest.raises(ReplaySessionNotFoundError):
            store.load("does-not-exist")

    def test_load_all_returns_all(self, store: ReplayStore) -> None:
        from tests.unit.replay.conftest import _make_session
        for _ in range(3):
            store.save(_make_session(2))
        sessions = store.load_all()
        assert len(sessions) == 3

    def test_load_all_empty(self, store: ReplayStore) -> None:
        assert store.load_all() == []


class TestReplayStoreListing:
    def test_list_ids_newest_first(self, store: ReplayStore) -> None:
        from tests.unit.replay.conftest import _make_session
        ids = []
        for _ in range(3):
            s = _make_session(1)
            store.save(s)
            ids.append(s.session_id)
        listed = store.list_ids()
        # newest first = reverse insertion order
        assert listed[0] == ids[-1]

    def test_count_empty(self, store: ReplayStore) -> None:
        assert store.count() == 0

    def test_count_after_saves(self, store: ReplayStore) -> None:
        from tests.unit.replay.conftest import _make_session
        for _ in range(4):
            store.save(_make_session(1))
        assert store.count() == 4

    def test_exists_true(self, store: ReplayStore) -> None:
        from tests.unit.replay.conftest import _make_session
        s = _make_session(1)
        store.save(s)
        assert store.exists(s.session_id)

    def test_exists_false(self, store: ReplayStore) -> None:
        assert not store.exists("ghost")


class TestReplayStoreRobustness:
    def test_corrupt_index_skipped_in_load_all(self, store: ReplayStore) -> None:
        from tests.unit.replay.conftest import _make_session
        s = _make_session(2)
        store.save(s)
        # Corrupt the log to reference a nonexistent session
        log = store._dir / "sessions.jsonl"
        with log.open("a") as fh:
            fh.write("ghost-session-id\n")
        # load_all should skip the corrupt/missing entry silently
        sessions = store.load_all()
        assert len(sessions) == 1
        assert sessions[0].session_id == s.session_id

    def test_load_all_skips_schema_errors(self, store: ReplayStore) -> None:
        from tests.unit.replay.conftest import _make_session
        s = _make_session(2)
        store.save(s)
        # Corrupt the index file
        bad_path = store._index_dir / f"{s.session_id}.json"
        bad_path.write_text("NOT_VALID_JSON", encoding="utf-8")
        sessions = store.load_all()
        assert sessions == []
