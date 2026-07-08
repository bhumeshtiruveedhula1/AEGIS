"""
backend.baseline.storage — Baseline Persistence Layer
=====================================================
Module 2.1 — Baseline Generator

BaselineStore handles all read/write operations for baseline artefacts.

Storage Layout
--------------
data/baseline/
  manifest.json                     — index of all profiles
  profiles/
    <profile_id>.json               — full BaselineProfile
  entities/
    user/
      svc-iis.json                  — EntityBaseline for user "svc-iis"
    host/
      hospital-server-01.json
    source/
      hospital_server.json
    user_host/
      svc-iis::hospital-server-01.json

Format
------
All files are UTF-8 JSON.
- Human-readable (2-space indent).
- Self-describing (all field names present).
- Diffable in Git for audit purposes.
- Pydantic model_dump(mode="json") → json.dumps → file.

Version Safety
--------------
Every file contains baseline_version.
BaselineStore validates version on load.
Raises BaselineVersionError on mismatch.

Thread Safety
-------------
BaselineStore is NOT thread-safe. Use one instance per process,
or wrap with an external lock for concurrent access.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

import structlog

from backend.baseline.exceptions import (
    BaselineNotFoundError,
    BaselineStorageError,
    BaselineVersionError,
)
from backend.baseline.models import (
    BASELINE_SCHEMA_VERSION,
    BaselineManifest,
    BaselineProfile,
    EntityBaseline,
    EntityKey,
)

logger = structlog.get_logger(__name__)

_DEFAULT_BASELINE_DIR = Path("./data/baseline")


class BaselineStore:
    """
    Reads and writes baseline artefacts to the filesystem.

    Parameters
    ----------
    baseline_dir:  Root directory for baseline storage.
                   Defaults to data/baseline/.
    """

    def __init__(self, baseline_dir: Path | None = None) -> None:
        self._root = baseline_dir or _DEFAULT_BASELINE_DIR
        self._profiles_dir = self._root / "profiles"
        self._entities_dir = self._root / "entities"
        self._manifest_path = self._root / "manifest.json"
        # Reentrant lock guards all write operations.
        # BaselineStore is used from a single process, but may be called
        # from multiple threads (e.g., scheduled updater + API thread).
        # RLock allows the same thread to re-enter (e.g. save → _update_manifest).
        self._lock = threading.RLock()

    @property
    def baseline_dir(self) -> Path:
        """Root directory for all baseline artefacts."""
        return self._root

    # ── Profile operations ──────────────────────────────────────────────────

    def save(self, profile: BaselineProfile) -> Path:
        """
        Persist a BaselineProfile to disk.

        Writes to profiles/<profile_id>.json.
        Also updates the manifest.json index.

        Parameters
        ----------
        profile:  The profile to persist.

        Returns
        -------
        Path of the written profile file.

        Raises
        ------
        BaselineStorageError on I/O failure.
        """
        self._ensure_dirs()
        profile_path = self._profiles_dir / f"{profile.profile_id}.json"

        with self._lock:
            try:
                data = profile.model_dump(mode="json")
                self._write_json(profile_path, data)
            except (OSError, TypeError, ValueError) as exc:
                raise BaselineStorageError(
                    f"Failed to save profile {profile.profile_id}: {exc}",
                    path=str(profile_path),
                ) from exc

            # Update manifest
            self._update_manifest(profile)

        logger.info(
            "baseline_store_profile_saved",
            profile_id=profile.profile_id,
            entity_count=profile.entity_count,
            path=str(profile_path),
        )
        return profile_path

    def load(self, profile_id: str) -> BaselineProfile:
        """
        Load a BaselineProfile by profile_id.

        Raises
        ------
        BaselineNotFoundError if the profile file does not exist.
        BaselineVersionError if the schema version is incompatible.
        BaselineStorageError on I/O or parse failure.
        """
        profile_path = self._profiles_dir / f"{profile_id}.json"

        if not profile_path.exists():
            raise BaselineNotFoundError(
                f"Profile not found: {profile_id}",
                entity_type="profile",
                entity_id=profile_id,
            )

        data = self._read_json(profile_path)
        self._check_version(data, profile_path)

        try:
            return BaselineProfile.model_validate(data)
        except Exception as exc:  # noqa: BLE001
            raise BaselineStorageError(
                f"Failed to deserialise profile {profile_id}: {exc}",
                path=str(profile_path),
            ) from exc

    def load_latest(self) -> BaselineProfile:
        """
        Load the most recently built BaselineProfile.

        Returns
        -------
        The latest BaselineProfile.

        Raises
        ------
        BaselineNotFoundError if no profiles have been saved yet.
        """
        manifest = self.load_manifest()
        if manifest.latest_profile_id is None:
            raise BaselineNotFoundError(
                "No baseline profiles found. Run BaselineBuilder.build_from_file() first.",
                entity_type="profile",
                entity_id="latest",
            )
        return self.load(manifest.latest_profile_id)

    def profile_exists(self, profile_id: str) -> bool:
        """Return True if a profile with this ID exists on disk."""
        return (self._profiles_dir / f"{profile_id}.json").exists()

    def list_profiles(self) -> list[str]:
        """Return all stored profile IDs (newest-first from manifest)."""
        manifest = self.load_manifest()
        return [entry.profile_id for entry in manifest.profiles]

    # ── Entity operations ───────────────────────────────────────────────────

    def save_entity(self, entity_key: EntityKey, baseline: EntityBaseline) -> Path:
        """
        Persist one EntityBaseline to its own JSON file.

        This is called by BaselineUpdater for incremental entity updates.
        The entity file can be loaded without loading the entire profile.

        Returns
        -------
        Path of the written entity file.
        """
        entity_dir = self._entities_dir / entity_key.entity_type
        entity_dir.mkdir(parents=True, exist_ok=True)

        safe_name = entity_key.entity_id.replace("::", "_").replace("/", "_")
        entity_path = entity_dir / f"{safe_name}.json"

        with self._lock:
            try:
                data = baseline.model_dump(mode="json")
                self._write_json(entity_path, data)
            except (OSError, TypeError, ValueError) as exc:
                raise BaselineStorageError(
                    f"Failed to save entity {entity_key!r}: {exc}",
                    path=str(entity_path),
                ) from exc

        logger.debug(
            "baseline_store_entity_saved",
            entity=repr(entity_key),
            path=str(entity_path),
        )
        return entity_path

    def load_entity(self, entity_key: EntityKey) -> EntityBaseline:
        """
        Load one EntityBaseline by EntityKey.

        Raises
        ------
        BaselineNotFoundError if the entity file does not exist.
        BaselineVersionError on schema mismatch.
        BaselineStorageError on I/O failure.
        """
        safe_name = entity_key.entity_id.replace("::", "_").replace("/", "_")
        entity_path = self._entities_dir / entity_key.entity_type / f"{safe_name}.json"

        if not entity_path.exists():
            raise BaselineNotFoundError(
                f"Entity baseline not found: {entity_key!r}",
                entity_type=entity_key.entity_type,
                entity_id=entity_key.entity_id,
            )

        data = self._read_json(entity_path)
        self._check_version(data, entity_path)

        try:
            return EntityBaseline.model_validate(data)
        except Exception as exc:  # noqa: BLE001
            raise BaselineStorageError(
                f"Failed to deserialise entity {entity_key!r}: {exc}",
                path=str(entity_path),
            ) from exc

    def entity_exists(self, entity_key: EntityKey) -> bool:
        """Return True if a persisted EntityBaseline exists for this key."""
        safe_name = entity_key.entity_id.replace("::", "_").replace("/", "_")
        entity_path = self._entities_dir / entity_key.entity_type / f"{safe_name}.json"
        return entity_path.exists()

    def save_profile_entities(self, profile: BaselineProfile) -> int:
        """
        Write each EntityBaseline in a profile as its own JSON file.

        Called after a full build to enable per-entity incremental lookups.

        Returns
        -------
        Count of entity files written.
        """
        self._ensure_dirs()
        count = 0
        for storage_key, baseline in profile.entities.items():
            parts = storage_key.split("__", 1)
            if len(parts) == 2:  # noqa: PLR2004
                key = EntityKey(entity_type=parts[0], entity_id=parts[1])
                self.save_entity(key, baseline)
                count += 1
        logger.info("baseline_store_entities_written", count=count)
        return count

    # ── Manifest operations ─────────────────────────────────────────────────

    def load_manifest(self) -> BaselineManifest:
        """
        Load the baseline manifest.

        Returns an empty manifest if the file does not exist yet.
        """
        if not self._manifest_path.exists():
            return BaselineManifest()
        data = self._read_json(self._manifest_path)
        try:
            return BaselineManifest.model_validate(data)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "baseline_store_manifest_corrupt",
                error=str(exc),
            )
            return BaselineManifest()

    def _update_manifest(self, profile: BaselineProfile) -> None:
        """Insert this profile into the manifest and persist atomically."""
        # Called under self._lock from save() and save_profile_entities().
        # RLock allows re-entry from within the same thread.
        self._ensure_dirs()
        manifest = self.load_manifest()
        manifest.add_entry(profile)
        try:
            self._write_json(self._manifest_path, manifest.model_dump(mode="json"))
        except (OSError, TypeError, ValueError) as exc:
            raise BaselineStorageError(
                f"Failed to update manifest: {exc}",
                path=str(self._manifest_path),
            ) from exc

    # ── Private helpers ─────────────────────────────────────────────────────

    def _ensure_dirs(self) -> None:
        """Create the baseline directory hierarchy if needed."""
        self._root.mkdir(parents=True, exist_ok=True)
        self._profiles_dir.mkdir(parents=True, exist_ok=True)
        self._entities_dir.mkdir(parents=True, exist_ok=True)

    def _write_json(self, path: Path, data: dict) -> None:
        """Write a dict as pretty-printed UTF-8 JSON."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    def _read_json(self, path: Path) -> dict:
        """Read and parse a JSON file."""
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise BaselineStorageError(
                f"Failed to read {path}: {exc}",
                path=str(path),
            ) from exc

    def _check_version(self, data: dict, path: Path) -> None:
        """Raise BaselineVersionError if stored version is incompatible."""
        stored = data.get("baseline_version", "unknown")
        if stored != BASELINE_SCHEMA_VERSION:
            raise BaselineVersionError(
                f"Incompatible baseline version in {path.name}: "
                f"stored={stored!r}, current={BASELINE_SCHEMA_VERSION!r}. "
                "Re-run BaselineBuilder to produce a compatible baseline.",
                stored_version=stored,
                current_version=BASELINE_SCHEMA_VERSION,
            )
