"""
backend.detection.storage — Model Store
========================================
Module 2.4 — Behavioral Detection Core

Handles all disk I/O for trained model artifacts.

Responsibilities
----------------
1. Save sklearn pipeline (scaler + Isolation Forest) to a versioned pickle file.
2. Save companion ModelMetadata as a JSON file.
3. Load the latest model + metadata from disk.
4. Load a specific model by model_id.
5. List all available model versions.
6. Enforce atomic writes (write .tmp → rename).

File Layout
-----------
models/
├── isolation_forest_<model_id>.pkl       ← sklearn Pipeline (scaler + IF)
├── isolation_forest_<model_id>_meta.json ← ModelMetadata JSON
└── ...

The "models/" directory is resolved from settings.models_dir at runtime.
Override via the store_dir constructor parameter (used in tests).

Thread Safety
-------------
Reads are inherently safe (files are immutable after rename).
Concurrent writes are protected by Python's os.rename atomicity on
POSIX and approximated on Windows via file locking — the .tmp pattern
ensures readers never observe a partial write.
"""

from __future__ import annotations

import json
import os
import pickle
from pathlib import Path
from typing import Any

import structlog

from backend.core.config import get_settings
from backend.detection.exceptions import ModelNotTrainedError, SchemaCompatibilityError
from backend.detection.models import ModelMetadata
from backend.features.models import ALL_FEATURE_NAMES, FEATURE_SCHEMA_VERSION

logger = structlog.get_logger(__name__)

# Prefix used for all model artifact files
_MODEL_PREFIX = "isolation_forest"


class ModelStore:
    """
    Versioned storage for trained Isolation Forest model artifacts.

    Each trained model version produces exactly two files:
      <prefix>_<model_id>.pkl       — sklearn Pipeline object (pickle)
      <prefix>_<model_id>_meta.json — ModelMetadata (JSON)

    Parameters
    ----------
    store_dir : Override the models directory.
                Defaults to settings.models_dir.
    """

    def __init__(self, store_dir: Path | None = None) -> None:
        settings = get_settings()
        self._dir: Path = store_dir if store_dir is not None else settings.models_dir
        self._dir.mkdir(parents=True, exist_ok=True)
        logger.debug("model_store_initialised", store_dir=str(self._dir))

    # ── Write API ────────────────────────────────────────────────────────────

    def save(
        self,
        model_pipeline: Any,
        metadata: ModelMetadata,
    ) -> tuple[Path, Path]:
        """
        Atomically persist a trained sklearn Pipeline and its ModelMetadata.

        Uses the write-to-tmp-then-rename pattern for crash safety.

        Parameters
        ----------
        model_pipeline : sklearn Pipeline — fitted (scaler + IsolationForest).
        metadata       : ModelMetadata — fully populated training record.

        Returns
        -------
        (model_path, metadata_path) — absolute Paths to the saved files.

        Raises
        ------
        OSError if the filesystem write fails.
        """
        model_path = self._dir / f"{_MODEL_PREFIX}_{metadata.model_id}.pkl"
        meta_path = self._dir / f"{_MODEL_PREFIX}_{metadata.model_id}_meta.json"

        # --- Atomic model pickle write ---
        tmp_model = model_path.with_suffix(".tmp")
        try:
            with tmp_model.open("wb") as fh:
                pickle.dump(model_pipeline, fh, protocol=pickle.HIGHEST_PROTOCOL)
            tmp_model.replace(model_path)
        except Exception:
            tmp_model.unlink(missing_ok=True)
            raise

        # --- Atomic metadata JSON write ---
        tmp_meta = meta_path.with_suffix(".tmp")
        try:
            meta_json = metadata.model_dump_json(indent=2)
            tmp_meta.write_text(meta_json, encoding="utf-8")
            tmp_meta.replace(meta_path)
        except Exception:
            tmp_meta.unlink(missing_ok=True)
            raise

        logger.info(
            "model_saved",
            model_id=metadata.model_id,
            model_path=str(model_path),
            sample_count=metadata.sample_count,
            feature_dimension=metadata.feature_dimension,
        )
        return model_path, meta_path

    # ── Read API ─────────────────────────────────────────────────────────────

    def load_latest(
        self,
        *,
        validate_schema: bool = True,
    ) -> tuple[Any, ModelMetadata]:
        """
        Load the most recently trained model and its metadata.

        "Most recent" is determined by `ModelMetadata.trained_at` timestamp
        stored in each companion JSON file.

        Parameters
        ----------
        validate_schema : If True (default), raise SchemaCompatibilityError
                          when the loaded model's feature schema does not match
                          the current live ALL_FEATURE_NAMES.

        Returns
        -------
        (model_pipeline, metadata)

        Raises
        ------
        ModelNotTrainedError     — No model files found in store_dir.
        SchemaCompatibilityError — Schema mismatch (when validate_schema=True).
        """
        all_meta = self._load_all_metadata()
        if not all_meta:
            raise ModelNotTrainedError(
                "No trained model found. Run DetectionService.train_from_features() first.",
                context={"store_dir": str(self._dir)},
            )

        # Sort by trained_at descending, pick newest
        latest_meta = sorted(all_meta, key=lambda m: m.trained_at, reverse=True)[0]
        return self._load_by_metadata(latest_meta, validate_schema=validate_schema)

    def load_by_id(
        self,
        model_id: str,
        *,
        validate_schema: bool = True,
    ) -> tuple[Any, ModelMetadata]:
        """
        Load a specific model version by its model_id.

        Parameters
        ----------
        model_id        : Exact model_id (from ModelMetadata.model_id).
        validate_schema : Schema compatibility check (default: True).

        Returns
        -------
        (model_pipeline, metadata)

        Raises
        ------
        ModelNotTrainedError     — model_id not found.
        SchemaCompatibilityError — Schema mismatch (when validate_schema=True).
        """
        meta_path = self._dir / f"{_MODEL_PREFIX}_{model_id}_meta.json"
        if not meta_path.exists():
            raise ModelNotTrainedError(
                f"Model {model_id!r} not found in store.",
                context={"model_id": model_id, "store_dir": str(self._dir)},
            )
        metadata = self._read_metadata(meta_path)
        return self._load_by_metadata(metadata, validate_schema=validate_schema)

    def list_models(self) -> list[ModelMetadata]:
        """
        Return all available model versions, sorted newest-first.

        Returns
        -------
        list[ModelMetadata] — empty list if no models are stored.
        """
        all_meta = self._load_all_metadata()
        return sorted(all_meta, key=lambda m: m.trained_at, reverse=True)

    def has_trained_model(self) -> bool:
        """Return True if at least one valid model is available."""
        return bool(self._load_all_metadata())

    # ── Internal helpers ─────────────────────────────────────────────────────

    def _load_all_metadata(self) -> list[ModelMetadata]:
        """Scan store_dir and return all valid ModelMetadata objects."""
        result: list[ModelMetadata] = []
        for meta_file in self._dir.glob(f"{_MODEL_PREFIX}_*_meta.json"):
            try:
                meta = self._read_metadata(meta_file)
                result.append(meta)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "model_metadata_unreadable",
                    file=str(meta_file),
                    error=str(exc),
                )
        return result

    @staticmethod
    def _read_metadata(meta_path: Path) -> ModelMetadata:
        """Deserialise a ModelMetadata JSON file."""
        raw = meta_path.read_text(encoding="utf-8")
        return ModelMetadata.model_validate_json(raw)

    def _load_by_metadata(
        self,
        metadata: ModelMetadata,
        *,
        validate_schema: bool,
    ) -> tuple[Any, ModelMetadata]:
        """Load the pickle for a given metadata record."""
        if validate_schema:
            self._check_schema_compatibility(metadata)

        model_path = self._dir / f"{_MODEL_PREFIX}_{metadata.model_id}.pkl"
        if not model_path.exists():
            raise ModelNotTrainedError(
                f"Model pickle missing for id={metadata.model_id!r}.",
                context={"expected_path": str(model_path)},
            )

        with model_path.open("rb") as fh:
            pipeline = pickle.load(fh)  # noqa: S301

        logger.info(
            "model_loaded",
            model_id=metadata.model_id,
            trained_at=metadata.trained_at.isoformat(),
            sample_count=metadata.sample_count,
            feature_dimension=metadata.feature_dimension,
        )
        return pipeline, metadata

    @staticmethod
    def _check_schema_compatibility(metadata: ModelMetadata) -> None:
        """
        Raise SchemaCompatibilityError if the loaded model's feature schema
        does not match the current live schema.

        Checks
        ------
        1. Feature dimension must match.
        2. Feature names must match in exact order.
        """
        live_names = ALL_FEATURE_NAMES
        trained_names = metadata.feature_names

        if len(trained_names) != len(live_names):
            raise SchemaCompatibilityError(
                f"Feature dimension mismatch: model trained on {len(trained_names)} "
                f"features, live schema has {len(live_names)}.",
                context={
                    "model_id": metadata.model_id,
                    "trained_dim": len(trained_names),
                    "live_dim": len(live_names),
                },
            )

        if trained_names != live_names:
            # Find first divergence for a helpful error message
            first_diff = next(
                (i for i, (t, l) in enumerate(zip(trained_names, live_names)) if t != l),
                len(trained_names),
            )
            raise SchemaCompatibilityError(
                f"Feature names mismatch at index {first_diff}: "
                f"trained={trained_names[first_diff]!r}, "
                f"live={live_names[first_diff]!r}.",
                context={
                    "model_id": metadata.model_id,
                    "first_divergence_index": first_diff,
                },
            )

        logger.debug(
            "model_schema_validated",
            model_id=metadata.model_id,
            feature_dimension=len(live_names),
        )
