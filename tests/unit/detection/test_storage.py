"""
tests/unit/detection/test_storage.py — ModelStore Tests
========================================================
Tests for atomic model persistence, load-latest, load-by-id,
schema validation, and list-models.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from backend.detection.exceptions import ModelNotTrainedError, SchemaCompatibilityError
from backend.detection.models import ModelMetadata
from backend.detection.preprocessor import FeaturePreprocessor
from backend.detection.storage import ModelStore
from backend.detection.trainer import _DetectionPipeline
from backend.features.models import ALL_FEATURE_NAMES, FEATURE_DIMENSION
from tests.unit.detection.conftest import make_normal_records


def make_real_pipeline() -> _DetectionPipeline:
    """Build a minimal real _DetectionPipeline that is picklable."""
    from sklearn.ensemble import IsolationForest

    records = make_normal_records(30)
    pp = FeaturePreprocessor()
    pp.fit_transform(records, entity_dim="user_host")
    iforest = IsolationForest(n_estimators=5, random_state=42)
    X = pp.transform(records)
    iforest.fit(X)
    return _DetectionPipeline(preprocessor=pp, isolation_forest=iforest)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_store(tmp_path: Path) -> ModelStore:
    """A ModelStore backed by a temp directory."""
    return ModelStore(store_dir=tmp_path / "models")


@pytest.fixture()
def sample_metadata() -> ModelMetadata:
    return ModelMetadata(
        model_id="iforest-test-store-001",
        feature_schema_version="1.0.0",
        feature_names=list(ALL_FEATURE_NAMES),
        feature_dimension=FEATURE_DIMENSION,
        n_estimators=10,
        contamination=0.05,
        random_state=42,
        entity_dimension="user_host",
        entity_count=20,
        sample_count=200,
        training_duration_seconds=0.5,
        scaler_fitted=True,
        model_file="isolation_forest_iforest-test-store-001.pkl",
    )


@pytest.fixture()
def mock_pipeline() -> _DetectionPipeline:
    """A real, picklable _DetectionPipeline for storage tests."""
    return make_real_pipeline()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestModelStore:
    def test_store_dir_created_on_init(self, tmp_path: Path) -> None:
        store_dir = tmp_path / "new_models"
        assert not store_dir.exists()
        ModelStore(store_dir=store_dir)
        assert store_dir.exists()

    def test_save_creates_two_files(
        self,
        tmp_store: ModelStore,
        sample_metadata: ModelMetadata,
        mock_pipeline: MagicMock,
    ) -> None:
        model_path, meta_path = tmp_store.save(mock_pipeline, sample_metadata)
        assert model_path.exists()
        assert meta_path.exists()
        assert model_path.suffix == ".pkl"
        assert meta_path.suffix == ".json"

    def test_save_atomic_no_tmp_files_remaining(
        self,
        tmp_store: ModelStore,
        sample_metadata: ModelMetadata,
        mock_pipeline: MagicMock,
    ) -> None:
        tmp_store.save(mock_pipeline, sample_metadata)
        store_dir = tmp_store._dir
        tmp_files = list(store_dir.glob("*.tmp"))
        assert len(tmp_files) == 0, f"Orphaned .tmp files: {tmp_files}"

    def test_save_and_load_latest(
        self,
        tmp_store: ModelStore,
        sample_metadata: ModelMetadata,
        mock_pipeline: MagicMock,
    ) -> None:
        tmp_store.save(mock_pipeline, sample_metadata)
        loaded_pipeline, loaded_meta = tmp_store.load_latest(validate_schema=False)
        assert loaded_meta.model_id == sample_metadata.model_id
        assert loaded_meta.sample_count == sample_metadata.sample_count

    def test_load_latest_empty_raises(self, tmp_store: ModelStore) -> None:
        with pytest.raises(ModelNotTrainedError):
            tmp_store.load_latest()

    def test_load_by_id_not_found_raises(self, tmp_store: ModelStore) -> None:
        with pytest.raises(ModelNotTrainedError):
            tmp_store.load_by_id("nonexistent-id")

    def test_load_by_id_success(
        self,
        tmp_store: ModelStore,
        sample_metadata: ModelMetadata,
        mock_pipeline: MagicMock,
    ) -> None:
        tmp_store.save(mock_pipeline, sample_metadata)
        pipeline, meta = tmp_store.load_by_id(sample_metadata.model_id, validate_schema=False)
        assert meta.model_id == sample_metadata.model_id

    def test_has_trained_model_false_when_empty(self, tmp_store: ModelStore) -> None:
        assert tmp_store.has_trained_model() is False

    def test_has_trained_model_true_after_save(
        self,
        tmp_store: ModelStore,
        sample_metadata: ModelMetadata,
        mock_pipeline: MagicMock,
    ) -> None:
        tmp_store.save(mock_pipeline, sample_metadata)
        assert tmp_store.has_trained_model() is True

    def test_list_models_empty(self, tmp_store: ModelStore) -> None:
        assert tmp_store.list_models() == []

    def test_list_models_sorted_newest_first(
        self,
        tmp_store: ModelStore,
        mock_pipeline: MagicMock,
    ) -> None:
        # Save two models with different timestamps
        old_meta = ModelMetadata(
            model_id="old-model",
            trained_at=datetime(2024, 1, 1, tzinfo=UTC),
            feature_schema_version="1.0.0",
            feature_names=list(ALL_FEATURE_NAMES),
            feature_dimension=FEATURE_DIMENSION,
            n_estimators=10,
            contamination=0.05,
            random_state=42,
            entity_dimension="user_host",
            model_file="isolation_forest_old-model.pkl",
        )
        new_meta = ModelMetadata(
            model_id="new-model",
            trained_at=datetime(2025, 1, 1, tzinfo=UTC),
            feature_schema_version="1.0.0",
            feature_names=list(ALL_FEATURE_NAMES),
            feature_dimension=FEATURE_DIMENSION,
            n_estimators=10,
            contamination=0.05,
            random_state=42,
            entity_dimension="user_host",
            model_file="isolation_forest_new-model.pkl",
        )
        tmp_store.save(mock_pipeline, old_meta)
        tmp_store.save(mock_pipeline, new_meta)

        models = tmp_store.list_models()
        assert len(models) == 2
        assert models[0].model_id == "new-model"
        assert models[1].model_id == "old-model"

    def test_schema_compatibility_check_passes_with_current_schema(
        self,
        tmp_store: ModelStore,
        sample_metadata: ModelMetadata,
        mock_pipeline: MagicMock,
    ) -> None:
        # sample_metadata uses current ALL_FEATURE_NAMES — should pass
        tmp_store.save(mock_pipeline, sample_metadata)
        # Should not raise
        _, meta = tmp_store.load_latest(validate_schema=True)
        assert meta.model_id == sample_metadata.model_id

    def test_schema_compatibility_fails_on_wrong_dim(
        self,
        tmp_store: ModelStore,
        mock_pipeline: MagicMock,
    ) -> None:
        # Build metadata with only 5 feature names (wrong)
        bad_meta = ModelMetadata(
            model_id="bad-schema",
            feature_schema_version="1.0.0",
            feature_names=["a", "b", "c", "d", "e"],
            feature_dimension=5,
            n_estimators=10,
            contamination=0.05,
            random_state=42,
            entity_dimension="user_host",
            model_file="isolation_forest_bad-schema.pkl",
        )
        tmp_store.save(mock_pipeline, bad_meta)
        with pytest.raises(SchemaCompatibilityError, match="dimension"):
            tmp_store.load_latest(validate_schema=True)

    def test_load_latest_skips_validate_schema_false(
        self,
        tmp_store: ModelStore,
        mock_pipeline: MagicMock,
    ) -> None:
        """validate_schema=False should not raise even with wrong feature names."""
        bad_meta = ModelMetadata(
            model_id="no-validate",
            feature_schema_version="1.0.0",
            feature_names=["a", "b"],
            feature_dimension=2,
            n_estimators=10,
            contamination=0.05,
            random_state=42,
            entity_dimension="user_host",
            model_file="isolation_forest_no-validate.pkl",
        )
        tmp_store.save(mock_pipeline, bad_meta)
        _, meta = tmp_store.load_latest(validate_schema=False)
        assert meta.model_id == "no-validate"

    def test_corrupt_metadata_file_is_skipped(
        self,
        tmp_store: ModelStore,
        sample_metadata: ModelMetadata,
        mock_pipeline: MagicMock,
        tmp_path: Path,
    ) -> None:
        """A corrupt metadata file should be skipped; valid models still loadable."""
        # Save a good model
        tmp_store.save(mock_pipeline, sample_metadata)
        # Plant a corrupt metadata file
        corrupt = tmp_store._dir / "isolation_forest_corrupt_meta.json"
        corrupt.write_text("{ not valid json {{{{", encoding="utf-8")

        # Should still return the good model
        models = tmp_store.list_models()
        assert any(m.model_id == sample_metadata.model_id for m in models)
