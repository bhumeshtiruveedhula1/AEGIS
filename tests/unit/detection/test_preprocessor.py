"""
tests/unit/detection/test_preprocessor.py — FeaturePreprocessor Tests
======================================================================
"""

from __future__ import annotations

import numpy as np
import pytest

from backend.detection.preprocessor import FeaturePreprocessor
from backend.features.models import FEATURE_DIMENSION
from tests.unit.detection.conftest import (
    make_anomalous_record,
    make_feature_record,
    make_normal_records,
)


class TestFeaturePreprocessor:
    def test_not_fitted_on_init(self) -> None:
        pp = FeaturePreprocessor()
        assert pp.is_fitted is False

    def test_fit_transform_returns_correct_shape(self) -> None:
        pp = FeaturePreprocessor()
        records = make_normal_records(50)
        X = pp.fit_transform(records, entity_dim="user_host")
        assert X.shape == (50, FEATURE_DIMENSION)
        assert X.dtype == np.float64

    def test_is_fitted_after_fit_transform(self) -> None:
        pp = FeaturePreprocessor()
        records = make_normal_records(20)
        pp.fit_transform(records, entity_dim="user_host")
        assert pp.is_fitted is True

    def test_filter_by_entity_dim(self) -> None:
        pp = FeaturePreprocessor()
        uh_records = make_normal_records(30, entity_type="user_host")
        user_records = make_normal_records(10, entity_type="user")
        all_records = uh_records + user_records

        filtered = pp.filter_records(all_records, entity_dim="user_host")
        assert len(filtered) == 30

        filtered_user = pp.filter_records(all_records, entity_dim="user")
        assert len(filtered_user) == 10

    def test_fit_transform_filters_entity_dim(self) -> None:
        pp = FeaturePreprocessor()
        # 20 user_host + 10 user — only user_host should be trained on
        uh = make_normal_records(20, entity_type="user_host")
        user = make_normal_records(10, entity_type="user")
        X = pp.fit_transform(uh + user, entity_dim="user_host")
        assert X.shape[0] == 20

    def test_fit_transform_empty_entity_dim_raises(self) -> None:
        pp = FeaturePreprocessor()
        records = make_normal_records(20, entity_type="user")
        with pytest.raises(ValueError, match="No FeatureRecord"):
            pp.fit_transform(records, entity_dim="user_host")

    def test_transform_without_fit_raises(self) -> None:
        pp = FeaturePreprocessor()
        records = make_normal_records(5)
        with pytest.raises(RuntimeError, match="not been fitted"):
            pp.transform(records)

    def test_transform_single_returns_correct_shape(self) -> None:
        pp = FeaturePreprocessor()
        records = make_normal_records(30)
        pp.fit_transform(records)
        single = make_feature_record()
        X = pp.transform_single(single)
        assert X.shape == (1, FEATURE_DIMENSION)

    def test_scaled_output_has_zero_mean_approximately(self) -> None:
        """StandardScaler should produce ~0 mean on training data."""
        pp = FeaturePreprocessor()
        records = make_normal_records(200)
        X = pp.fit_transform(records)
        # All training records have identical feature values (0.0) so
        # scaler sets mean=0, std=1 (or std=0 for constant features).
        # Column means should be close to 0.
        assert np.abs(X.mean(axis=0)).max() < 1e-6

    def test_no_nan_or_inf_in_output(self) -> None:
        pp = FeaturePreprocessor()
        records = make_normal_records(50)
        X = pp.fit_transform(records)
        assert np.all(np.isfinite(X))

    def test_transform_anomalous_record_is_finite(self) -> None:
        pp = FeaturePreprocessor()
        normal = make_normal_records(50)
        pp.fit_transform(normal)
        anomalous = make_anomalous_record()
        X = pp.transform_single(anomalous)
        assert np.all(np.isfinite(X))

    def test_validate_schema_passes_on_current_schema(self) -> None:
        pp = FeaturePreprocessor()
        # Should not raise — live schema matches construction snapshot
        pp.validate_schema()
