"""
backend.metrics.collectors.health — Platform Health Metrics Collector
=====================================================================
Module 2.3 — Metrics Collection & Evaluation Engine

Collects PlatformHealthMetrics by inspecting:
  - Schema version constants across all modules
  - BaselineReader operational state
  - File system presence of key data artifacts
  - Application settings / feature flags
  - Collection timestamp

All health metrics are fully available now — they do not depend on
future modules, only on the current state of the platform runtime.

Component Health Checks
-----------------------
Each component is checked via a lightweight probe and assigned
ComponentStatus: HEALTHY | DEGRADED | UNAVAILABLE | NOT_IMPLEMENTED
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from backend.baseline.models import BASELINE_SCHEMA_VERSION
from backend.core.config import get_settings
from backend.features.models import FEATURE_SCHEMA_VERSION
from backend.metrics.collectors import BaseCollector, register_collector
from backend.metrics.models import (
    METRICS_SCHEMA_VERSION,
    ComponentHealth,
    ComponentStatus,
    MetricDomain,
    MetricValue,
    PlatformHealthMetrics,
)


@register_collector
class PlatformHealthCollector(BaseCollector):
    """Collects cross-module health indicators and schema version tracking."""

    @property
    def domain(self) -> MetricDomain:
        return MetricDomain.PLATFORM_HEALTH

    @property
    def name(self) -> str:
        return "platform_health"

    def collect(self, **kwargs: Any) -> PlatformHealthMetrics:
        """
        Compute PlatformHealthMetrics from runtime state.

        Keyword Arguments
        -----------------
        baseline_reader : BaselineReader | None
        """
        reader = kwargs.get("baseline_reader")
        settings = get_settings()
        now = datetime.now(UTC)

        components = self._check_components(settings, reader)
        enabled_flags = self._enabled_flags(settings)

        return PlatformHealthMetrics(
            normalization_schema_version=MetricValue.computed(
                "1.0",  # canonical event version
                description="CanonicalEvent normalization schema version.",
            ),
            baseline_schema_version=MetricValue.computed(
                BASELINE_SCHEMA_VERSION,
                description="BaselineProfile schema version.",
            ),
            feature_schema_version=MetricValue.computed(
                FEATURE_SCHEMA_VERSION,
                description="FeatureVector schema version.",
            ),
            metrics_schema_version=MetricValue.computed(
                METRICS_SCHEMA_VERSION,
                description="MetricSnapshot schema version.",
            ),
            components=components,
            feature_flags_enabled=MetricValue.computed(
                enabled_flags,
                description="Names of currently enabled feature flags.",
            ),
            app_environment=MetricValue.computed(
                settings.app_env,
                description="Current deployment environment.",
            ),
            collection_timestamp=MetricValue.computed(
                now.isoformat(),
                description="UTC timestamp when this health snapshot was collected.",
            ),
        )

    # ── Component health probes ──────────────────────────────────────────

    def _check_components(
        self,
        settings: Any,
        reader: Any,
    ) -> list[ComponentHealth]:
        """Run lightweight probes for each platform component."""
        components = []

        # Module 1.3 — Normalization pipeline
        components.append(self._check_normalization(settings))

        # Module 2.1 — Baseline system
        components.append(self._check_baseline(settings, reader))

        # Module 2.2 — Feature engine
        components.append(self._check_feature_engine(settings))

        # Module 2.3 — Metrics engine (self)
        components.append(ComponentHealth(
            name="metrics_engine",
            status=ComponentStatus.HEALTHY,
            version=METRICS_SCHEMA_VERSION,
            detail="Metrics collection engine operational.",
        ))

        # Future modules — mark NOT_IMPLEMENTED
        for future_name in ("detection_core", "response_orchestrator", "llm_enrichment"):
            components.append(ComponentHealth(
                name=future_name,
                status=ComponentStatus.NOT_IMPLEMENTED,
                detail="Planned for a future implementation phase.",
            ))

        return components

    def _check_normalization(self, settings: Any) -> ComponentHealth:
        """Check if normalization output exists and is non-empty."""
        try:
            norm_dir = settings.norm_output_dir
            norm_file = norm_dir / "normalized_events.jsonl"
            if norm_file.exists() and norm_file.stat().st_size > 0:
                return ComponentHealth(
                    name="normalization_pipeline",
                    status=ComponentStatus.HEALTHY,
                    version="1.0",
                    detail=f"Output file found: {norm_file.name} ({norm_file.stat().st_size} bytes).",
                )
            elif norm_file.exists():
                return ComponentHealth(
                    name="normalization_pipeline",
                    status=ComponentStatus.DEGRADED,
                    version="1.0",
                    detail="Output file exists but is empty.",
                )
            else:
                return ComponentHealth(
                    name="normalization_pipeline",
                    status=ComponentStatus.DEGRADED,
                    version="1.0",
                    detail="No normalized events output file found.",
                )
        except Exception as exc:  # noqa: BLE001
            return ComponentHealth(
                name="normalization_pipeline",
                status=ComponentStatus.UNAVAILABLE,
                detail=f"Health check failed: {exc}",
            )

    def _check_baseline(self, settings: Any, reader: Any) -> ComponentHealth:
        """Check baseline reader operational state."""
        try:
            if reader is not None:
                is_ready = getattr(reader, "is_ready", False)
                profile_id = getattr(reader, "profile_id", None)
                if is_ready:
                    return ComponentHealth(
                        name="baseline_system",
                        status=ComponentStatus.HEALTHY,
                        version=BASELINE_SCHEMA_VERSION,
                        detail=f"Baseline loaded: profile_id={profile_id}.",
                    )
                else:
                    return ComponentHealth(
                        name="baseline_system",
                        status=ComponentStatus.DEGRADED,
                        version=BASELINE_SCHEMA_VERSION,
                        detail="BaselineReader initialised but no profile loaded.",
                    )
            # Check for baseline file system artifacts
            baseline_dir = settings.data_dir / "baseline"
            manifest_file = baseline_dir / "manifest.json"
            if manifest_file.exists():
                return ComponentHealth(
                    name="baseline_system",
                    status=ComponentStatus.DEGRADED,
                    version=BASELINE_SCHEMA_VERSION,
                    detail="Baseline manifest found but reader not active.",
                )
            return ComponentHealth(
                name="baseline_system",
                status=ComponentStatus.DEGRADED,
                version=BASELINE_SCHEMA_VERSION,
                detail="No baseline artifacts found. Run Module 2.1 to build a baseline.",
            )
        except Exception as exc:  # noqa: BLE001
            return ComponentHealth(
                name="baseline_system",
                status=ComponentStatus.UNAVAILABLE,
                detail=f"Health check failed: {exc}",
            )

    def _check_feature_engine(self, settings: Any) -> ComponentHealth:
        """Check if feature engine output exists."""
        try:
            feature_dir = settings.data_dir / "features"
            if not feature_dir.exists():
                return ComponentHealth(
                    name="feature_engine",
                    status=ComponentStatus.DEGRADED,
                    version=FEATURE_SCHEMA_VERSION,
                    detail="No feature output directory found. Run Module 2.2 pipeline.",
                )
            jsonl_files = list(feature_dir.glob("features_*.jsonl"))
            if jsonl_files:
                latest = max(jsonl_files, key=lambda p: p.stat().st_mtime)
                return ComponentHealth(
                    name="feature_engine",
                    status=ComponentStatus.HEALTHY,
                    version=FEATURE_SCHEMA_VERSION,
                    detail=f"Latest output: {latest.name}.",
                )
            return ComponentHealth(
                name="feature_engine",
                status=ComponentStatus.DEGRADED,
                version=FEATURE_SCHEMA_VERSION,
                detail="Feature output directory exists but no JSONL files found.",
            )
        except Exception as exc:  # noqa: BLE001
            return ComponentHealth(
                name="feature_engine",
                status=ComponentStatus.UNAVAILABLE,
                detail=f"Health check failed: {exc}",
            )

    def _enabled_flags(self, settings: Any) -> list[str]:
        """Return names of all enabled feature flags."""
        flag_fields = [f for f in type(settings).model_fields if f.startswith("feature_")]
        return [f for f in flag_fields if getattr(settings, f, False) is True]
