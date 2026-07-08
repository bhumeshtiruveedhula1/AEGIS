"""
backend.metrics.collectors — Metric Collector Registry & Base Class
====================================================================
Module 2.3 — Metrics Collection & Evaluation Engine

This package defines:
  - BaseCollector    — abstract base class for all metric collectors
  - COLLECTOR_REGISTRY — ordered dict of registered collector classes
  - get_all_collectors() — factory producing live collector instances

Design
------
Every collector is responsible for exactly one MetricDomain.
Collectors are stateless — they receive data at collection time and
return populated domain metric models. No caching, no side effects.

Isolation contract: one collector failure MUST NOT abort collection
for other domains. The service wraps each call in a safe_collect().

Extension
---------
To add a new collector:
  1. Subclass BaseCollector
  2. Implement domain, name, collect()
  3. Register with @register_collector

The registry is ordered — collectors run in registration order.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections import OrderedDict
from typing import TYPE_CHECKING, Any, Callable, Type

import structlog

from backend.metrics.models import MetricDomain

if TYPE_CHECKING:
    from backend.metrics.models import (
        BaselineMetrics,
        DetectionMetrics,
        FeatureMetrics,
        PipelineMetrics,
        PlatformHealthMetrics,
        ResponseMetrics,
    )

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Collector type alias
# ---------------------------------------------------------------------------

# Each domain model is a Pydantic model — typed at domain level
DomainMetrics = Any  # resolved at runtime


# ---------------------------------------------------------------------------
# BaseCollector — abstract interface every collector must implement
# ---------------------------------------------------------------------------

class BaseCollector(ABC):
    """
    Abstract base class for all metric collectors.

    A collector owns one metric domain and implements collect() which:
    - Accepts input data as keyword arguments
    - Returns a fully populated domain Pydantic model
    - Never raises — wraps all failures in MetricValue.insufficient()

    The `safe_collect()` wrapper provides an additional exception barrier
    at the service level.
    """

    @property
    @abstractmethod
    def domain(self) -> MetricDomain:
        """The MetricDomain this collector populates."""
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        """
        Human-readable collector name for logs and diagnostics.
        Must be unique within the registry.
        """
        ...

    @abstractmethod
    def collect(self, **kwargs: Any) -> DomainMetrics:
        """
        Compute and return the domain metric model.

        Parameters are domain-specific and passed as keyword arguments by
        MetricService. Collectors should gracefully handle missing kwargs
        by returning MetricValue.insufficient() for affected fields.

        Returns
        -------
        A populated domain Pydantic model (e.g. PipelineMetrics).
        Must NEVER raise. Use MetricValue.insufficient() for failures.
        """
        ...

    def safe_collect(self, **kwargs: Any) -> DomainMetrics | None:
        """
        Collect metrics with a top-level exception barrier.

        Returns the domain model on success, None on unrecoverable failure.
        All errors are logged; no exception propagates.
        """
        try:
            return self.collect(**kwargs)
        except Exception:  # noqa: BLE001
            logger.exception(
                "metric_collector_failed",
                collector=self.name,
                domain=self.domain.value,
            )
            return None


# ---------------------------------------------------------------------------
# Collector Registry
# ---------------------------------------------------------------------------

_REGISTRY: OrderedDict[str, Type[BaseCollector]] = OrderedDict()


def register_collector(cls: Type[BaseCollector]) -> Type[BaseCollector]:
    """
    Class decorator to register a collector in the global registry.

    Usage
    -----
    @register_collector
    class PipelineCollector(BaseCollector):
        ...
    """
    instance = cls()
    name = instance.name
    if name in _REGISTRY:
        from backend.metrics.exceptions import MetricRegistryError
        msg = f"Duplicate collector name registered: {name!r}"
        raise MetricRegistryError(msg)
    _REGISTRY[name] = cls
    logger.debug("metric_collector_registered", name=name, domain=instance.domain.value)
    return cls


def get_all_collectors() -> list[BaseCollector]:
    """
    Return one live instance of every registered collector, in registry order.

    Instances are created fresh on each call — collectors are stateless.
    """
    return [cls() for cls in _REGISTRY.values()]


def get_collector_names() -> list[str]:
    """Return the names of all registered collectors."""
    return list(_REGISTRY.keys())


# ---------------------------------------------------------------------------
# Auto-import all collector modules to trigger @register_collector decorators
# ---------------------------------------------------------------------------
# Collectors are registered via the @register_collector class decorator.
# Without importing the module, the decorator never fires and the registry
# stays empty. This block eagerly imports each collector module so that
# all collectors are registered when `from backend.metrics.collectors import ...`
# is used anywhere.

def _bootstrap() -> None:
    """Import all collector sub-modules to populate the registry."""
    import importlib
    _MODULES = [
        "backend.metrics.collectors.pipeline",
        "backend.metrics.collectors.baseline",
        "backend.metrics.collectors.feature",
        "backend.metrics.collectors.detection",
        "backend.metrics.collectors.response",
        "backend.metrics.collectors.health",
    ]
    for module_path in _MODULES:
        try:
            importlib.import_module(module_path)
        except Exception as exc:
            import logging
            logging.getLogger(__name__).warning(
                "Failed to import collector module %s: %s", module_path, exc
            )


_bootstrap()

