"""
backend.normalization — Unified Log Collection & Normalization
==============================================================
Module 1.3 — Operation AEGIS, Phase 1

Public API surface for the normalization module.  Import from here
in all application code.  Do not import directly from submodules.

Quick Start
-----------
    from backend.normalization import (
        NormalizationPipeline,
        CanonicalEvent,
        get_parser,
    )
    from backend.digital_twin.registry import get_registry

    registry = get_registry()
    pipeline = NormalizationPipeline(registry)
    report = pipeline.run()

Data Flow
---------
  DigitalTwinRegistry
      │  (source discovery)
      ▼
  TelemetryCollector       ← stream_records() → RawRecord generator
      │
      ▼ (parser dispatch)
  PARSER_REGISTRY[source]  ← one parser per source
      │
      ▼
  CanonicalEvent           ← the single source of truth
      │
      ▼
  NormalizedEventWriter    ← data/normalized/normalized_events.jsonl

Schema Contract
---------------
Every downstream module MUST accept CanonicalEvent.
Never accept RawRecord or raw dicts outside this module.

Extension Contract
------------------
To add a new telemetry source:
  1. Add a parser in backend/normalization/parsers/<source>.py
  2. Register in backend/normalization/parsers/__init__.py
  3. Add tests in tests/unit/normalization/test_<source>_parser.py
  No other files require modification.
"""

from __future__ import annotations

from backend.normalization.collector import TelemetryCollector
from backend.normalization.exceptions import (
    MissingFieldError,
    NormalizationError,
    ParseError,
    SchemaValidationError,
    SourceError,
)
from backend.normalization.models import (
    CanonicalEvent,
    ParseReport,
    ParseStats,
    RawRecord,
)
from backend.normalization.parsers import (
    BaseParser,
    get_parser,
    list_registered_sources,
)
from backend.normalization.pipeline import NormalizationPipeline
from backend.normalization.writer import NormalizedEventWriter

__all__ = [
    # Core pipeline
    "NormalizationPipeline",
    "TelemetryCollector",
    "NormalizedEventWriter",
    # Models
    "CanonicalEvent",
    "RawRecord",
    "ParseStats",
    "ParseReport",
    # Parsers
    "BaseParser",
    "get_parser",
    "list_registered_sources",
    # Exceptions
    "NormalizationError",
    "ParseError",
    "SchemaValidationError",
    "SourceError",
    "MissingFieldError",
]

