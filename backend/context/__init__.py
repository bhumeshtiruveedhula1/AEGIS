"""backend.context — Attack Context Generation Module (Module 4.1)."""

from backend.context.builder import AttackContextBuilder
from backend.context.exceptions import (
    ContextBuildError,
    ContextError,
    ContextSchemaError,
    ContextStorageError,
    InsufficientInputError,
)
from backend.context.models import (
    CONTEXT_SCHEMA_VERSION,
    AttackContext,
    BehavioralSummary,
    ChainSummary,
    ContextCompleteness,
    ContextIdentity,
    DetectionSummary,
    FeatureSummaryItem,
    GraphSummary,
    MissingComponent,
    MitreSummary,
    ShapSummary,
    StatisticalSummary,
    SupportingEvidence,
    TechniqueSummary,
    TimelineEvent,
)
from backend.context.service import AttackContextService
from backend.context.storage import ContextStore
from backend.context.summarizer import (
    BehavioralSummarizer,
    ChainSummarizer,
    CompletenessSummarizer,
    DetectionSummarizer,
    EvidenceSummarizer,
    GraphSummarizer,
    MitreSummarizer,
    ShapSummarizer,
    StatisticalSummarizer,
)
from backend.context.timeline import TimelineBuilder

__all__ = [
    # Service (primary entry point)
    "AttackContextService",
    # Builder
    "AttackContextBuilder",
    # Timeline
    "TimelineBuilder",
    # Summarizers
    "DetectionSummarizer",
    "ShapSummarizer",
    "MitreSummarizer",
    "GraphSummarizer",
    "ChainSummarizer",
    "EvidenceSummarizer",
    "BehavioralSummarizer",
    "StatisticalSummarizer",
    "CompletenessSummarizer",
    # Storage
    "ContextStore",
    # Models
    "AttackContext",
    "ContextIdentity",
    "DetectionSummary",
    "ShapSummary",
    "FeatureSummaryItem",
    "MitreSummary",
    "TechniqueSummary",
    "GraphSummary",
    "ChainSummary",
    "TimelineEvent",
    "SupportingEvidence",
    "BehavioralSummary",
    "StatisticalSummary",
    "ContextCompleteness",
    "MissingComponent",
    "CONTEXT_SCHEMA_VERSION",
    # Exceptions
    "ContextError",
    "ContextBuildError",
    "ContextStorageError",
    "ContextSchemaError",
    "InsufficientInputError",
]
