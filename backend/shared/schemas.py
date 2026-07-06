"""
backend.shared.schemas — Shared API Request/Response Schemas
============================================================
Common Pydantic schemas used across multiple API endpoints.

Module-specific schemas (e.g., alert ingestion, LLM enrichment) are
defined in their respective modules.  Only genuinely cross-cutting schemas
belong here.

Usage
-----
    from backend.shared.schemas import (
        SuccessResponse,
        ErrorResponse,
        PaginatedResponse,
    )
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Generic, TypeVar

from pydantic import Field

from backend.shared.models import CyberShieldBaseModel
from backend.shared.utils.id_utils import generate_id

T = TypeVar("T")


# ---------------------------------------------------------------------------
# Standard Response Wrappers
# ---------------------------------------------------------------------------
class SuccessResponse(CyberShieldBaseModel):
    """
    Generic success response for operations that do not return data.

    Use for: action approvals, deletions, confirmations.
    """

    success: bool = Field(default=True)
    message: str = Field(description="Human-readable success message.")
    request_id: str | None = Field(
        default=None,
        description="Echo of the HTTP request ID for log correlation.",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
    )


class ErrorResponse(CyberShieldBaseModel):
    """
    Structured error response body for all API errors.

    Returned by the global exception handler for all CyberShieldError subtypes.
    """

    success: bool = Field(default=False)
    error_code: str = Field(description="Machine-readable error code (snake_case).")
    message: str = Field(description="Human-readable error description.")
    detail: dict[str, Any] | None = Field(
        default=None,
        description="Optional structured context about the error.",
    )
    request_id: str | None = Field(
        default=None,
        description="HTTP request ID for log correlation.",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
    )


class PaginatedResponse(CyberShieldBaseModel, Generic[T]):
    """
    Generic paginated response wrapper.

    Use for: alert lists, audit log queries, action queue listings.

    Example
    -------
        return PaginatedResponse[AlertSummary](
            items=alerts,
            total=total_count,
            page=page,
            page_size=page_size,
        )
    """

    items: list[T] = Field(description="The current page of results.")
    total: int = Field(ge=0, description="Total number of matching records.")
    page: int = Field(ge=1, description="Current page number (1-indexed).")
    page_size: int = Field(ge=1, le=1000, description="Number of items per page.")
    has_next: bool = Field(description="True if there are more pages after this one.")
    has_prev: bool = Field(description="True if there are pages before this one.")

    @classmethod
    def from_items(
        cls,
        items: list[T],
        total: int,
        page: int,
        page_size: int,
    ) -> "PaginatedResponse[T]":
        """Factory method for constructing paginated responses."""
        return cls(
            items=items,
            total=total,
            page=page,
            page_size=page_size,
            has_next=(page * page_size) < total,
            has_prev=page > 1,
        )


# ---------------------------------------------------------------------------
# Version Schema
# ---------------------------------------------------------------------------
class VersionInfo(CyberShieldBaseModel):
    """
    Application version information.

    Returned by GET /version.
    """

    name: str = Field(description="Application name.")
    version: str = Field(description="Semantic version string.")
    module: str = Field(description="Currently active module name.")
    environment: str = Field(description="Deployment environment.")
    build_timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Timestamp of this server instance startup.",
    )


# ---------------------------------------------------------------------------
# Pagination Query Parameters (shared dependency)
# ---------------------------------------------------------------------------
class PaginationParams(CyberShieldBaseModel):
    """
    Standard pagination query parameters.

    Use as a FastAPI dependency:
        from fastapi import Depends
        from backend.shared.schemas import PaginationParams

        @router.get("/alerts")
        async def list_alerts(pagination: PaginationParams = Depends()):
            ...
    """

    page: int = Field(default=1, ge=1, description="Page number (1-indexed).")
    page_size: int = Field(
        default=50,
        ge=1,
        le=1000,
        description="Items per page (max 1000).",
    )

    @property
    def offset(self) -> int:
        """Database query offset for the current page."""
        return (self.page - 1) * self.page_size

    @property
    def limit(self) -> int:
        """Database query limit."""
        return self.page_size
