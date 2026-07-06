"""
backend.api.dependencies — FastAPI Dependency Injection
=======================================================
Provides reusable FastAPI dependencies that are injected into route handlers.

All shared resources (settings, DB sessions, authenticated user) flow
through this module via FastAPI's Depends() mechanism.  This keeps route
handlers thin and testable.

Usage
-----
    from fastapi import APIRouter, Depends
    from backend.api.dependencies import get_settings_dep, get_request_id

    router = APIRouter()

    @router.get("/example")
    async def example(
        settings: Settings = Depends(get_settings_dep),
        request_id: str = Depends(get_request_id),
    ) -> dict:
        ...
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from backend.core.config import Settings, get_settings
from backend.core.constants import HTTP_401_UNAUTHORIZED
from backend.core.logging import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Settings Dependency
# ---------------------------------------------------------------------------


def get_settings_dep() -> Settings:
    """
    FastAPI dependency: inject the application Settings singleton.

    Usage:
        @router.get("/example")
        async def route(settings: Settings = Depends(get_settings_dep)):
            ...
    """
    return get_settings()


SettingsDep = Annotated[Settings, Depends(get_settings_dep)]


# ---------------------------------------------------------------------------
# Request ID Dependency
# ---------------------------------------------------------------------------


def get_request_id(request: Request) -> str:
    """
    FastAPI dependency: extract the request ID injected by RequestIdMiddleware.

    Returns an empty string if the middleware has not run (e.g., in unit tests).
    """
    return getattr(request.state, "request_id", "")


RequestIdDep = Annotated[str, Depends(get_request_id)]


# ---------------------------------------------------------------------------
# API Key Authentication
# ---------------------------------------------------------------------------
_bearer_scheme = HTTPBearer(auto_error=False)


def verify_api_key(
    credentials: HTTPAuthorizationCredentials | None = Security(_bearer_scheme),
    settings: Settings = Depends(get_settings_dep),
) -> str:
    """
    FastAPI security dependency: validate Bearer API key.

    In development mode, accepts any key or no key.
    In production, requires a valid bearer token matching API_KEY env var.

    Returns
    -------
    str
        The validated API key.

    Raises
    ------
    HTTPException
        401 if no credentials provided in production.
        403 if credentials are invalid.
    """
    if settings.is_development:
        # Bypass auth in development for developer convenience
        return "dev-bypass"

    if credentials is None:
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED,
            detail="Missing API key. Provide a Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    expected_key = settings.api_key.get_secret_value()
    if credentials.credentials != expected_key:
        logger.warning(
            "invalid_api_key_attempt",
            provided_prefix=credentials.credentials[:8] + "...",
        )
        raise HTTPException(
            status_code=403,
            detail="Invalid API key.",
        )

    return credentials.credentials


ApiKeyDep = Annotated[str, Security(verify_api_key)]
