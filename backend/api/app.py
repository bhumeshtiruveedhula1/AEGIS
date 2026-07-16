"""
backend.api.app — FastAPI Application Factory
=============================================
Creates and configures the FastAPI application instance.

Uses the application factory pattern (create_app()) to allow:
  - Easy testing with different settings
  - Clean startup/shutdown lifecycle via lifespan
  - Deferred module registration as features are enabled

Usage
-----
    # Start with uvicorn (via Makefile):
    uvicorn backend.api.app:create_app --factory --reload

    # In tests:
    from fastapi.testclient import TestClient
    from backend.api.app import create_app

    client = TestClient(create_app())

Startup Sequence
----------------
1. Load settings from env
2. Configure structured logging
3. Register global exception handlers
4. Register middleware (CORS, request-ID, logging)
5. Mount versioned API routes (currently: health only)
6. Future modules register their routers when feature flags are enabled
"""

from __future__ import annotations

import pathlib
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from backend.api.middleware import (
    LoggingMiddleware,
    RequestIdMiddleware,
)
from backend.api.routes import dashboard as dashboard_router, health as health_router
from backend.core.config import Settings, get_settings
from backend.core.constants import API_PREFIX, APP_DESCRIPTION, APP_NAME, APP_VERSION
from backend.core.exceptions import CyberShieldError
from backend.core.logging import configure_logging, get_logger

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

logger = get_logger(__name__)


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    """
    Application lifespan handler (startup + shutdown).

    Runs synchronous setup before the server starts accepting requests,
    and teardown after the last request is served.

    Future modules hook in here:
        - Load trained models into memory
        - Establish DB connection pools
        - Warm up LLM client
        - Register Prometheus metrics
    """
    settings: Settings = app.state.settings
    log = get_logger(__name__)

    # --- Startup ---
    log.info(
        "cybershield_starting",
        version=APP_VERSION,
        environment=settings.app_env,
        log_level=settings.log_level,
        database_url=settings.database_url if settings.is_development else "[redacted]",
    )

    # Future: initialise DB engine, load ML models, etc.
    # Example:
    #   if settings.feature_detection_enabled:
    #       app.state.anomaly_detector = await load_isolation_forest(settings)

    log.info("cybershield_started", module="foundation", status="ready")

    yield  # ← server runs here

    # --- Shutdown ---
    log.info("cybershield_stopping")
    # Future: close DB connections, flush buffers, etc.
    log.info("cybershield_stopped")


def _register_exception_handlers(app: FastAPI) -> None:
    """Register global exception handlers for the application."""

    @app.exception_handler(CyberShieldError)
    async def cybershield_error_handler(
        request: Request,
        exc: CyberShieldError,
    ) -> JSONResponse:
        """Handle all CyberShieldError subclasses with structured JSON responses."""
        request_id = getattr(request.state, "request_id", None)
        log = get_logger(__name__)
        log.warning(
            "cybershield_error",
            error_code=exc.error_code,
            message=exc.message,
            context=exc.context,
            request_id=request_id,
            path=str(request.url.path),
        )
        return JSONResponse(
            status_code=exc.http_status_code,
            content={
                "success": False,
                "error_code": exc.error_code,
                "message": exc.message,
                "detail": exc.context if exc.context else None,
                "request_id": request_id,
            },
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(
        request: Request,
        exc: Exception,
    ) -> JSONResponse:
        """Catch-all for unhandled exceptions. Never exposes internal details."""
        request_id = getattr(request.state, "request_id", None)
        log = get_logger(__name__)
        log.error(
            "unhandled_exception",
            exc_type=type(exc).__name__,
            exc_message=str(exc),
            request_id=request_id,
            path=str(request.url.path),
            exc_info=True,
        )
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "error_code": "internal_server_error",
                "message": "An unexpected error occurred. See logs for details.",
                "request_id": request_id,
            },
        )


def _register_routers(app: FastAPI, _settings: Settings) -> None:
    """
    Mount all API routers.

    Foundation (always active):
    - /health, /ready, /version

    Future modules (controlled by feature flags):
    - /api/v1/alerts        → ingestion module
    - /api/v1/anomalies     → detection module
    - /api/v1/attack_chains → graph module
    - /api/v1/enrich        → llm module
    - /api/v1/actions       → response module
    - /api/v1/metrics       → dashboard module
    """
    # Foundation routes — always registered
    app.include_router(health_router.router, tags=["Health"])

    # Dashboard routes — Module 7.1
    app.include_router(
        dashboard_router.router,
        prefix=f"{API_PREFIX}/dashboard",
        tags=["Dashboard"],
    )

    # Future module router registration pattern:
    # if settings.feature_ingestion_enabled:
    #     from backend.api.routes import ingestion as ingestion_router
    #     app.include_router(
    #         ingestion_router.router,
    #         prefix=f"{API_PREFIX}/alerts",
    #         tags=["Ingestion"],
    #     )


def create_app(settings: Settings | None = None) -> FastAPI:
    """
    Application factory: creates and fully configures a FastAPI instance.

    Parameters
    ----------
    settings:
        Optional Settings override. If None, loads from environment.
        Pass custom settings in tests to override config.

    Returns
    -------
    FastAPI
        Fully configured application ready to serve requests.
    """
    resolved_settings = settings or get_settings()

    # Configure logging before anything else
    configure_logging(
        level=resolved_settings.log_level,
        format=resolved_settings.log_format,
    )

    app = FastAPI(
        title=APP_NAME,
        description=APP_DESCRIPTION,
        version=APP_VERSION,
        docs_url="/docs" if resolved_settings.is_development else None,
        redoc_url="/redoc" if resolved_settings.is_development else None,
        openapi_url="/openapi.json" if resolved_settings.is_development else None,
        lifespan=_lifespan,
    )

    # Attach settings to app state for access in lifespan and dependencies
    app.state.settings = resolved_settings

    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=resolved_settings.cors_allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Custom middleware (order matters — outermost first)
    app.add_middleware(LoggingMiddleware)
    app.add_middleware(RequestIdMiddleware)

    # Exception handlers
    _register_exception_handlers(app)

    # API routers
    _register_routers(app, resolved_settings)

    # Static files — serve frontend dashboard
    # frontend/ lives at the project root (sibling of backend/)
    _project_root = pathlib.Path(__file__).parent.parent.parent
    _frontend_dir = _project_root / "frontend"
    _static_dir   = _frontend_dir / "static"

    if _static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")

    if _frontend_dir.exists():

        @app.get("/", include_in_schema=False, response_class=HTMLResponse)
        async def serve_dashboard() -> HTMLResponse:
            """Serve the operational dashboard single-page app."""
            html_path = _frontend_dir / "index.html"
            if html_path.exists():
                return HTMLResponse(content=html_path.read_text(encoding="utf-8"))
            return HTMLResponse(content="<h1>Dashboard not found</h1>", status_code=404)

    return app
