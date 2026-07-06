"""
backend.api.middleware — Custom FastAPI Middleware
=================================================
Provides cross-cutting HTTP concerns as ASGI middleware:

1. RequestIdMiddleware  — Injects a unique UUID into every request and response.
2. LoggingMiddleware    — Logs structured request/response records for every call.

Middleware execution order (outermost first, as registered in app.py):
    RequestIdMiddleware → LoggingMiddleware → [route handler]

This means RequestIdMiddleware runs FIRST (on request) and LAST (on response),
so the request_id is available to all downstream middleware and handlers.

Design Notes
------------
- Middleware must NOT raise exceptions — they must catch and continue.
- All timing is in milliseconds for consistency with metric definitions.
- The request_id is stored in request.state for downstream use.
"""

from __future__ import annotations

import time
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from backend.core.logging import get_logger
from backend.shared.utils.id_utils import generate_id

logger = get_logger(__name__)

# Header names for request ID propagation
REQUEST_ID_HEADER = "X-Request-ID"
RESPONSE_ID_HEADER = "X-Request-ID"


class RequestIdMiddleware(BaseHTTPMiddleware):
    """
    Inject a unique request ID into every HTTP request and response.

    Request ID priority:
    1. Use X-Request-ID header from the client (if present and valid UUID)
    2. Generate a new UUID v4 if none provided

    The ID is stored in:
    - request.state.request_id   (for downstream handlers and logging)
    - X-Request-ID response header (for client-side log correlation)
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Accept client-provided request ID or generate a new one
        client_id = request.headers.get(REQUEST_ID_HEADER)
        request_id = client_id if client_id else generate_id()

        # Attach to request state for downstream access
        request.state.request_id = request_id

        response = await call_next(request)

        # Echo the request ID in the response
        response.headers[RESPONSE_ID_HEADER] = request_id

        return response


class LoggingMiddleware(BaseHTTPMiddleware):
    """
    Log structured request/response records for every HTTP call.

    Emits two log records per request:
    1. 'http_request'  — when the request arrives
    2. 'http_response' — after the response is sent (includes latency)

    Health check endpoints (/health, /ready) are logged at DEBUG level
    to avoid noisy logs in production monitoring.
    """

    # Paths to suppress at INFO level (logged at DEBUG instead)
    _QUIET_PATHS = frozenset({"/health", "/ready", "/metrics"})

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start_time = time.perf_counter()
        request_id = getattr(request.state, "request_id", "")
        path = request.url.path
        method = request.method
        is_quiet = path in self._QUIET_PATHS

        log_fn = logger.debug if is_quiet else logger.info

        log_fn(
            "http_request",
            method=method,
            path=path,
            query=str(request.url.query) or None,
            request_id=request_id,
            client=request.client.host if request.client else "unknown",
        )

        try:
            response = await call_next(request)
        except Exception as exc:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            logger.error(
                "http_request_failed",
                method=method,
                path=path,
                request_id=request_id,
                elapsed_ms=elapsed_ms,
                exc_type=type(exc).__name__,
                exc_message=str(exc),
                exc_info=True,
            )
            raise

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        status_code = response.status_code

        # Log errors at WARNING, slow responses at DEBUG, normal at INFO/DEBUG
        if status_code >= 500:
            logger.error(
                "http_response",
                method=method,
                path=path,
                status_code=status_code,
                elapsed_ms=elapsed_ms,
                request_id=request_id,
            )
        elif status_code >= 400:
            logger.warning(
                "http_response",
                method=method,
                path=path,
                status_code=status_code,
                elapsed_ms=elapsed_ms,
                request_id=request_id,
            )
        else:
            log_fn(
                "http_response",
                method=method,
                path=path,
                status_code=status_code,
                elapsed_ms=elapsed_ms,
                request_id=request_id,
            )

        return response
