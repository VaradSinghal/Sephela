"""Prometheus-compatible RED metrics (Rate, Errors, Duration).

Adds a Starlette middleware that records HTTP request metrics and exposes
a ``/metrics`` endpoint for Prometheus scraping. Disabled by default —
enable via ``SEPHELA_METRICS_ENABLED=true``.

Standard metrics emitted:

- ``http_requests_total``           — counter by method, path, status
- ``http_request_duration_seconds`` — histogram by method, path
- ``http_request_errors_total``     — counter for 4xx/5xx by method, path

Queue-depth and worker metrics are left to the Celery/Flower integration
or a scheduled task that publishes gauges; this module covers the API
surface only.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from app.core.config import settings
from app.core.logging import get_logger

if TYPE_CHECKING:
    from fastapi import FastAPI

logger = get_logger(__name__)

# Lazy-loaded prometheus_client references.  Set in ``setup_metrics()``.
_REQUEST_COUNT = None
_REQUEST_DURATION = None
_ERROR_COUNT = None


def setup_metrics(app: FastAPI) -> None:
    """Register the metrics middleware and ``/metrics`` endpoint.

    Safe to call when ``prometheus_client`` is not installed — logs a
    warning and returns.
    """
    global _REQUEST_COUNT, _REQUEST_DURATION, _ERROR_COUNT  # noqa: PLW0603

    if not settings.metrics_enabled:
        logger.info("metrics_disabled")
        return

    try:
        from prometheus_client import Counter, Histogram, generate_latest
        from starlette.responses import Response as StarletteResponse
    except ImportError:
        logger.warning(
            "metrics_import_failed",
            detail="prometheus_client not installed; metrics disabled",
        )
        return

    _REQUEST_COUNT = Counter(
        "http_requests_total",
        "Total HTTP requests",
        ["method", "path", "status"],
    )
    _REQUEST_DURATION = Histogram(
        "http_request_duration_seconds",
        "HTTP request duration in seconds",
        ["method", "path"],
        buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
    )
    _ERROR_COUNT = Counter(
        "http_request_errors_total",
        "Total HTTP error responses (4xx + 5xx)",
        ["method", "path", "status"],
    )

    app.add_middleware(MetricsMiddleware)

    @app.get("/metrics", include_in_schema=False)
    async def metrics_endpoint() -> StarletteResponse:
        body = generate_latest()
        return StarletteResponse(
            content=body,
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    logger.info("metrics_enabled")


def _normalize_path(path: str) -> str:
    """Collapse UUID/int path params to reduce cardinality.

    ``/api/v1/jobs/abc-123/stages`` → ``/api/v1/jobs/{id}/stages``
    """
    parts = path.strip("/").split("/")
    normalized: list[str] = []
    for part in parts:
        # UUID-shaped or numeric → placeholder
        if len(part) == 36 and part.count("-") == 4:
            normalized.append("{id}")
        elif part.isdigit():
            normalized.append("{id}")
        else:
            normalized.append(part)
    return "/" + "/".join(normalized)


class MetricsMiddleware(BaseHTTPMiddleware):
    """Record RED metrics for every HTTP request."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        if _REQUEST_COUNT is None:
            return await call_next(request)

        method = request.method
        path = _normalize_path(request.url.path)
        start = time.perf_counter()

        response = await call_next(request)

        elapsed = time.perf_counter() - start
        status = str(response.status_code)

        _REQUEST_COUNT.labels(method=method, path=path, status=status).inc()
        _REQUEST_DURATION.labels(method=method, path=path).observe(elapsed)

        if response.status_code >= 400:
            _ERROR_COUNT.labels(method=method, path=path, status=status).inc()

        return response
