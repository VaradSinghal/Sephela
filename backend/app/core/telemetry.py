"""OpenTelemetry tracing instrumentation (Phase 14 observability).

Bootstraps a ``TracerProvider`` with an OTLP span exporter when
``settings.otel_enabled`` is ``True`` and an endpoint is configured.
Otherwise, all instrumentation is a no-op — zero runtime overhead.

Usage::

    from app.core.telemetry import instrument_app
    instrument_app(app)   # call once in create_app()
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.core.config import settings
from app.core.logging import get_logger

if TYPE_CHECKING:
    from fastapi import FastAPI

logger = get_logger(__name__)


def instrument_app(app: FastAPI) -> None:
    """Attach OpenTelemetry instrumentation to the FastAPI application.

    Safe to call even when OTEL packages are not installed — gracefully
    degrades with a warning log.
    """
    if not settings.otel_enabled:
        logger.info("otel_disabled", reason="settings.otel_enabled is False")
        return

    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
            OTLPSpanExporter,
        )
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError:
        logger.warning(
            "otel_import_failed",
            detail="opentelemetry packages not installed; tracing disabled",
        )
        return

    resource = Resource.create(
        {
            "service.name": settings.otel_service_name,
            "service.version": "0.1.0",
            "deployment.environment": settings.env,
        }
    )

    provider = TracerProvider(resource=resource)

    if settings.otel_exporter_endpoint:
        exporter = OTLPSpanExporter(endpoint=settings.otel_exporter_endpoint)
        provider.add_span_processor(BatchSpanProcessor(exporter))
        logger.info(
            "otel_exporter_configured",
            endpoint=settings.otel_exporter_endpoint,
        )

    trace.set_tracer_provider(provider)
    FastAPIInstrumentor.instrument_app(app)

    # Optional instrumentors — import individually so a missing package
    # doesn't block the ones that are installed.
    try:
        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor

        HTTPXClientInstrumentor().instrument()
        logger.debug("otel_httpx_instrumented")
    except ImportError:
        pass

    try:
        from opentelemetry.instrumentation.celery import CeleryInstrumentor

        CeleryInstrumentor().instrument()
        logger.debug("otel_celery_instrumented")
    except ImportError:
        pass

    logger.info("otel_tracing_enabled", service=settings.otel_service_name)
