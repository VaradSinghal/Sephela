"""Central exception hierarchy + RFC 9457 Problem Details handlers.

Domain code raises ``AppError`` subclasses; the API layer maps them to
``application/problem+json`` responses. Never leak internals in prod.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.logging import get_logger

logger = get_logger(__name__)

PROBLEM_CONTENT_TYPE = "application/problem+json"


class AppError(Exception):
    """Base application error mapped to a Problem Details response."""

    status_code: int = 500
    title: str = "Internal Server Error"
    error_type: str = "about:blank"

    def __init__(self, detail: str | None = None, **extra: Any) -> None:
        self.detail = detail or self.title
        self.extra = extra
        super().__init__(self.detail)


class NotFoundError(AppError):
    status_code = 404
    title = "Resource Not Found"
    error_type = "https://sephela.dev/errors/not-found"


class ValidationAppError(AppError):
    status_code = 422
    title = "Validation Error"
    error_type = "https://sephela.dev/errors/validation"


class ConflictError(AppError):
    status_code = 409
    title = "Conflict"
    error_type = "https://sephela.dev/errors/conflict"


class UnauthorizedError(AppError):
    status_code = 401
    title = "Unauthorized"
    error_type = "https://sephela.dev/errors/unauthorized"


class ForbiddenError(AppError):
    status_code = 403
    title = "Forbidden"
    error_type = "https://sephela.dev/errors/forbidden"


# ---------------------------------------------------------------------------
# Transient vs Permanent — used by retry logic in tasks/pipeline
# ---------------------------------------------------------------------------


class TransientError(AppError):
    """Retriable error — the operation may succeed on retry.

    Use for: network timeouts, temporary unavailability, rate limits,
    database connection issues, etc.
    """

    status_code = 503
    title = "Service Temporarily Unavailable"
    error_type = "https://sephela.dev/errors/transient"
    is_retryable: bool = True


class PermanentError(AppError):
    """Non-retriable error — retrying will not change the outcome.

    Use for: invalid configuration, malformed input, missing required
    resources, logic errors, etc.
    """

    status_code = 500
    title = "Permanent Error"
    error_type = "https://sephela.dev/errors/permanent"
    is_retryable: bool = False


class EngineError(TransientError):
    """An analysis engine failed during execution."""

    title = "Engine Error"
    error_type = "https://sephela.dev/errors/engine"


class ExternalServiceError(TransientError):
    """An external service (threat-intel feed, sandbox API) is unavailable."""

    title = "External Service Error"
    error_type = "https://sephela.dev/errors/external-service"


class RateLimitError(TransientError):
    """An external API rate limit was hit."""

    status_code = 429
    title = "Rate Limited"
    error_type = "https://sephela.dev/errors/rate-limit"


class ExternalTimeoutError(TransientError):
    """An external call timed out."""

    status_code = 504
    title = "Gateway Timeout"
    error_type = "https://sephela.dev/errors/timeout"


class ConfigurationError(PermanentError):
    """Invalid or missing configuration — cannot proceed."""

    title = "Configuration Error"
    error_type = "https://sephela.dev/errors/configuration"


def _problem(
    *, status: int, title: str, detail: str, error_type: str, request: Request, **extra: Any
) -> JSONResponse:
    trace_id = getattr(request.state, "trace_id", None)
    body: dict[str, Any] = {
        "type": error_type,
        "title": title,
        "status": status,
        "detail": detail,
        "instance": str(request.url.path),
        "trace_id": trace_id,
    }
    body.update(extra)
    return JSONResponse(status_code=status, content=body, media_type=PROBLEM_CONTENT_TYPE)


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def _app_error(request: Request, exc: AppError) -> JSONResponse:
        logger.warning("app_error", type=exc.error_type, detail=exc.detail)
        return _problem(
            status=exc.status_code,
            title=exc.title,
            detail=exc.detail,
            error_type=exc.error_type,
            request=request,
            **exc.extra,
        )

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        return _problem(
            status=422,
            title="Validation Error",
            detail="Request validation failed.",
            error_type="https://sephela.dev/errors/validation",
            request=request,
            errors=exc.errors(),
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        return _problem(
            status=exc.status_code,
            title=str(exc.detail),
            detail=str(exc.detail),
            error_type="about:blank",
            request=request,
        )

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("unhandled_error")
        return _problem(
            status=500,
            title="Internal Server Error",
            detail="An unexpected error occurred.",
            error_type="about:blank",
            request=request,
        )
