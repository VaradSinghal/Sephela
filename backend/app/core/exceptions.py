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
