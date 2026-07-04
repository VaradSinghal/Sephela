"""FastAPI application entrypoint (API Gateway / Core Service)."""

from __future__ import annotations

from contextlib import asynccontextmanager
from collections.abc import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.router import api_router
from app.core.config import settings
from app.core.exceptions import register_exception_handlers
from app.core.logging import configure_logging, get_logger
from app.core.middleware import TraceMiddleware
from app.core.redis import redis_client
from app.db.session import engine

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    configure_logging()
    logger.info("startup", env=settings.env, project=settings.project_name)
    yield
    await engine.dispose()
    await redis_client.aclose()
    logger.info("shutdown")


def create_app() -> FastAPI:
    configure_logging()
    app = FastAPI(
        title=settings.project_name,
        version="0.1.0",
        docs_url="/docs" if not settings.is_prod else None,
        redoc_url=None,
        openapi_url=f"{settings.api_v1_prefix}/openapi.json",
        lifespan=lifespan,
    )

    app.add_middleware(TraceMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    register_exception_handlers(app)
    app.include_router(api_router, prefix=settings.api_v1_prefix)
    return app


app = create_app()
