"""Health endpoints: liveness, readiness, dependency detail."""

from __future__ import annotations

from fastapi import APIRouter
from sqlalchemy import text

from app.core.redis import redis_client
from app.db.session import engine
from app.schemas.common import DependencyStatus, HealthStatus, ReadinessResponse

router = APIRouter(prefix="/health", tags=["health"])


@router.get("/live", response_model=HealthStatus)
async def liveness() -> HealthStatus:
    """Process is up. No dependency checks (used by k8s livenessProbe)."""
    return HealthStatus(status="ok")


async def _check_db() -> DependencyStatus:
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return DependencyStatus(name="postgres", healthy=True)
    except Exception as exc:  # noqa: BLE001
        return DependencyStatus(name="postgres", healthy=False, detail=str(exc))


async def _check_redis() -> DependencyStatus:
    try:
        await redis_client.ping()
        return DependencyStatus(name="redis", healthy=True)
    except Exception as exc:  # noqa: BLE001
        return DependencyStatus(name="redis", healthy=False, detail=str(exc))


@router.get("/ready", response_model=ReadinessResponse)
async def readiness() -> ReadinessResponse:
    """All critical dependencies reachable (used by k8s readinessProbe)."""
    deps = [await _check_db(), await _check_redis()]
    ok = all(d.healthy for d in deps)
    return ReadinessResponse(status="ok" if ok else "degraded", dependencies=deps)
