"""Per-principal request rate limiting (Phase 14).

Implements a fixed-window counter in Redis. The window is deliberately simple: the
purpose here is DoS protection and cost control (an upload triggers minutes of
sandbox and LLM work), not fair-share scheduling. A sliding-log or token bucket
would smooth the boundary burst — at 2× the configured rate for one window
straddle — at the cost of more Redis round-trips per request. If that burst starts
mattering, the place to change it is ``_window_key``/``check``, not the callers.

Two properties matter more than the algorithm:

- **Keyed on the authenticated principal where possible.** Keying on IP alone
  punishes every analyst behind one bank's NAT gateway as if they were one client.
  The token's subject is used when present, falling back to client IP for
  unauthenticated routes (login, which is exactly where IP-keying belongs).
- **Fails open.** If Redis is unreachable the request proceeds. A rate limiter that
  takes the API down when its own dependency blips has converted a availability
  safeguard into an outage; the correct posture for a *protective* control is to
  log loudly and let traffic through.
"""

from __future__ import annotations

from dataclasses import dataclass

from redis.asyncio import Redis
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.core.config import settings
from app.core.logging import get_logger
from app.core.redis import redis_client
from app.core.security import decode_token

logger = get_logger(__name__)

# Paths exempt from limiting: probes are called continuously by the orchestrator and
# metrics scraping is internal. Rate-limiting a liveness probe gets pods killed.
_EXEMPT_SUFFIXES = ("/health/live", "/health/ready", "/health", "/metrics")


@dataclass(frozen=True)
class Budget:
    """One bucket's allowance."""

    requests: int
    window_seconds: int
    name: str


def _budget_for(path: str) -> Budget:
    """Pick the bucket a path draws from.

    Uploads get their own, tighter budget: one upload costs orders of magnitude more
    than a status poll, so a shared counter would let a client spend the whole
    allowance on the expensive endpoint.
    """
    if path.endswith("/uploads"):
        return Budget(
            settings.rate_limit_upload_requests,
            settings.rate_limit_upload_window_seconds,
            "upload",
        )
    return Budget(settings.rate_limit_requests, settings.rate_limit_window_seconds, "default")


def principal_key(request: Request) -> str:
    """Identify the caller for limiting purposes.

    The token's signature is verified before its subject is trusted — an unverified
    `sub` would let a client pick its own bucket (or someone else's) by editing a
    claim. An unparseable or absent token falls back to the peer address.
    """
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        try:
            claims = decode_token(auth.split(" ", 1)[1].strip())
            subject = claims.get("sub")
            if subject:
                return f"user:{subject}"
        except Exception:  # noqa: BLE001 — invalid token: fall through to IP
            pass
    client = request.client
    return f"ip:{client.host if client else 'unknown'}"


class RateLimiter:
    """Fixed-window counter backed by Redis."""

    def __init__(self, redis: Redis | None = None) -> None:
        self._redis = redis if redis is not None else redis_client

    async def check(self, key: str, budget: Budget) -> tuple[bool, int, int]:
        """Consume one unit from *key*'s budget.

        Returns:
            ``(allowed, remaining, retry_after_seconds)``. On a Redis failure this
            returns ``(True, budget.requests, 0)`` — see the module docstring on
            failing open.
        """
        redis_key = f"ratelimit:{budget.name}:{key}"
        try:
            pipe = self._redis.pipeline()
            pipe.incr(redis_key)
            # Only the first increment in a window sets the TTL, so the window is
            # anchored to the first request rather than sliding forward on each one
            # (which would never let the counter reset under sustained traffic).
            pipe.ttl(redis_key)
            count, ttl = await pipe.execute()
            count = int(count)
            ttl = int(ttl)

            if ttl < 0:
                await self._redis.expire(redis_key, budget.window_seconds)
                ttl = budget.window_seconds

            remaining = max(0, budget.requests - count)
            return count <= budget.requests, remaining, ttl
        except Exception:  # noqa: BLE001
            logger.warning("rate_limit_unavailable", key=redis_key, exc_info=True)
            return True, budget.requests, 0


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Enforce per-principal budgets and advertise them in response headers."""

    def __init__(self, app: object, limiter: RateLimiter | None = None) -> None:
        super().__init__(app)  # type: ignore[arg-type]
        self.limiter = limiter or RateLimiter()

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        path = request.url.path
        if not settings.rate_limit_enabled or path.endswith(_EXEMPT_SUFFIXES):
            return await call_next(request)

        budget = _budget_for(path)
        allowed, remaining, retry_after = await self.limiter.check(principal_key(request), budget)

        if not allowed:
            logger.warning("rate_limited", path=path, budget=budget.name, retry_after=retry_after)
            # RFC 9457 problem shape, matching app.core.exceptions handlers so
            # clients parse one error format for the whole API.
            return JSONResponse(
                status_code=429,
                content={
                    "type": "https://sephela.dev/errors/rate-limit",
                    "title": "Too Many Requests",
                    "status": 429,
                    "detail": (
                        f"Rate limit of {budget.requests} requests per "
                        f"{budget.window_seconds}s exceeded."
                    ),
                    "instance": path,
                },
                headers={
                    "Retry-After": str(max(1, retry_after)),
                    "X-RateLimit-Limit": str(budget.requests),
                    "X-RateLimit-Remaining": "0",
                },
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(budget.requests)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        return response
