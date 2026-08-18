"""Tests for per-principal rate limiting.

The two properties worth pinning are the ones that make a rate limiter either
useless or actively harmful: keying (a limiter that buckets an entire bank's NAT
gateway as one client, or that lets a client choose its own bucket) and failure
behaviour (a limiter that takes the API down when Redis blips has turned a
protective control into an outage).
"""

from __future__ import annotations

from typing import Any

import pytest
from starlette.datastructures import Headers
from starlette.requests import Request

from app.core.config import settings
from app.core.ratelimit import Budget, RateLimiter, _budget_for, principal_key
from app.core.security import create_access_token


class FakePipeline:
    def __init__(self, store: dict[str, int], key_holder: dict[str, Any]) -> None:
        self.store = store
        self.key_holder = key_holder
        self.ops: list[str] = []

    def incr(self, key: str) -> None:
        self.key_holder["key"] = key
        self.store[key] = self.store.get(key, 0) + 1
        self.ops.append("incr")

    def ttl(self, key: str) -> None:
        self.ops.append("ttl")

    async def execute(self) -> list[int]:
        key = self.key_holder["key"]
        return [self.store[key], self.key_holder.get("ttl", -1)]


class FakeRedis:
    """Minimal Redis stand-in; can be told to fail."""

    def __init__(self, *, fail: bool = False, ttl: int = -1) -> None:
        self.store: dict[str, int] = {}
        self.fail = fail
        self.expires: list[tuple[str, int]] = []
        self._holder: dict[str, Any] = {"ttl": ttl}

    def pipeline(self) -> FakePipeline:
        if self.fail:
            raise ConnectionError("redis is down")
        return FakePipeline(self.store, self._holder)

    async def expire(self, key: str, seconds: int) -> None:
        self.expires.append((key, seconds))


def _request(path: str = "/api/v1/jobs", headers: dict[str, str] | None = None) -> Request:
    scope = {
        "type": "http",
        "method": "GET",
        "path": path,
        "headers": Headers(headers or {}).raw,
        "client": ("10.0.0.7", 51234),
        "query_string": b"",
    }
    return Request(scope)


# ---------------------------------------------------------------------------
# Budgets
# ---------------------------------------------------------------------------


class TestBudgetSelection:
    def test_uploads_draw_from_their_own_tighter_budget(self) -> None:
        # One upload costs minutes of sandbox and LLM work; a shared counter would
        # let a client spend the whole allowance on the expensive endpoint.
        upload = _budget_for("/api/v1/uploads")
        default = _budget_for("/api/v1/jobs")

        assert upload.name == "upload"
        assert default.name == "default"
        assert upload.requests < default.requests

    def test_other_paths_use_the_default_budget(self) -> None:
        assert _budget_for("/api/v1/jobs/abc/findings").name == "default"


# ---------------------------------------------------------------------------
# Keying
# ---------------------------------------------------------------------------


class TestPrincipalKey:
    def test_an_authenticated_caller_is_keyed_on_their_user_id(self) -> None:
        # Keying on IP alone would throttle every analyst behind one bank's gateway
        # as if they were a single client.
        token = create_access_token("user-42")
        key = principal_key(_request(headers={"authorization": f"Bearer {token}"}))

        assert key == "user:user-42"

    def test_an_anonymous_caller_is_keyed_on_their_address(self) -> None:
        assert principal_key(_request()) == "ip:10.0.0.7"

    def test_an_unsigned_token_cannot_choose_its_own_bucket(self) -> None:
        # The subject is only trusted after signature verification; otherwise a
        # client edits `sub` to get a fresh allowance, or to exhaust someone else's.
        import jwt

        forged = jwt.encode({"sub": "victim"}, "attacker-key", algorithm="HS256")
        key = principal_key(_request(headers={"authorization": f"Bearer {forged}"}))

        assert key == "ip:10.0.0.7"

    def test_a_malformed_authorization_header_falls_back_to_the_address(self) -> None:
        key = principal_key(_request(headers={"authorization": "Bearer not.a.token"}))

        assert key == "ip:10.0.0.7"


# ---------------------------------------------------------------------------
# Counting
# ---------------------------------------------------------------------------


class TestCounting:
    async def test_requests_within_the_budget_are_allowed(self) -> None:
        limiter = RateLimiter(FakeRedis())
        budget = Budget(requests=3, window_seconds=60, name="test")

        results = [await limiter.check("user:1", budget) for _ in range(3)]

        assert all(allowed for allowed, _, _ in results)
        assert [remaining for _, remaining, _ in results] == [2, 1, 0]

    async def test_the_request_past_the_budget_is_refused(self) -> None:
        limiter = RateLimiter(FakeRedis())
        budget = Budget(requests=2, window_seconds=60, name="test")

        for _ in range(2):
            await limiter.check("user:1", budget)
        allowed, remaining, _ = await limiter.check("user:1", budget)

        assert not allowed
        assert remaining == 0

    async def test_separate_principals_have_separate_allowances(self) -> None:
        limiter = RateLimiter(FakeRedis())
        budget = Budget(requests=1, window_seconds=60, name="test")

        await limiter.check("user:1", budget)
        allowed, _, _ = await limiter.check("user:2", budget)

        assert allowed

    async def test_the_window_ttl_is_set_on_the_first_request(self) -> None:
        # Anchored to the first request rather than refreshed on each one; a sliding
        # TTL would never let the counter reset under sustained traffic.
        redis = FakeRedis(ttl=-1)
        limiter = RateLimiter(redis)

        await limiter.check("user:1", Budget(requests=5, window_seconds=30, name="test"))

        assert redis.expires == [("ratelimit:test:user:1", 30)]

    async def test_a_redis_outage_fails_open(self) -> None:
        # A protective control must not become the cause of an outage.
        limiter = RateLimiter(FakeRedis(fail=True))

        allowed, remaining, retry_after = await limiter.check(
            "user:1", Budget(requests=1, window_seconds=60, name="test")
        )

        assert allowed
        assert remaining == 1
        assert retry_after == 0


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------


class TestMiddleware:
    """Driven against a purpose-built app.

    Starlette builds its middleware stack once, on first request, so patching the
    shared ``app.main.app`` after another test has already exercised it silently has
    no effect — the suite would pass in isolation and fail in a full run. A local app
    per test also keeps the assertions about the limiter rather than about whichever
    real route happened to be convenient.
    """

    @pytest.fixture
    def client(self, monkeypatch):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from app.core.ratelimit import RateLimitMiddleware

        monkeypatch.setattr(settings, "rate_limit_enabled", True)
        monkeypatch.setattr(settings, "rate_limit_requests", 2)
        monkeypatch.setattr(settings, "rate_limit_window_seconds", 60)

        def _build() -> TestClient:
            local = FastAPI()
            local.add_middleware(RateLimitMiddleware, limiter=RateLimiter(FakeRedis()))

            @local.get("/api/v1/jobs")
            async def jobs() -> dict[str, str]:
                return {"ok": "yes"}

            @local.get("/api/v1/health/live")
            async def live() -> dict[str, str]:
                return {"status": "ok"}

            return TestClient(local)

        return _build

    def test_exceeding_the_budget_returns_429_with_retry_after(self, client) -> None:
        c = client()
        for _ in range(2):
            c.get("/api/v1/jobs")

        resp = c.get("/api/v1/jobs")

        assert resp.status_code == 429
        assert resp.headers["Retry-After"]
        assert resp.json()["title"] == "Too Many Requests"

    def test_allowed_responses_advertise_the_remaining_budget(self, client) -> None:
        resp = client().get("/api/v1/jobs")

        assert resp.status_code == 200
        assert resp.headers["X-RateLimit-Limit"] == "2"
        assert resp.headers["X-RateLimit-Remaining"] == "1"

    def test_liveness_probes_are_never_rate_limited(self, client) -> None:
        # Throttling a probe gets healthy pods killed by the orchestrator.
        c = client()
        for _ in range(6):
            resp = c.get("/api/v1/health/live")

        assert resp.status_code == 200

    def test_limiting_can_be_disabled_entirely(self, client, monkeypatch) -> None:
        monkeypatch.setattr(settings, "rate_limit_enabled", False)
        c = client()

        for _ in range(5):
            resp = c.get("/api/v1/jobs")

        assert resp.status_code == 200
