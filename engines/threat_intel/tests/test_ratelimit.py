"""Token bucket + circuit breaker.

Time is injected everywhere, so these tests are instant and deterministic — no
``asyncio.sleep`` based timing assertions.
"""

from __future__ import annotations

import pytest

from sephela_threat_intel.ratelimit import BreakerState, CircuitBreaker, TokenBucket


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class TestTokenBucket:
    def test_burst_is_capped_by_capacity(self) -> None:
        clock = FakeClock()
        bucket = TokenBucket(rate_per_minute=60, capacity=3, clock=clock)
        assert [bucket.try_acquire() for _ in range(4)] == [True, True, True, False]

    def test_tokens_refill_continuously(self) -> None:
        clock = FakeClock()
        bucket = TokenBucket(rate_per_minute=60, capacity=1, clock=clock)  # 1/sec
        assert bucket.try_acquire() is True
        assert bucket.try_acquire() is False
        clock.advance(1.0)
        assert bucket.try_acquire() is True

    def test_refill_never_exceeds_capacity(self) -> None:
        clock = FakeClock()
        bucket = TokenBucket(rate_per_minute=60, capacity=2, clock=clock)
        clock.advance(3600.0)  # idle for an hour
        assert [bucket.try_acquire() for _ in range(3)] == [True, True, False]

    async def test_acquire_waits_then_proceeds(self) -> None:
        # Real clock here, but a fast rate: verifies acquire() blocks rather than
        # failing when the bucket is empty.
        bucket = TokenBucket(rate_per_minute=6000, capacity=1)  # 100/sec
        await bucket.acquire()
        await bucket.acquire()  # would fail with try_acquire; here it waits

    def test_zero_rate_is_rejected(self) -> None:
        with pytest.raises(ValueError):
            TokenBucket(rate_per_minute=0)

    def test_default_capacity_allows_a_modest_burst(self) -> None:
        # VirusTotal's 4/min tier must still allow at least one call immediately.
        assert TokenBucket(rate_per_minute=4).try_acquire() is True


class TestCircuitBreaker:
    def test_trips_after_threshold_consecutive_failures(self) -> None:
        clock = FakeClock()
        breaker = CircuitBreaker(threshold=3, reset_after=60.0, clock=clock)
        for _ in range(2):
            breaker.record_failure()
        assert breaker.allows_call is True
        breaker.record_failure()
        assert breaker.state is BreakerState.open
        assert breaker.allows_call is False

    def test_success_resets_the_failure_count(self) -> None:
        breaker = CircuitBreaker(threshold=3)
        breaker.record_failure()
        breaker.record_failure()
        breaker.record_success()
        breaker.record_failure()
        assert breaker.allows_call is True

    def test_half_opens_after_the_cooldown(self) -> None:
        clock = FakeClock()
        breaker = CircuitBreaker(threshold=1, reset_after=60.0, clock=clock)
        breaker.record_failure()
        assert breaker.state is BreakerState.open
        clock.advance(60.0)
        assert breaker.state is BreakerState.half_open
        assert breaker.allows_call is True

    def test_failure_while_probing_reopens_for_a_full_cooldown(self) -> None:
        clock = FakeClock()
        breaker = CircuitBreaker(threshold=1, reset_after=60.0, clock=clock)
        breaker.record_failure()
        clock.advance(60.0)
        assert breaker.state is BreakerState.half_open
        breaker.record_failure()
        assert breaker.state is BreakerState.open
        clock.advance(59.0)
        assert breaker.state is BreakerState.open

    def test_success_while_probing_closes_it(self) -> None:
        clock = FakeClock()
        breaker = CircuitBreaker(threshold=1, reset_after=10.0, clock=clock)
        breaker.record_failure()
        clock.advance(10.0)
        breaker.record_success()
        assert breaker.state is BreakerState.closed
