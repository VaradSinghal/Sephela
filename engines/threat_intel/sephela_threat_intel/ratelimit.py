"""Rate limiting + circuit breaking — the two things that keep a shared,
metered, third-party dependency from taking the pipeline down with it.

``docs/architecture/02-services.md`` requires the TI engine to be "rate-limit
aware; circuit-breakered". The split of responsibility:

- **TokenBucket** protects *them*: it paces our calls to a provider's documented
  quota, so a job with 400 IoCs does not get the whole deployment's API key
  banned. Free tiers are measured in requests per minute, so the bucket refills
  continuously rather than in fixed windows.
- **CircuitBreaker** protects *us*: after repeated failures it stops calling a
  dead provider outright, so a feed that is down costs one timeout instead of
  one timeout per indicator. A job with 400 IoCs against a 30s-timeout dead API
  would otherwise stall the queue for hours.

Both are per-process. The engine is deliberately not distributed-coordinated:
overshooting quota slightly across workers is cheaper than a Redis round-trip
per lookup, and providers answer 429 (which the breaker also counts) when we do.

Time is injected so tests are instant and deterministic — no ``sleep``-based
tests anywhere in this module's suite.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from enum import Enum

Clock = Callable[[], float]


class TokenBucket:
    """Continuously-refilling request budget.

    ``capacity`` is the burst allowance; ``rate`` is the sustained refill in
    tokens per second. ``acquire()`` waits for a token rather than failing, so a
    slow provider throttles the pipeline instead of dropping indicators.
    """

    def __init__(
        self,
        *,
        rate_per_minute: int,
        capacity: int | None = None,
        clock: Clock = time.monotonic,
    ) -> None:
        if rate_per_minute <= 0:
            raise ValueError("rate_per_minute must be positive")
        self.rate = rate_per_minute / 60.0
        self.capacity = float(capacity if capacity is not None else max(1, rate_per_minute // 4))
        self._clock = clock
        self._tokens = self.capacity
        self._updated = clock()
        self._lock = asyncio.Lock()

    def _refill(self) -> None:
        now = self._clock()
        elapsed = max(0.0, now - self._updated)
        self._updated = now
        self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)

    def _take(self) -> float:
        """Consume a token, or return the seconds to wait for the next one."""
        self._refill()
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return 0.0
        return (1.0 - self._tokens) / self.rate

    async def acquire(self) -> None:
        """Block until a request may be made."""
        while True:
            async with self._lock:
                wait = self._take()
            if wait <= 0.0:
                return
            await asyncio.sleep(wait)

    def try_acquire(self) -> bool:
        """Non-blocking variant, for callers that would rather skip than wait."""
        return self._take() <= 0.0


class BreakerState(str, Enum):
    closed = "closed"  # calls flow
    open = "open"  # calls rejected outright
    half_open = "half_open"  # one probe allowed


class CircuitBreaker:
    """Trips after ``threshold`` consecutive failures; probes after ``reset_after``.

    A single success in ``half_open`` closes it again — providers usually recover
    wholesale (their outage ends) rather than per-indicator.
    """

    def __init__(
        self,
        *,
        threshold: int = 5,
        reset_after: float = 60.0,
        clock: Clock = time.monotonic,
    ) -> None:
        self.threshold = max(1, threshold)
        self.reset_after = reset_after
        self._clock = clock
        self._failures = 0
        self._opened_at: float | None = None

    @property
    def state(self) -> BreakerState:
        if self._opened_at is None:
            return BreakerState.closed
        if self._clock() - self._opened_at >= self.reset_after:
            return BreakerState.half_open
        return BreakerState.open

    @property
    def allows_call(self) -> bool:
        return self.state is not BreakerState.open

    def record_success(self) -> None:
        self._failures = 0
        self._opened_at = None

    def record_failure(self) -> None:
        # A failure while probing re-opens the breaker for a fresh cool-down.
        if self.state is BreakerState.half_open:
            self._opened_at = self._clock()
            return
        self._failures += 1
        if self._failures >= self.threshold:
            self._opened_at = self._clock()
