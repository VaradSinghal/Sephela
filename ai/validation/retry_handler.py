"""Retry handling with exponential backoff for LLM calls."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable, TypeVar, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)

T = TypeVar('T')


class RetryStrategy(str, Enum):
    """Retry strategy types."""
    EXPONENTIAL = "exponential"
    LINEAR = "linear"
    CONSTANT = "constant"
    FIBONACCI = "fibonacci"


@dataclass
class RetryConfig:
    """Configuration for retry behavior."""
    max_attempts: int = 3
    base_delay: float = 1.0
    max_delay: float = 60.0
    strategy: RetryStrategy = RetryStrategy.EXPONENTIAL
    jitter: bool = True
    jitter_factor: float = 0.1
    retryable_exceptions: tuple = (
        Exception,  # Base - will be filtered
    )
    non_retryable_exceptions: tuple = ()
    on_retry: Optional[Callable[[Exception, int], None]] = None


@dataclass
class RetryResult:
    """Result of a retry operation."""
    success: bool
    result: Any = None
    error: Optional[Exception] = None
    attempts: int = 0
    total_delay: float = 0.0
    last_exception: Optional[Exception] = None


class RetryHandler:
    """Handles retries with configurable strategies."""

    def __init__(self, config: Optional[RetryConfig] = None):
        self.config = config or RetryConfig()

    async def execute(self, func: Callable[..., T], *args, **kwargs) -> RetryResult:
        """Execute function with retry logic."""
        last_exception = None
        total_delay = 0.0

        for attempt in range(self.config.max_attempts):
            try:
                if asyncio.iscoroutinefunction(func):
                    result = await func(*args, **kwargs)
                else:
                    result = func(*args, **kwargs)

                return RetryResult(
                    success=True,
                    result=result,
                    attempts=attempt + 1,
                    total_delay=total_delay,
                )

            except self.config.non_retryable_exceptions as e:
                logger.error(f"Non-retryable exception: {e}")
                return RetryResult(
                    success=False,
                    error=e,
                    attempts=attempt + 1,
                    total_delay=total_delay,
                    last_exception=e,
                )

            except Exception as e:
                last_exception = e

                if attempt < self.config.max_attempts - 1:
                    delay = self._calculate_delay(attempt)
                    total_delay += delay

                    logger.warning(
                        f"Attempt {attempt + 1} failed: {e}. Retrying in {delay:.2f}s"
                    )

                    if self.config.on_retry:
                        self.config.on_retry(e, attempt + 1)

                    await asyncio.sleep(delay)
                else:
                    logger.error(f"All {self.config.max_attempts} attempts failed")

        return RetryResult(
            success=False,
            error=last_exception,
            attempts=self.config.max_attempts,
            total_delay=total_delay,
            last_exception=last_exception,
        )

    def _calculate_delay(self, attempt: int) -> float:
        """Calculate delay based on strategy."""
        import random

        if self.config.strategy == RetryStrategy.EXPONENTIAL:
            delay = self.config.base_delay * (2 ** attempt)
        elif self.config.strategy == RetryStrategy.LINEAR:
            delay = self.config.base_delay * (attempt + 1)
        elif self.config.strategy == RetryStrategy.CONSTANT:
            delay = self.config.base_delay
        elif self.config.strategy == RetryStrategy.FIBONACCI:
            fib = self._fibonacci(attempt + 2)
            delay = self.config.base_delay * fib
        else:
            delay = self.config.base_delay

        delay = min(delay, self.config.max_delay)

        if self.config.jitter:
            jitter_range = delay * self.config.jitter_factor
            delay += random.uniform(-jitter_range, jitter_range)
            delay = max(0, delay)

        return delay

    def _fibonacci(self, n: int) -> int:
        """Calculate nth Fibonacci number."""
        if n <= 1:
            return n
        a, b = 0, 1
        for _ in range(n):
            a, b = b, a + b
        return a


def with_retry(config: Optional[RetryConfig] = None):
    """Decorator for adding retry logic to functions."""
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        handler = RetryHandler(config)

        async def async_wrapper(*args, **kwargs) -> T:
            result = await handler.execute(func, *args, **kwargs)
            if result.success:
                return result.result
            raise result.error or RuntimeError("Retry failed")

        def sync_wrapper(*args, **kwargs) -> T:
            result = asyncio.run(handler.execute(func, *args, **kwargs))
            if result.success:
                return result.result
            raise result.error or RuntimeError("Retry failed")

        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper

    return decorator


class CircuitBreaker:
    """Circuit breaker pattern for preventing cascade failures."""

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
        expected_exception: type = Exception,
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception
        self.failure_count = 0
        self.last_failure_time = None
        self.state = "closed"  # closed, open, half-open

    async def call(self, func: Callable[..., T], *args, **kwargs) -> T:
        """Execute function with circuit breaker."""
        if self.state == "open":
            if self.last_failure_time and \
               (asyncio.get_event_loop().time() - self.last_failure_time) > self.recovery_timeout:
                self.state = "half-open"
                logger.info("Circuit breaker entering half-open state")
            else:
                raise RuntimeError("Circuit breaker is open")

        try:
            if asyncio.iscoroutinefunction(func):
                result = await func(*args, **kwargs)
            else:
                result = func(*args, **kwargs)

            if self.state == "half-open":
                self.state = "closed"
                self.failure_count = 0
                logger.info("Circuit breaker closed")

            return result

        except self.expected_exception as e:
            self.failure_count += 1
            self.last_failure_time = asyncio.get_event_loop().time()

            if self.failure_count >= self.failure_threshold:
                self.state = "open"
                logger.error(f"Circuit breaker opened after {self.failure_count} failures")

            raise

    def reset(self):
        """Reset circuit breaker."""
        self.failure_count = 0
        self.last_failure_time = None
        self.state = "closed"