"""Enrichment cache contract.

"Caches aggressively" (docs/architecture/02-services.md) is not an optimization
here — it is what makes the engine affordable. Free provider tiers allow a few
hundred lookups a day, while a single APK can yield hundreds of indicators, and
the same CDN domain recurs across nearly every sample in a campaign. A cache hit
also makes a stage re-run free, which is what lets the orchestrator retry
threat-intel like any other stage.

The engine defines the *protocol* and ships an in-memory implementation for tests
and standalone runs. The durable implementation lives in the backend against the
``enrichments`` table (``expires_at`` is the TTL column reserved for exactly
this in docs/architecture/04-data-model.md) — the engine never touches the
database itself, keeping it a pure function of its inputs.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from sephela_threat_intel.base import ProviderResult, Verdict
from sephela_threat_intel.iocs import Ioc, IocType

#: Per-IoC-type default TTLs, in seconds. A file hash's verdict is essentially
#: immutable, so it is cached for a week; network infrastructure is rented and
#: rotates within days, so domains/IPs/URLs expire much sooner.
DEFAULT_TTLS: dict[IocType, int] = {
    IocType.hash: 7 * 24 * 3600,
    IocType.cert: 7 * 24 * 3600,
    IocType.domain: 12 * 3600,
    IocType.ip: 6 * 3600,
    IocType.url: 12 * 3600,
}
FALLBACK_TTL = 6 * 3600


def ttl_for(ioc: Ioc) -> int:
    return DEFAULT_TTLS.get(ioc.type, FALLBACK_TTL)


@dataclass
class CachedVerdict:
    """The persisted shape of a provider answer — mirrors an ``enrichments`` row."""

    verdict: Verdict
    raw: dict[str, Any]

    def to_result(self, ioc: Ioc, provider: str) -> ProviderResult:
        """Rehydrate a ``ProviderResult`` from cache.

        The normalized fields are stored inside ``raw`` under a reserved
        ``_normalized`` key so a cached answer reconstructs identically without
        needing the provider's parsing code — the parser may have changed
        version since, and re-parsing an old payload with new code would produce
        a verdict the cache key never described.
        """
        norm = self.raw.get("_normalized")
        norm = norm if isinstance(norm, dict) else {}
        return ProviderResult(
            ioc=ioc,
            provider=provider,
            verdict=self.verdict,
            score=float(norm.get("score", 0.0)),
            families=list(norm.get("families", [])),
            signatures=list(norm.get("signatures", [])),
            actors=list(norm.get("actors", [])),
            summary=str(norm.get("summary", "")),
            raw=self.raw,
            cached=True,
        )


def to_cached(result: ProviderResult) -> CachedVerdict:
    """Pack a fresh result for persistence, embedding the normalized fields."""
    raw = dict(result.raw)
    raw["_normalized"] = {
        "score": result.score,
        "families": result.families,
        "signatures": result.signatures,
        "actors": result.actors,
        "summary": result.summary,
    }
    return CachedVerdict(verdict=result.verdict, raw=raw)


@runtime_checkable
class EnrichmentCache(Protocol):
    """What the engine needs from a cache. Implemented by the backend over Postgres.

    Runtime-checkable so an adapter (the backend's repository) can assert it still
    satisfies the contract in its own test suite, without importing anything from
    the engine's internals.
    """

    async def get(self, ioc: Ioc, provider: str) -> CachedVerdict | None:
        """Return a non-expired verdict, or None."""
        ...

    async def put(self, ioc: Ioc, provider: str, entry: CachedVerdict, *, ttl: int) -> None:
        """Store a verdict with a TTL in seconds."""
        ...


class InMemoryCache:
    """Process-local cache — used by tests and standalone engine runs."""

    def __init__(self, *, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._store: dict[tuple[str, str], tuple[float, CachedVerdict]] = {}

    async def get(self, ioc: Ioc, provider: str) -> CachedVerdict | None:
        entry = self._store.get((ioc.key, provider))
        if entry is None:
            return None
        expires_at, cached = entry
        if self._clock() >= expires_at:
            del self._store[(ioc.key, provider)]
            return None
        return cached

    async def put(self, ioc: Ioc, provider: str, entry: CachedVerdict, *, ttl: int) -> None:
        self._store[(ioc.key, provider)] = (self._clock() + ttl, entry)


class NullCache:
    """Disables caching — every lookup goes to the provider. For debugging only."""

    async def get(self, ioc: Ioc, provider: str) -> CachedVerdict | None:
        return None

    async def put(self, ioc: Ioc, provider: str, entry: CachedVerdict, *, ttl: int) -> None:
        return None
