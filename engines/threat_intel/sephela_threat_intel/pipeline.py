"""Threat Intelligence pipeline — IoCs → cached/live lookups → Evidence Envelope.

The engine's public entrypoint, mirroring ``sephela_static.pipeline`` and
``sephela_dynamic.pipeline``: same envelope out, same "one source failing is
``partial``, never fatal" isolation guarantee. What differs is that the work is
network-bound against metered third-party APIs, so the pipeline owns three
concerns the other engines don't have:

**Routing.** Indicators go only to providers that can answer for their class, so
no quota is spent asking AbuseIPDB about a file hash.

**Cost control, in layers.** Cache first (a hit costs nothing); then a global
``max_lookups`` ceiling so one pathological sample with 4000 extracted strings
cannot drain the day's quota; then a per-provider token bucket pacing the calls
that remain. Truncation is recorded in ``errors`` — a silently shortened
enrichment would read as "nothing found" to both the scoring engine and the
analyst.

**Failure containment.** A rate-limited or unreachable provider is disabled for
the rest of the run after its circuit breaker trips, rather than being retried
per indicator. With hundreds of indicators and a 30-second timeout, the
difference is a few seconds versus hours of a blocked queue.

Concurrency is bounded and per-provider ordering is preserved so runs are
reproducible enough to debug.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

import httpx

from sephela_threat_intel.base import (
    Provider,
    ProviderError,
    ProviderResult,
    RateLimitedError,
    Verdict,
)
from sephela_threat_intel.cache import (
    EnrichmentCache,
    InMemoryCache,
    to_cached,
    ttl_for,
)
from sephela_threat_intel.correlate import IocConsensus, build_findings
from sephela_threat_intel.envelope import (
    ENVELOPE_VERSION,
    EngineInfo,
    EvidenceEnvelope,
    ExtractorError,
    Status,
)
from sephela_threat_intel.iocs import Ioc, dedupe, expand_urls
from sephela_threat_intel.ratelimit import CircuitBreaker, TokenBucket

ENGINE_NAME = "threat_intel"
ENGINE_VERSION = "1.0.0"

#: Total live lookups allowed per job across all providers. Cache hits are free
#: and do not count against it.
DEFAULT_MAX_LOOKUPS = 200
#: Concurrent in-flight requests across all providers.
DEFAULT_CONCURRENCY = 8
DEFAULT_TIMEOUT_SECS = 20.0
#: Consecutive failures before a provider is dropped for the rest of the run.
DEFAULT_BREAKER_THRESHOLD = 4

USER_AGENT = f"Sephela-ThreatIntel/{ENGINE_VERSION}"


class _Channel:
    """One provider plus the guardrails around it, for the duration of one run."""

    def __init__(self, provider: Provider, *, breaker_threshold: int) -> None:
        self.provider = provider
        self.bucket = TokenBucket(rate_per_minute=provider.requests_per_minute)
        # reset_after is deliberately longer than any single job: within one run
        # a tripped provider should stay down, not be probed repeatedly.
        self.breaker = CircuitBreaker(threshold=breaker_threshold, reset_after=3600.0)
        self.calls = 0
        self.cache_hits = 0
        self.errors: list[str] = []
        #: set when the provider is out of quota — no further calls this run
        self.exhausted = False

    @property
    def usable(self) -> bool:
        return not self.exhausted and self.breaker.allows_call

    def record_error(self, message: str) -> None:
        # Hundreds of indicators against one dead feed produce one message, not
        # hundreds — the envelope's error list is read by humans.
        if message not in self.errors:
            self.errors.append(message)


async def analyze(
    iocs: list[Ioc],
    *,
    providers: list[Provider],
    cache: EnrichmentCache | None = None,
    job_id: str | None = None,
    apk_sha256: str | None = None,
    max_lookups: int = DEFAULT_MAX_LOOKUPS,
    concurrency: int = DEFAULT_CONCURRENCY,
    timeout_secs: float = DEFAULT_TIMEOUT_SECS,
    breaker_threshold: int = DEFAULT_BREAKER_THRESHOLD,
    client: httpx.AsyncClient | None = None,
) -> EvidenceEnvelope:
    """Enrich a list of indicators and return an Evidence Envelope.

    Never raises for provider-level problems — those become entries in
    ``envelope.errors`` and degrade the status to ``partial`` (or ``failed`` if
    no provider produced anything at all).

    Args:
        iocs: Indicators to enrich. Normalized and de-duplicated here, and URL
            indicators are expanded into their host domain/IP so each provider
            receives the indicator class it can answer for.
        providers: Configured providers to consult (see ``build_providers``).
        cache: Enrichment cache. Defaults to a process-local one, which is
            effectively no cache across worker restarts — the backend passes a
            Postgres-backed implementation.
        job_id: Job identifier, echoed into the envelope for tracing.
        apk_sha256: The sample's hash, echoed into the envelope.
        max_lookups: Ceiling on *live* provider calls for this run.
        concurrency: Maximum in-flight requests.
        timeout_secs: Per-request timeout.
        breaker_threshold: Consecutive failures before a provider is dropped.
        client: Inject an ``httpx.AsyncClient`` (tests use a MockTransport).

    Returns:
        A complete Evidence Envelope with threat-intel findings.
    """
    envelope = EvidenceEnvelope(
        envelope_version=ENVELOPE_VERSION,
        job_id=job_id,
        apk_sha256=apk_sha256,
        engine=EngineInfo(name=ENGINE_NAME, version=ENGINE_VERSION),
        produced_at=datetime.now(timezone.utc).isoformat(),
        status=Status.ok,
    )

    candidates = dedupe([*iocs, *expand_urls(iocs)])
    active = [p for p in providers if p.configured]

    if not candidates:
        envelope.status = Status.ok
        envelope.evidence["summary"] = _summary([], [], 0, 0)
        return envelope
    if not active:
        envelope.status = Status.failed
        envelope.errors.append(
            ExtractorError(
                extractor="pipeline",
                message="No threat-intel providers are configured — nothing was enriched.",
            )
        )
        return envelope

    channels = {p.name: _Channel(p, breaker_threshold=breaker_threshold) for p in active}
    cache = cache if cache is not None else InMemoryCache()

    # Work items are (provider, ioc) pairs — the routing decision, made once.
    tasks = [
        (channels[p.name], ioc) for ioc in candidates for p in active if p.handles(ioc)
    ]

    budget = _Budget(max_lookups)
    semaphore = asyncio.Semaphore(max(1, concurrency))

    owns_client = client is None
    http = client or httpx.AsyncClient(
        timeout=httpx.Timeout(timeout_secs),
        headers={"User-Agent": USER_AGENT},
        follow_redirects=True,
    )
    try:
        results = await asyncio.gather(
            *(
                _lookup(channel, ioc, http, cache, budget, semaphore)
                for channel, ioc in tasks
            )
        )
    finally:
        if owns_client:
            await http.aclose()

    collected = [r for r in results if r is not None]
    findings, reconciled = build_findings(collected)
    envelope.findings.extend(findings)

    live_calls = sum(c.calls for c in channels.values())
    cache_hits = sum(c.cache_hits for c in channels.values())
    envelope.iocs_queried = len({r.ioc for r in collected})
    envelope.iocs_cached = cache_hits

    for channel in channels.values():
        envelope.evidence[channel.provider.name] = {
            "live_calls": channel.calls,
            "cache_hits": channel.cache_hits,
            "hits": sum(
                1 for r in collected if r.provider == channel.provider.name and r.is_hit
            ),
            "circuit": channel.breaker.state.value,
            "exhausted": channel.exhausted,
        }
        for message in channel.errors:
            envelope.errors.append(
                ExtractorError(extractor=channel.provider.name, message=message)
            )

    envelope.evidence["indicators"] = [_indicator_evidence(item) for item in reconciled]
    envelope.evidence["summary"] = _summary(reconciled, active, live_calls, cache_hits)

    if budget.truncated:
        envelope.errors.append(
            ExtractorError(
                extractor="pipeline",
                message=(
                    f"Lookup budget of {max_lookups} exhausted — "
                    f"{budget.skipped} indicator/provider pair(s) were not queried."
                ),
            )
        )

    envelope.status = _status(collected, channels, budget)
    return envelope


class _Budget:
    """Shared ceiling on live provider calls, with a record of what it cost."""

    def __init__(self, limit: int) -> None:
        self.limit = max(0, limit)
        self.used = 0
        self.skipped = 0

    def take(self) -> bool:
        if self.used >= self.limit:
            self.skipped += 1
            return False
        self.used += 1
        return True

    @property
    def truncated(self) -> bool:
        return self.skipped > 0


async def _lookup(
    channel: _Channel,
    ioc: Ioc,
    client: httpx.AsyncClient,
    cache: EnrichmentCache,
    budget: _Budget,
    semaphore: asyncio.Semaphore,
) -> ProviderResult | None:
    """Resolve one (provider, indicator) pair: cache, then budget, then network."""
    provider = channel.provider

    cached = await cache.get(ioc, provider.name)
    if cached is not None:
        channel.cache_hits += 1
        return cached.to_result(ioc, provider.name)

    # Checked after the cache so a tripped provider still serves cached answers.
    if not channel.usable:
        return None
    if not budget.take():
        return None

    async with semaphore:
        # Re-check inside the semaphore: the breaker may have tripped while this
        # coroutine waited its turn behind other indicators.
        if not channel.usable:
            return None
        await channel.bucket.acquire()
        try:
            result = await provider.lookup(ioc, client)
        except RateLimitedError as exc:
            channel.exhausted = True
            channel.record_error(str(exc))
            return None
        except ProviderError as exc:
            channel.breaker.record_failure()
            channel.record_error(str(exc))
            return None
        except Exception as exc:  # noqa: BLE001 — isolation is the whole point
            channel.breaker.record_failure()
            channel.record_error(f"unexpected {type(exc).__name__}: {exc}")
            return None

    channel.calls += 1
    channel.breaker.record_success()

    # Cache every answer, including "no record" — a negative result is expensive
    # to obtain and just as reusable as a positive one.
    await cache.put(ioc, provider.name, to_cached(result), ttl=ttl_for(ioc))
    return result


def _indicator_evidence(item: IocConsensus) -> dict[str, Any]:
    return {
        "ioc": item.ioc.key,
        "type": item.ioc.type.value,
        "value": item.ioc.value,
        "source": item.ioc.source,
        "verdict": item.verdict.value,
        "confidence": item.confidence,
        "providers": item.providers,
        "flagged_by": item.hit_providers,
        "cached": item.all_cached,
    }


def _summary(
    reconciled: list[IocConsensus],
    providers: list[Provider],
    live_calls: int,
    cache_hits: int,
) -> dict[str, Any]:
    counts = {v.value: 0 for v in Verdict}
    for item in reconciled:
        counts[item.verdict.value] += 1
    return {
        "indicators": len(reconciled),
        "verdicts": counts,
        "malicious_indicators": counts[Verdict.malicious.value],
        "providers_consulted": [p.name for p in providers],
        "live_calls": live_calls,
        "cache_hits": cache_hits,
    }


def _status(
    collected: list[ProviderResult],
    channels: dict[str, _Channel],
    budget: _Budget,
) -> Status:
    """Derive the envelope status.

    ``failed`` is reserved for "we learned nothing": every provider errored and
    no answer, live or cached, came back. A run where some feeds failed but
    others answered is ``partial`` — genuinely useful evidence with a caveat
    attached, which is what the orchestrator's partial-success policy expects.
    """
    had_errors = any(c.errors for c in channels.values()) or budget.truncated
    if not collected:
        return Status.failed if had_errors else Status.partial
    return Status.partial if had_errors else Status.ok
