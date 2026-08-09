"""End-to-end engine behaviour: routing, caching, budgets, and failure isolation.

Providers here are fakes rather than mock-transport-backed real providers: these
tests are about the pipeline's *policy* (who gets asked what, how often, and what
happens when a feed misbehaves), which is independent of any provider's wire
format. ``test_providers.py`` covers the wire format.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sephela_threat_intel.base import (
    Provider,
    ProviderResult,
    ProviderUnavailableError,
    RateLimitedError,
    Verdict,
)
from sephela_threat_intel.cache import CachedVerdict, InMemoryCache
from sephela_threat_intel.envelope import FindingType, Status
from sephela_threat_intel.iocs import Ioc, IocType
from sephela_threat_intel.pipeline import ENGINE_NAME, ENGINE_VERSION, analyze

if TYPE_CHECKING:  # pragma: no cover
    import httpx

HASH = Ioc(IocType.hash, "a" * 64, "sample")
DOMAIN = Ioc(IocType.domain, "c2.evil.tk", "static")
IP = Ioc(IocType.ip, "45.55.1.2", "dynamic")
URL = Ioc(IocType.url, "http://c2.evil.tk/reg", "dynamic")


class FakeProvider(Provider):
    """Records every indicator it is asked about; answers however the test wants."""

    def __init__(
        self,
        name: str,
        supports: set[IocType],
        *,
        verdict: Verdict = Verdict.malicious,
        score: float = 0.9,
        families: list[str] | None = None,
        raises: type[Exception] | None = None,
        rate_per_minute: int = 6000,
    ) -> None:
        super().__init__(api_key="test-key")
        self.name = name
        self.supports = frozenset(supports)
        self.requests_per_minute = rate_per_minute
        self.seen: list[Ioc] = []
        self._verdict = verdict
        self._score = score
        self._families = families or []
        self._raises = raises

    async def lookup(self, ioc: Ioc, client: httpx.AsyncClient) -> ProviderResult:
        self.seen.append(ioc)
        if self._raises is not None:
            raise self._raises(f"{self.name} failed")
        return ProviderResult(
            ioc=ioc,
            provider=self.name,
            verdict=self._verdict,
            score=self._score,
            families=list(self._families),
            summary=f"{self.name} says {self._verdict.value}",
        )


class TestRouting:
    async def test_indicators_only_reach_providers_that_support_them(self) -> None:
        hashes = FakeProvider("hashes", {IocType.hash})
        hosts = FakeProvider("hosts", {IocType.domain, IocType.ip})
        await analyze([HASH, DOMAIN, IP], providers=[hashes, hosts])
        assert hashes.seen == [HASH]
        assert set(hosts.seen) == {DOMAIN, IP}

    async def test_url_indicators_are_expanded_to_their_host(self) -> None:
        # URLhaus knows the URL; AbuseIPDB only knows the IP. Expansion is what
        # lets both contribute from one observed request.
        hosts = FakeProvider("hosts", {IocType.domain})
        urls = FakeProvider("urls", {IocType.url})
        await analyze([URL], providers=[hosts, urls])
        assert urls.seen == [URL]
        assert hosts.seen == [Ioc(IocType.domain, "c2.evil.tk")]

    async def test_duplicate_indicators_are_queried_once(self) -> None:
        provider = FakeProvider("p", {IocType.domain})
        duplicate = Ioc(IocType.domain, "c2.evil.tk", "dynamic")
        await analyze([DOMAIN, duplicate], providers=[provider])
        assert len(provider.seen) == 1


class TestEnvelope:
    async def test_successful_run_is_ok_and_well_formed(self) -> None:
        provider = FakeProvider("bazaar", {IocType.hash}, families=["Cerberus"])
        envelope = await analyze(
            [HASH], providers=[provider], job_id="job-1", apk_sha256="a" * 64
        )
        assert envelope.status is Status.ok
        assert envelope.engine.name == ENGINE_NAME
        assert envelope.engine.version == ENGINE_VERSION
        assert envelope.job_id == "job-1"
        assert envelope.apk_sha256 == "a" * 64
        assert envelope.produced_at is not None
        assert envelope.errors == []

        types = {f.type for f in envelope.findings}
        assert FindingType.ioc_match in types
        assert FindingType.family_attribution in types

    async def test_evidence_records_per_provider_activity(self) -> None:
        provider = FakeProvider("bazaar", {IocType.hash})
        envelope = await analyze([HASH], providers=[provider])
        assert envelope.evidence["bazaar"] == {
            "live_calls": 1,
            "cache_hits": 0,
            "hits": 1,
            "circuit": "closed",
            "exhausted": False,
        }
        summary = envelope.evidence["summary"]
        assert summary["indicators"] == 1  # type: ignore[index]
        assert summary["malicious_indicators"] == 1  # type: ignore[index]
        assert summary["providers_consulted"] == ["bazaar"]  # type: ignore[index]

    async def test_clean_indicators_are_still_reported_as_evidence(self) -> None:
        provider = FakeProvider("p", {IocType.domain}, verdict=Verdict.benign, score=0.0)
        envelope = await analyze([DOMAIN], providers=[provider])
        assert envelope.findings == []
        indicators = envelope.evidence["indicators"]
        assert indicators[0]["verdict"] == "benign"  # type: ignore[index]
        assert envelope.status is Status.ok

    async def test_no_indicators_is_a_clean_no_op(self) -> None:
        provider = FakeProvider("p", {IocType.hash})
        envelope = await analyze([], providers=[provider])
        assert envelope.status is Status.ok
        assert envelope.findings == []
        assert provider.seen == []

    async def test_no_configured_providers_fails_loudly(self) -> None:
        # Silence here would read as "nothing found" to scoring and the analyst.
        envelope = await analyze([HASH], providers=[])
        assert envelope.status is Status.failed
        assert "No threat-intel providers" in envelope.errors[0].message


class TestCaching:
    async def test_a_cached_verdict_skips_the_network(self) -> None:
        cache = InMemoryCache()
        provider = FakeProvider("p", {IocType.hash})

        first = await analyze([HASH], providers=[provider], cache=cache)
        second = await analyze([HASH], providers=[provider], cache=cache)

        assert len(provider.seen) == 1  # only the first run called out
        assert first.iocs_cached == 0
        assert second.iocs_cached == 1
        assert second.evidence["p"]["live_calls"] == 0  # type: ignore[index]

    async def test_cached_verdicts_reproduce_the_original_findings(self) -> None:
        cache = InMemoryCache()
        provider = FakeProvider("p", {IocType.hash}, families=["Cerberus"])
        first = await analyze([HASH], providers=[provider], cache=cache)
        second = await analyze([HASH], providers=[provider], cache=cache)

        assert {f.id for f in first.findings} == {f.id for f in second.findings}
        match = next(f for f in second.findings if f.type is FindingType.ioc_match)
        # Cached provenance is flagged so an analyst can judge verdict freshness.
        assert match.provenance.cached is True

    async def test_negative_results_are_cached_too(self) -> None:
        # A "not found" answer is expensive to obtain and just as reusable.
        cache = InMemoryCache()
        provider = FakeProvider("p", {IocType.hash}, verdict=Verdict.unknown, score=0.0)
        await analyze([HASH], providers=[provider], cache=cache)
        assert await cache.get(HASH, "p") is not None

    async def test_cache_is_keyed_per_provider(self) -> None:
        cache = InMemoryCache()
        a = FakeProvider("a", {IocType.hash})
        b = FakeProvider("b", {IocType.hash})
        await analyze([HASH], providers=[a], cache=cache)
        await analyze([HASH], providers=[b], cache=cache)
        assert len(b.seen) == 1  # a's cached answer must not satisfy b

    async def test_cached_answers_survive_a_dead_provider(self) -> None:
        # Cache is checked before the circuit breaker, so an outage degrades to
        # "stale answers only" rather than "no answers".
        cache = InMemoryCache()
        await cache.put(
            HASH,
            "p",
            CachedVerdict(verdict=Verdict.malicious, raw={"_normalized": {"score": 1.0}}),
            ttl=3600,
        )
        provider = FakeProvider("p", {IocType.hash}, raises=ProviderUnavailableError)
        envelope = await analyze([HASH], providers=[provider], cache=cache)
        assert provider.seen == []
        assert any(f.type is FindingType.ioc_match for f in envelope.findings)


class TestFailureIsolation:
    async def test_one_failing_provider_degrades_to_partial(self) -> None:
        good = FakeProvider("good", {IocType.hash})
        bad = FakeProvider("bad", {IocType.hash}, raises=ProviderUnavailableError)
        envelope = await analyze([HASH], providers=[good, bad])

        assert envelope.status is Status.partial
        assert any(f.type is FindingType.ioc_match for f in envelope.findings)
        assert [e.extractor for e in envelope.errors] == ["bad"]

    async def test_every_provider_failing_is_a_failed_stage(self) -> None:
        bad = FakeProvider("bad", {IocType.hash}, raises=ProviderUnavailableError)
        envelope = await analyze([HASH], providers=[bad])
        assert envelope.status is Status.failed

    async def test_a_dead_provider_is_dropped_after_the_breaker_trips(self) -> None:
        # The point of the breaker: 50 indicators must not mean 50 timeouts.
        bad = FakeProvider("bad", {IocType.domain}, raises=ProviderUnavailableError)
        iocs = [Ioc(IocType.domain, f"c2-{i}.evil.tk") for i in range(50)]
        envelope = await analyze(iocs, providers=[bad], breaker_threshold=3, concurrency=1)
        assert len(bad.seen) <= 5
        assert envelope.evidence["bad"]["circuit"] == "open"  # type: ignore[index]

    async def test_rate_limiting_exhausts_a_provider_immediately(self) -> None:
        # Unlike a transient error, a 429 means stop now — no threshold to reach.
        limited = FakeProvider("limited", {IocType.domain}, raises=RateLimitedError)
        iocs = [Ioc(IocType.domain, f"c2-{i}.evil.tk") for i in range(20)]
        envelope = await analyze(iocs, providers=[limited], concurrency=1)
        assert len(limited.seen) == 1
        assert envelope.evidence["limited"]["exhausted"] is True  # type: ignore[index]

    async def test_unexpected_exceptions_are_contained(self) -> None:
        broken = FakeProvider("broken", {IocType.hash}, raises=ValueError)
        envelope = await analyze([HASH], providers=[broken])
        assert envelope.status is Status.failed
        assert "unexpected ValueError" in envelope.errors[0].message

    async def test_repeated_identical_errors_collapse_to_one_message(self) -> None:
        bad = FakeProvider("bad", {IocType.domain}, raises=ProviderUnavailableError)
        iocs = [Ioc(IocType.domain, f"c2-{i}.evil.tk") for i in range(10)]
        envelope = await analyze(iocs, providers=[bad], breaker_threshold=99, concurrency=1)
        assert len([e for e in envelope.errors if e.extractor == "bad"]) == 1


class TestBudget:
    async def test_the_lookup_ceiling_is_enforced_and_disclosed(self) -> None:
        provider = FakeProvider("p", {IocType.domain})
        iocs = [Ioc(IocType.domain, f"c2-{i}.evil.tk") for i in range(20)]
        envelope = await analyze(iocs, providers=[provider], max_lookups=5)

        assert len(provider.seen) == 5
        # Truncation must be visible — a quietly shortened run reads as "clean".
        assert envelope.status is Status.partial
        assert "budget of 5 exhausted" in envelope.errors[0].message
        assert "15 indicator/provider pair(s)" in envelope.errors[0].message

    async def test_the_budget_is_shared_across_providers(self) -> None:
        a = FakeProvider("a", {IocType.domain})
        b = FakeProvider("b", {IocType.domain})
        iocs = [Ioc(IocType.domain, f"c2-{i}.evil.tk") for i in range(10)]
        await analyze(iocs, providers=[a, b], max_lookups=6, concurrency=1)
        assert len(a.seen) + len(b.seen) == 6

    async def test_cache_hits_do_not_consume_the_budget(self) -> None:
        cache = InMemoryCache()
        provider = FakeProvider("p", {IocType.domain})
        iocs = [Ioc(IocType.domain, f"c2-{i}.evil.tk") for i in range(5)]
        await analyze(iocs, providers=[provider], cache=cache, max_lookups=5)
        # Second run is entirely cached, so nothing is truncated even at budget 0.
        envelope = await analyze(iocs, providers=[provider], cache=cache, max_lookups=0)
        assert envelope.status is Status.ok
        assert envelope.iocs_cached == 5
