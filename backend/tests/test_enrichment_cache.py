"""Enrichment cache semantics (app.repositories.enrichment).

The cache is what makes threat-intel affordable on metered free tiers, so its
edge cases are load-bearing: what counts as a miss, how long an entry lives, and
what happens when a stored row no longer matches the current verdict vocabulary.

A fake session stands in for Postgres — these are tests of the repository's
decisions, not of SQLAlchemy's emitted SQL.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from sephela_threat_intel.base import Verdict
from sephela_threat_intel.cache import CachedVerdict
from sephela_threat_intel.iocs import Ioc, IocType

from app.db.models.analysis import Enrichment
from app.repositories.enrichment import MAX_IOC_VALUE_CHARS, EnrichmentCacheRepository

DOMAIN = Ioc(IocType.domain, "c2.evil.tk", "static")
JOB_ID = uuid.uuid4()


class FakeResult:
    def __init__(self, row: Any) -> None:
        self._row = row

    def scalar_one_or_none(self) -> Any:
        return self._row


class FakeSession:
    """Records added rows and returns a canned row for queries."""

    def __init__(self, row: Any = None) -> None:
        self.row = row
        self.added: list[Any] = []
        self.flushed = 0

    async def execute(self, _stmt: Any) -> FakeResult:
        return FakeResult(self.row)

    def add(self, obj: Any) -> None:
        self.added.append(obj)

    async def flush(self) -> None:
        self.flushed += 1


def fresh_row(**overrides: Any) -> Enrichment:
    defaults: dict[str, Any] = {
        "id": uuid.uuid4(),
        "job_id": JOB_ID,
        "ioc_type": "domain",
        "ioc_value": DOMAIN.value,
        "provider": "urlhaus",
        "verdict": "malicious",
        "raw": {"found": True, "_normalized": {"score": 1.0}},
        "fetched_at": datetime.now(timezone.utc),
        "expires_at": datetime.now(timezone.utc) + timedelta(hours=1),
    }
    return Enrichment(**{**defaults, **overrides})


@pytest.fixture
def repo_factory():  # type: ignore[no-untyped-def]
    def _factory(row: Any = None, *, ttl_factor: float = 1.0):  # type: ignore[no-untyped-def]
        session = FakeSession(row)
        repo = EnrichmentCacheRepository(
            session,  # type: ignore[arg-type]
            job_id=JOB_ID,
            ttl_factor=ttl_factor,
        )
        return repo, session

    return _factory


class TestGet:
    async def test_a_fresh_row_is_a_hit(self, repo_factory) -> None:  # type: ignore[no-untyped-def]
        repo, _ = repo_factory(fresh_row())
        entry = await repo.get(DOMAIN, "urlhaus")
        assert entry is not None
        assert entry.verdict is Verdict.malicious
        assert entry.raw["found"] is True

    async def test_no_row_is_a_miss(self, repo_factory) -> None:  # type: ignore[no-untyped-def]
        repo, _ = repo_factory(None)
        assert await repo.get(DOMAIN, "urlhaus") is None

    async def test_a_row_without_a_verdict_is_a_miss(self, repo_factory) -> None:  # type: ignore[no-untyped-def]
        repo, _ = repo_factory(fresh_row(verdict=None))
        assert await repo.get(DOMAIN, "urlhaus") is None

    async def test_an_unrecognized_verdict_is_a_miss_not_a_crash(self, repo_factory) -> None:  # type: ignore[no-untyped-def]
        # A verdict vocabulary change must invalidate old entries, not break the
        # stage on rows written by an earlier version.
        repo, _ = repo_factory(fresh_row(verdict="probably-bad"))
        assert await repo.get(DOMAIN, "urlhaus") is None

    async def test_a_null_raw_payload_still_rehydrates(self, repo_factory) -> None:  # type: ignore[no-untyped-def]
        repo, _ = repo_factory(fresh_row(raw=None))
        entry = await repo.get(DOMAIN, "urlhaus")
        assert entry is not None
        assert entry.raw == {}

    async def test_the_rehydrated_entry_reconstructs_the_normalized_fields(
        self, repo_factory
    ) -> None:  # type: ignore[no-untyped-def]
        raw = {
            "found": True,
            "_normalized": {
                "score": 0.9,
                "families": ["Cerberus"],
                "signatures": ["Vendor: X"],
                "actors": [],
                "summary": "listed",
            },
        }
        repo, _ = repo_factory(fresh_row(raw=raw))
        entry = await repo.get(DOMAIN, "urlhaus")
        assert entry is not None

        result = entry.to_result(DOMAIN, "urlhaus")
        assert result.score == 0.9
        assert result.families == ["Cerberus"]
        assert result.cached is True


class TestPut:
    async def test_a_verdict_is_written_with_its_ttl(self, repo_factory) -> None:  # type: ignore[no-untyped-def]
        repo, session = repo_factory()
        before = datetime.now(timezone.utc)

        await repo.put(
            DOMAIN, "urlhaus", CachedVerdict(verdict=Verdict.malicious, raw={"a": 1}), ttl=3600
        )

        assert session.flushed == 1
        row = session.added[0]
        assert row.ioc_type == "domain"
        assert row.ioc_value == DOMAIN.value
        assert row.provider == "urlhaus"
        assert row.verdict == "malicious"
        assert row.job_id == JOB_ID  # per-job audit trail
        assert row.expires_at >= before + timedelta(seconds=3595)

    async def test_the_ttl_factor_scales_the_lifetime(self, repo_factory) -> None:  # type: ignore[no-untyped-def]
        # The deployment's quota, not the engine, decides how long to trust a
        # verdict.
        repo, session = repo_factory(ttl_factor=2.0)
        await repo.put(DOMAIN, "urlhaus", CachedVerdict(Verdict.benign, {}), ttl=1000)

        row = session.added[0]
        lifetime = (row.expires_at - row.fetched_at).total_seconds()
        assert lifetime == pytest.approx(2000, abs=2)

    async def test_a_zero_ttl_factor_expires_immediately(self, repo_factory) -> None:  # type: ignore[no-untyped-def]
        # An operator disabling reuse must not accidentally get immortal entries.
        repo, session = repo_factory(ttl_factor=0.0)
        await repo.put(DOMAIN, "urlhaus", CachedVerdict(Verdict.benign, {}), ttl=3600)

        row = session.added[0]
        assert row.expires_at == row.fetched_at

    async def test_negative_ttls_are_clamped(self, repo_factory) -> None:  # type: ignore[no-untyped-def]
        repo, session = repo_factory()
        await repo.put(DOMAIN, "urlhaus", CachedVerdict(Verdict.benign, {}), ttl=-10)

        row = session.added[0]
        assert row.expires_at == row.fetched_at

    async def test_oversized_indicator_values_are_truncated(self, repo_factory) -> None:  # type: ignore[no-untyped-def]
        long_url = Ioc(IocType.url, "http://evil.tk/" + "a" * 5000)
        repo, session = repo_factory()
        await repo.put(long_url, "urlhaus", CachedVerdict(Verdict.malicious, {}), ttl=60)

        assert len(session.added[0].ioc_value) == MAX_IOC_VALUE_CHARS

    async def test_negative_results_are_stored_too(self, repo_factory) -> None:  # type: ignore[no-untyped-def]
        # "Not found" costs a real API call and is just as reusable as a hit.
        repo, session = repo_factory()
        await repo.put(DOMAIN, "urlhaus", CachedVerdict(Verdict.unknown, {"found": False}), ttl=60)

        assert session.added[0].verdict == "unknown"


class TestProtocolConformance:
    def test_the_repository_satisfies_the_engine_cache_protocol(self) -> None:
        # The engine depends on the protocol, never on the backend — this is the
        # seam that keeps it a pure function of its inputs.
        from sephela_threat_intel.cache import EnrichmentCache

        repo = EnrichmentCacheRepository(FakeSession())  # type: ignore[arg-type]
        assert isinstance(repo, EnrichmentCache)
