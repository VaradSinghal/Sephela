"""Data access for threat-intel enrichments — and the engine's durable cache.

``EnrichmentCacheRepository`` implements the engine's ``EnrichmentCache`` protocol
(``sephela_threat_intel.cache``) over the ``enrichments`` table. The engine holds
no database dependency; this class is the adapter, which is what lets the engine's
own tests run against an in-memory cache.

Two design decisions worth stating outright:

**Reads ignore ``job_id``.** The cache is global on purpose. Campaign samples
share C2 infrastructure, so the same domain recurs across jobs and tenants, and
re-paying for a verdict we already hold would make the engine unaffordable on
free provider tiers. Verdicts are facts about public indicators, not tenant data,
so sharing them across orgs leaks nothing — but note that a *cache hit* does
reveal that some other job asked about the same indicator, which is why the
per-job audit row is still written (see ``record``).

**Expired rows are kept, not deleted.** A completed job is immutable and its
report must remain reproducible, so the row that justified a finding stays as
audit evidence even once it is too stale to reuse. Pruning is a retention
concern, handled separately.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.db.models.analysis import Enrichment

if TYPE_CHECKING:  # pragma: no cover — engine is an optional worker dependency
    from sephela_threat_intel.cache import CachedVerdict
    from sephela_threat_intel.iocs import Ioc

logger = get_logger(__name__)

#: ``enrichments.ioc_value`` is unbounded TEXT, but an indicator longer than this
#: is not a real one — cap it so a pathological string cannot bloat the table.
MAX_IOC_VALUE_CHARS = 2048


class EnrichmentCacheRepository:
    """Postgres-backed implementation of the engine's ``EnrichmentCache``.

    Instantiated per stage run with the job it is enriching, so every live lookup
    also leaves a per-job audit row.
    """

    def __init__(
        self,
        session: AsyncSession,
        *,
        job_id: uuid.UUID | None = None,
        ttl_factor: float = 1.0,
    ) -> None:
        self.session = session
        self.job_id = job_id
        # The engine decides a sensible TTL per indicator class; the deployment
        # decides how much it trusts that against its own quota. Applied here
        # rather than in the engine so the engine stays free of config.
        self.ttl_factor = max(0.0, ttl_factor)

    async def get(self, ioc: Ioc, provider: str) -> CachedVerdict | None:
        """Return the freshest non-expired verdict for this indicator/provider.

        Rows with a NULL ``expires_at`` are treated as expired rather than
        immortal: a missing TTL means the row predates a TTL policy, and silently
        serving it forever would pin a verdict that may be years stale.
        """
        from sephela_threat_intel.cache import CachedVerdict

        now = datetime.now(timezone.utc)
        stmt = (
            select(Enrichment)
            .where(
                Enrichment.ioc_type == ioc.type.value,
                Enrichment.ioc_value == ioc.value[:MAX_IOC_VALUE_CHARS],
                Enrichment.provider == provider,
                Enrichment.expires_at.is_not(None),
                Enrichment.expires_at > now,
            )
            .order_by(Enrichment.fetched_at.desc())
            .limit(1)
        )
        row = (await self.session.execute(stmt)).scalar_one_or_none()
        if row is None or row.verdict is None:
            return None

        from sephela_threat_intel.base import Verdict

        try:
            verdict = Verdict(row.verdict)
        except ValueError:
            # A verdict vocabulary change should invalidate the entry, not crash
            # the stage.
            logger.warning("enrichment_cache_unknown_verdict", verdict=row.verdict)
            return None

        raw: dict[str, Any] = row.raw if isinstance(row.raw, dict) else {}
        return CachedVerdict(verdict=verdict, raw=raw)

    async def put(
        self, ioc: Ioc, provider: str, entry: CachedVerdict, *, ttl: int
    ) -> None:
        """Persist a freshly fetched verdict, tagged to the job that fetched it.

        Always inserts rather than upserting: the row is simultaneously the cache
        entry and the per-job audit record of what this job asked and was told.
        ``get`` reads the newest row, so an insert supersedes older entries
        without destroying the history that a completed job's report depends on.
        """
        now = datetime.now(timezone.utc)
        effective_ttl = int(max(0, ttl) * self.ttl_factor)
        self.session.add(
            Enrichment(
                id=uuid.uuid4(),
                job_id=self.job_id,
                ioc_type=ioc.type.value,
                ioc_value=ioc.value[:MAX_IOC_VALUE_CHARS],
                provider=provider[:32],
                verdict=entry.verdict.value,
                raw=entry.raw,
                fetched_at=now,
                expires_at=now + timedelta(seconds=effective_ttl),
            )
        )
        await self.session.flush()


class EnrichmentRepository:
    """Read access to enrichments for the API/report layers."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def list_for_job(
        self, job_id: uuid.UUID, *, provider: str | None = None, limit: int = 500
    ) -> list[Enrichment]:
        stmt = (
            select(Enrichment)
            .where(Enrichment.job_id == job_id)
            .order_by(Enrichment.fetched_at.asc())
            .limit(limit)
        )
        if provider is not None:
            stmt = stmt.where(Enrichment.provider == provider)
        return list((await self.session.execute(stmt)).scalars().all())

    async def history_for_ioc(
        self, ioc_type: str, ioc_value: str, *, limit: int = 20
    ) -> list[Enrichment]:
        """Every verdict ever recorded for one indicator, newest first.

        This is the pivot an analyst uses to spot infrastructure reuse: the same
        C2 domain appearing across several jobs is a campaign, not a coincidence.
        """
        stmt = (
            select(Enrichment)
            .where(
                Enrichment.ioc_type == ioc_type,
                Enrichment.ioc_value == ioc_value[:MAX_IOC_VALUE_CHARS],
            )
            .order_by(Enrichment.fetched_at.desc())
            .limit(limit)
        )
        return list((await self.session.execute(stmt)).scalars().all())
