"""Threat-intelligence stage (Phase 11) — IoCs → external feeds → Evidence Envelope.

DFD-6 (docs/architecture/07-data-flow.md)::

    job (static/dynamic evidence present) → q.threat_intel → harvest IoCs from
    normalized findings → cache lookup → rate-limited provider calls → correlate
    verdicts → Evidence Envelope + enrichment rows

This task is the *adapter*, mirroring ``app.tasks.dynamic``: it gathers the
indicators, hands them to ``sephela_threat_intel.analyze()`` with a
Postgres-backed cache, and lets ``StageRunner`` persist the result. It holds no
analysis logic.

Failure policy — enrichment is best-effort, so nothing here fails the job:
disabled by policy → ``skipped``; no providers configured or engine missing →
``failed`` stage, job continues. Per docs/architecture/05-messaging.md the
threat-intel stage runs in parallel with AI analysis and neither blocks the other,
so a feed outage costs coverage, never the run.

The stage is *cheap to retry* by design: every verdict fetched on the first
attempt is cached, so a retry re-queries only what genuinely failed.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.logging import get_logger
from app.db.models.analysis import AnalysisJob, JobStatus, Sample, StageStatus
from app.db.session import AsyncSessionLocal
from app.repositories.enrichment import EnrichmentCacheRepository
from app.services.stages import StageOutcome, StageRunner
from app.services.threat_intel import (
    ThreatIntelUnavailableError,
    build_providers,
    engine_module,
    gather_iocs,
)
from app.tasks.celery_app import celery_app

logger = get_logger(__name__)

ENGINE_NAME = "threat_intel"
# Fallback when the engine package isn't importable; the real version is read
# from sephela_threat_intel at runtime.
_UNKNOWN_VERSION = "0.0.0"


async def _run(job_id: str) -> str:
    jid = uuid.UUID(job_id)

    async with AsyncSessionLocal() as session:
        job = await session.get(AnalysisJob, jid)
        if job is None:
            logger.warning("threat_intel_job_missing", job_id=job_id)
            return "missing"
        if job.status == JobStatus.cancelled:
            return JobStatus.cancelled.value

        sample = await session.get(Sample, job.sample_id)
        if sample is None:  # pragma: no cover — FK guarantees this
            logger.warning("threat_intel_sample_missing", job_id=job_id)
            return "missing"

        # Resolve the engine before claiming the stage, so a missing install is
        # reported against a truthful version string.
        try:
            engine, engine_version = engine_module()
        except ThreatIntelUnavailableError as exc:
            stage = StageRunner(
                session, jid, engine_name=ENGINE_NAME, engine_version=_UNKNOWN_VERSION
            )
            await stage.begin()
            return (await stage.fail(exc)).status.value

        stage = StageRunner(
            session, jid, engine_name=ENGINE_NAME, engine_version=engine_version
        )
        outcome = await _execute(
            session=session, stage=stage, engine=engine, job_id=job_id, jid=jid, sample=sample
        )
        return outcome.status.value


async def _execute(
    *,
    session: AsyncSession,
    stage: StageRunner,
    engine: Any,
    job_id: str,
    jid: uuid.UUID,
    sample: Sample,
) -> StageOutcome:
    """Run the engine, mapping every failure onto a stage status."""
    # Policy gate first — skip before spending a query on indicators nobody will
    # look up.
    if not settings.threat_intel_enabled:
        await stage.begin()
        return await stage.skip(
            "Threat-intel enrichment is disabled (SEPHELA_THREAT_INTEL_ENABLED)."
        )

    providers = build_providers()
    if not providers:
        await stage.begin()
        return await stage.fail(
            "No threat-intel providers are configured — set at least one provider API key."
        )

    await stage.begin()

    try:
        iocs = await gather_iocs(session, jid, sample)
    except Exception as exc:  # noqa: BLE001 — a query failure must not kill the job
        logger.exception("threat_intel_ioc_error", job_id=job_id)
        return await stage.fail(exc)

    if not iocs:
        # Upstream stages found nothing enrichable. Recorded as a skip so the job
        # detail page explains the empty result rather than implying a clean bill
        # of health from feeds that were never asked.
        return await stage.skip(
            "No enrichable indicators were found in upstream evidence."
        )

    cache = EnrichmentCacheRepository(
        session,
        job_id=jid,
        ttl_factor=settings.threat_intel_cache_ttl_factor,
    )

    try:
        envelope = await engine.analyze(
            iocs,
            providers=providers,
            cache=cache,
            job_id=job_id,
            apk_sha256=sample.sha256,
            max_lookups=settings.threat_intel_max_lookups,
            concurrency=settings.threat_intel_concurrency,
            timeout_secs=settings.threat_intel_timeout_secs,
            breaker_threshold=settings.threat_intel_breaker_threshold,
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("threat_intel_engine_error", job_id=job_id)
        return await stage.fail(exc)

    return await stage.complete(envelope.model_dump(mode="json"))


@celery_app.task(
    name="threat_intel.analyze",
    queue="threat_intel",
    bind=True,
    max_retries=2,
    default_retry_delay=120,
    acks_late=True,
    # Bounded by the lookup budget × provider pacing rather than by compute.
    # VirusTotal's free tier is 4 requests/minute, so a fully uncached run of a
    # couple of hundred indicators legitimately takes tens of minutes.
    soft_time_limit=30 * 60,
    time_limit=35 * 60,
)
def analyze_threat_intel(self, job_id: str) -> str:  # type: ignore[no-untyped-def]
    """Threat-intel stage for a job. Best-effort: records, never re-raises.

    Returns the resulting stage status so a Celery chain can observe it.
    """
    try:
        return asyncio.run(_run(job_id))
    except Exception:  # noqa: BLE001
        # Everything recoverable is already mapped to a stage status inside
        # _run; reaching here means infrastructure trouble (DB down, etc.).
        logger.exception("threat_intel_task_error", job_id=job_id)
        return StageStatus.failed.value
