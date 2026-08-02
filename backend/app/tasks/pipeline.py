"""Analysis pipeline orchestration.

Owns the DAG, not the analysis: each stage is an idempotent Celery task that
loads its own inputs from DB/storage, writes an Evidence Envelope, and sets its
own stage status. This module sequences them and derives the job's terminal
status from what the stages actually achieved.

Current shape (docs/architecture/05-messaging.md):

    intake (validate/hash/dedup/persist — done in the API)
      └─ chain:
           dynamic_analysis      (Phase 10, policy-gated parallel branch)
           → finalize            (aggregate stage statuses → job status)

Stages for static, code_intel, ai, threat_intel, scoring, and reporting slot in
between as their phases land; ``finalize`` already aggregates whatever ran.

Every task is DB-driven and never trusts the previous message payload beyond the
job id, so runs are safe to retry and resume.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone

from celery import chain
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.core.logging import get_logger
from app.db.models.analysis import AnalysisJob, JobStatus, StageRun, StageStatus
from app.db.session import AsyncSessionLocal
from app.tasks.celery_app import celery_app
from app.tasks.dynamic import analyze_dynamic

logger = get_logger(__name__)

# Terminal states a job must not be dragged out of by a late stage.
_TERMINAL = (JobStatus.completed, JobStatus.cancelled, JobStatus.failed)


def derive_job_status(stages: list[StageRun]) -> JobStatus:
    """Roll per-stage outcomes up into the job's terminal status.

    - no stage did any work           → ``completed`` (nothing was asked of it)
    - every attempted stage failed    → ``failed``
    - any partial, failure, or skip   → ``partial`` (analysis is incomplete)
    - all attempted stages ``ok``     → ``completed``
    """
    attempted = [s for s in stages if s.status is not StageStatus.skipped]
    if not attempted:
        return JobStatus.completed

    statuses = {s.status for s in attempted}
    if statuses == {StageStatus.failed}:
        return JobStatus.failed
    if statuses <= {StageStatus.ok}:
        # A skipped stage still means the job is missing evidence it could have had.
        return JobStatus.completed if len(attempted) == len(stages) else JobStatus.partial
    return JobStatus.partial


def _stage_errors(stages: list[StageRun]) -> str | None:
    parts = [f"{s.engine_name}: {s.error}" for s in stages if s.error and s.status.value != "ok"]
    return "; ".join(parts)[:4000] if parts else None


async def _start(job_id: str) -> str:
    """Claim the job and mark it running (idempotent)."""
    async with AsyncSessionLocal() as session:
        job = (
            await session.execute(select(AnalysisJob).where(AnalysisJob.id == uuid.UUID(job_id)))
        ).scalar_one_or_none()
        if job is None:
            logger.warning("pipeline_job_missing", job_id=job_id)
            return "missing"
        if job.status in _TERMINAL:
            return job.status.value  # idempotent no-op

        job.status = JobStatus.running
        job.started_at = datetime.now(timezone.utc)
        job.progress = 0
        await session.commit()
        logger.info("pipeline_started", job_id=job_id)
        return job.status.value


async def _finalize(job_id: str) -> str:
    async with AsyncSessionLocal() as session:
        job = (
            await session.execute(
                select(AnalysisJob)
                .where(AnalysisJob.id == uuid.UUID(job_id))
                .options(selectinload(AnalysisJob.stages))
            )
        ).scalar_one_or_none()
        if job is None:
            logger.warning("pipeline_job_missing", job_id=job_id)
            return "missing"
        if job.status in _TERMINAL:
            return job.status.value

        stages = list(job.stages)
        job.status = derive_job_status(stages)
        job.error = _stage_errors(stages)
        job.progress = 100
        job.completed_at = datetime.now(timezone.utc)
        await session.commit()
        logger.info(
            "pipeline_finalized",
            job_id=job_id,
            status=job.status.value,
            stages={s.engine_name: s.status.value for s in stages},
        )
        return job.status.value


@celery_app.task(
    name="pipeline.analyze",
    queue="intake",
    bind=True,
    max_retries=3,
    default_retry_delay=10,
    acks_late=True,
)
def analyze(self, job_id: str) -> str:  # type: ignore[no-untyped-def]
    """Entrypoint task for a job: claim it, then dispatch the stage chain."""
    try:
        claimed = asyncio.run(_start(job_id))
    except Exception as exc:  # noqa: BLE001
        logger.exception("pipeline_error", job_id=job_id)
        raise self.retry(exc=exc) from exc

    if claimed != JobStatus.running.value:
        return claimed  # missing, or already terminal

    # Immutable signatures (.si) — each stage re-reads state from the DB rather
    # than consuming the previous task's return value.
    stages = []
    if settings.dynamic_enabled:
        stages.append(analyze_dynamic.si(job_id))
    stages.append(finalize.si(job_id))

    chain(*stages).apply_async()
    logger.info("pipeline_dispatched", job_id=job_id, dynamic=settings.dynamic_enabled)
    return JobStatus.running.value


@celery_app.task(
    name="pipeline.finalize",
    queue="intake",
    bind=True,
    max_retries=3,
    default_retry_delay=10,
    acks_late=True,
)
def finalize(self, job_id: str) -> str:  # type: ignore[no-untyped-def]
    """Aggregate stage outcomes into the job's terminal status."""
    try:
        return asyncio.run(_finalize(job_id))
    except Exception as exc:  # noqa: BLE001
        logger.exception("pipeline_finalize_error", job_id=job_id)
        raise self.retry(exc=exc) from exc
