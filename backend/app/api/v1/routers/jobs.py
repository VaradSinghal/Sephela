"""Job status API (Phase 4) — list, retrieve, cancel."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Query

from app.api.deps import DbSession
from app.core.exceptions import ConflictError, NotFoundError
from app.core.security import CurrentUserDep
from app.db.models.analysis import AnalysisJob, JobStatus
from app.repositories.evidence import EvidenceRepository, FindingRepository
from app.repositories.samples import JobRepository
from app.schemas.jobs import (
    EvidenceListOut,
    EvidenceOut,
    FindingListOut,
    FindingOut,
    JobListOut,
    JobOut,
    StageDetailOut,
    StageOut,
)

router = APIRouter(prefix="/jobs", tags=["jobs"])

_ACTIVE = {JobStatus.queued, JobStatus.running}


def _to_out(job: AnalysisJob) -> JobOut:
    return JobOut(
        job_id=job.id,
        sample_id=job.sample_id,
        status=job.status,
        progress=job.progress,
        pipeline_version=job.pipeline_version,
        stages=[
            StageOut(
                engine=s.engine_name,
                status=s.status,
                started_at=s.started_at,
                finished_at=s.finished_at,
            )
            for s in sorted(job.stages, key=lambda s: s.created_at)
        ],
        error=job.error,
        created_at=job.created_at,
    )


@router.get("", response_model=JobListOut)
async def list_jobs(
    session: DbSession,
    _user: CurrentUserDep,
    status: JobStatus | None = None,
    limit: int = Query(50, ge=1, le=200),
) -> JobListOut:
    jobs = await JobRepository(session).list(status=status, limit=limit)
    return JobListOut(items=[_to_out(j) for j in jobs], next_cursor=None)


@router.get("/{job_id}", response_model=JobOut)
async def get_job(session: DbSession, _user: CurrentUserDep, job_id: uuid.UUID) -> JobOut:
    job = await JobRepository(session).get(job_id)
    if job is None:
        raise NotFoundError("Job not found.")
    return _to_out(job)


@router.get("/{job_id}/stages", response_model=list[StageDetailOut])
async def get_job_stages(
    session: DbSession, _user: CurrentUserDep, job_id: uuid.UUID
) -> list[StageDetailOut]:
    """Per-stage status, with the error/skip reason each stage recorded."""
    job = await JobRepository(session).get(job_id)
    if job is None:
        raise NotFoundError("Job not found.")
    return [
        StageDetailOut(
            engine=s.engine_name,
            engine_version=s.engine_version,
            status=s.status,
            attempt=s.attempt,
            started_at=s.started_at,
            finished_at=s.finished_at,
            error=s.error,
        )
        for s in sorted(job.stages, key=lambda s: s.created_at)
    ]


@router.get("/{job_id}/evidence", response_model=EvidenceListOut)
async def get_job_evidence(
    session: DbSession,
    _user: CurrentUserDep,
    job_id: uuid.UUID,
    engine: str | None = Query(None, description="Filter to one engine, e.g. 'dynamic'"),
) -> EvidenceListOut:
    """Raw Evidence Envelopes for a job (docs/architecture/06-api-spec.md)."""
    if await JobRepository(session).get(job_id) is None:
        raise NotFoundError("Job not found.")
    rows = await EvidenceRepository(session).list_for_job(job_id, engine=engine)
    return EvidenceListOut(
        items=[
            EvidenceOut(
                evidence_id=r.id,
                engine=r.engine_name,
                envelope_version=r.envelope_version,
                payload=r.payload,
                large_artifact_uri=r.large_artifact_uri,
                created_at=r.created_at,
            )
            for r in rows
        ]
    )


@router.get("/{job_id}/findings", response_model=FindingListOut)
async def get_job_findings(
    session: DbSession,
    _user: CurrentUserDep,
    job_id: uuid.UUID,
    type: str | None = None,
    severity: str | None = None,
    limit: int = Query(200, ge=1, le=1000),
) -> FindingListOut:
    """Normalized findings for a job, filterable by type and severity."""
    if await JobRepository(session).get(job_id) is None:
        raise NotFoundError("Job not found.")
    rows = await FindingRepository(session).list_for_job(
        job_id, type_=type, severity=severity, limit=limit
    )
    items = [
        FindingOut(
            finding_id=r.finding_id,
            source_engine=r.source_engine,
            type=r.type,
            severity=r.severity,
            confidence=r.confidence,
            detail=r.detail,
            provenance=r.provenance,
            mitre=list(r.mitre or []),
            owasp_mobile=list(r.owasp_mobile or []),
        )
        for r in rows
    ]
    return FindingListOut(items=items, total=len(items))


@router.post("/{job_id}/cancel", response_model=JobOut)
async def cancel_job(session: DbSession, _user: CurrentUserDep, job_id: uuid.UUID) -> JobOut:
    repo = JobRepository(session)
    job = await repo.get(job_id)
    if job is None:
        raise NotFoundError("Job not found.")
    if job.status not in _ACTIVE:
        raise ConflictError(f"Job in status '{job.status.value}' cannot be cancelled.")
    job.status = JobStatus.cancelled
    job.completed_at = datetime.now(timezone.utc)
    await session.commit()
    return _to_out(job)
