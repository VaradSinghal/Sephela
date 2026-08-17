"""Job status API — list, retrieve, cancel (Phase 4; secured in Phase 14).

Every lookup here is scoped to the caller's organisation. That scoping is done by
passing ``org_id`` into the repository rather than by filtering after the fetch, so
a missed check is a missing argument (visible) rather than a forgotten ``if``
(invisible). A job belonging to another tenant returns 404, not 403: telling an
outsider that job X exists but is not theirs is itself a disclosure.

Role requirements follow docs/architecture/09-security.md — viewers may read status
and findings; raw evidence and state changes need analyst or above.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Query, Request

from app.api.deps import DbSession
from app.core.exceptions import ConflictError, NotFoundError
from app.core.security import AnalystDep, ViewerDep
from app.db.models.analysis import AnalysisJob, JobStatus
from app.db.models.audit import AuditAction
from app.repositories.audit import AuditRepository
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
        risk_score=job.risk_score,
        risk_tier=job.risk_tier,
    )


async def _require_job(
    session: DbSession, job_id: uuid.UUID, org_id: uuid.UUID | None
) -> AnalysisJob:
    """Fetch a job within the caller's tenant or raise 404."""
    job = await JobRepository(session).get(job_id, org_id=org_id)
    if job is None:
        raise NotFoundError("Job not found.")
    return job


@router.get("", response_model=JobListOut)
async def list_jobs(
    session: DbSession,
    user: ViewerDep,
    status: Annotated[list[JobStatus] | None, Query()] = None,
    limit: int = Query(50, ge=1, le=200),
) -> JobListOut:
    """List jobs, newest first.

    ``status`` is repeatable (``?status=completed&status=partial``) because the
    groupings a client wants are not single states — a job that skipped a stage is
    ``partial`` and still has a report.
    """
    jobs = await JobRepository(session).list(status=status, limit=limit, org_id=user.org_uuid)
    return JobListOut(items=[_to_out(j) for j in jobs], next_cursor=None)


@router.get("/{job_id}", response_model=JobOut)
async def get_job(session: DbSession, user: ViewerDep, job_id: uuid.UUID) -> JobOut:
    return _to_out(await _require_job(session, job_id, user.org_uuid))


@router.get("/{job_id}/stages", response_model=list[StageDetailOut])
async def get_job_stages(
    session: DbSession, user: ViewerDep, job_id: uuid.UUID
) -> list[StageDetailOut]:
    """Per-stage status, with the error/skip reason each stage recorded."""
    job = await _require_job(session, job_id, user.org_uuid)
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
    user: AnalystDep,
    request: Request,
    job_id: uuid.UUID,
    engine: str | None = Query(None, description="Filter to one engine, e.g. 'dynamic'"),
) -> EvidenceListOut:
    """Raw Evidence Envelopes for a job (docs/architecture/06-api-spec.md).

    Analyst-gated and audited: envelopes contain decompiled strings and captured
    traffic from a live malware sample, which is the most sensitive data the
    platform holds. Access is the event worth recording, not just modification.
    """
    await _require_job(session, job_id, user.org_uuid)
    rows = await EvidenceRepository(session).list_for_job(job_id, engine=engine)

    await AuditRepository(session).record(
        AuditAction.evidence_accessed,
        actor_id=uuid.UUID(user.id),
        actor_email=user.email,
        org_id=user.org_uuid,
        target_type="job",
        target_id=str(job_id),
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        trace_id=getattr(request.state, "trace_id", None),
        detail={"engine": engine, "envelopes": len(rows)},
    )

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
    user: ViewerDep,
    job_id: uuid.UUID,
    type: str | None = None,
    severity: str | None = None,
    limit: int = Query(200, ge=1, le=1000),
) -> FindingListOut:
    """Normalized findings for a job, filterable by type and severity.

    Viewer-readable: findings are the triaged conclusions, already free of the raw
    sample-derived content that gates ``/evidence`` behind analyst.
    """
    await _require_job(session, job_id, user.org_uuid)
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
async def cancel_job(
    session: DbSession, user: AnalystDep, request: Request, job_id: uuid.UUID
) -> JobOut:
    job = await _require_job(session, job_id, user.org_uuid)
    if job.status not in _ACTIVE:
        raise ConflictError(f"Job in status '{job.status.value}' cannot be cancelled.")

    job.status = JobStatus.cancelled
    job.completed_at = datetime.now(UTC)

    await AuditRepository(session).record(
        AuditAction.job_cancelled,
        actor_id=uuid.UUID(user.id),
        actor_email=user.email,
        org_id=user.org_uuid,
        target_type="job",
        target_id=str(job_id),
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        trace_id=getattr(request.state, "trace_id", None),
    )
    await session.commit()
    return _to_out(job)
