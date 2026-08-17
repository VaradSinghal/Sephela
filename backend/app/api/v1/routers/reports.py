"""Report API — the structured report and its rendered artifacts (Phase 9).

Two endpoints, split by cost and by audience:

``GET /jobs/{id}/report``
    The structured report: the score, its per-domain decomposition, the synergy
    rules that fired, and the findings. Viewer-readable, because it is the
    triaged conclusion rather than raw sample-derived content — the same
    reasoning that puts ``/findings`` behind viewer and ``/evidence`` behind
    analyst.

``GET /jobs/{id}/report/{format}``
    Streams one rendered artifact from object storage. Audited: a report leaving
    the platform as a file is the moment analysis becomes something forwarded to
    a regulator or an external party, which is worth being able to reconstruct
    later even though reading the same report in-app is not.

Both resolve the job through ``_require_job``, so tenant scoping and the
404-rather-than-403 rule are inherited from the jobs router rather than
reimplemented here.
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Request, Response

from app.api.deps import DbSession, Storage
from app.core.exceptions import NotFoundError
from app.core.logging import get_logger
from app.core.security import ViewerDep
from app.db.models.analysis import Evidence
from app.db.models.audit import AuditAction
from app.repositories.audit import AuditRepository
from app.repositories.evidence import EvidenceRepository
from app.repositories.samples import JobRepository
from app.schemas.reports import ReportOut, ScoreBreakdownOut

logger = get_logger(__name__)

router = APIRouter(prefix="/jobs", tags=["reports"])

REPORTING_ENGINE_NAME = "reporting"
SCORING_ENGINE_NAME = "scoring"

# Media types for the formats the reporting engine renders. Used to serve a
# download with the right type even though the stored bytes carry none.
_MEDIA_TYPES = {
    "json": "application/json",
    "markdown": "text/markdown; charset=utf-8",
    "html": "text/html; charset=utf-8",
    "pdf": "application/pdf",
    "sarif": "application/json",
}
_EXTENSIONS = {
    "json": "json",
    "markdown": "md",
    "html": "html",
    "pdf": "pdf",
    "sarif": "sarif.json",
}


async def _require_job_id(session: DbSession, job_id: uuid.UUID, org_id: uuid.UUID | None) -> None:
    """Confirm the job exists within the caller's tenant, or 404."""
    if await JobRepository(session).get(job_id, org_id=org_id) is None:
        raise NotFoundError("Job not found.")


async def _reporting_evidence(session: DbSession, job_id: uuid.UUID) -> Evidence:
    rows = await EvidenceRepository(session).list_for_job(job_id, engine=REPORTING_ENGINE_NAME)
    if not rows:
        raise NotFoundError(
            "No report has been generated for this job. Reports are produced by the "
            "reporting stage once analysis completes."
        )
    return rows[-1]


def _manifest(payload: dict[str, Any]) -> dict[str, str]:
    evidence = payload.get("evidence")
    if not isinstance(evidence, dict):
        return {}
    artifacts = evidence.get("artifacts")
    if not isinstance(artifacts, dict):
        return {}
    return {str(k): str(v) for k, v in artifacts.items() if isinstance(v, str)}


def _warnings(payload: dict[str, Any]) -> list[str]:
    errors = payload.get("errors")
    if not isinstance(errors, list):
        return []
    out: list[str] = []
    for err in errors:
        if isinstance(err, dict) and err.get("message"):
            out.append(str(err["message"]))
    return out


@router.get("/{job_id}/report", response_model=ReportOut)
async def get_report(session: DbSession, user: ViewerDep, job_id: uuid.UUID) -> ReportOut:
    """The structured report for a job, with the formats available to download."""
    await _require_job_id(session, job_id, user.org_uuid)
    row = await _reporting_evidence(session, job_id)

    payload = row.payload
    evidence = payload.get("evidence")
    report = evidence.get("report") if isinstance(evidence, dict) else None
    report_dict = report if isinstance(report, dict) else {}

    score = None
    scoring_rows = await EvidenceRepository(session).list_for_job(
        job_id, engine=SCORING_ENGINE_NAME
    )
    if scoring_rows:
        scoring_evidence = scoring_rows[-1].payload.get("evidence")
        if isinstance(scoring_evidence, dict):
            block = scoring_evidence.get("scoring")
            if isinstance(block, dict):
                # The stored envelope is the engine's own dataclass dump, so
                # unknown/renamed fields are dropped rather than 500-ing a report
                # that is otherwise perfectly readable.
                score = ScoreBreakdownOut.model_validate(block)

    return ReportOut(
        job_id=job_id,
        report_id=str(payload.get("report_id") or f"rpt-{job_id}"),
        generated_at=row.created_at.isoformat(),
        score=score,
        report=report_dict,
        formats={fmt: f"/api/v1/jobs/{job_id}/report/{fmt}" for fmt in sorted(_manifest(payload))},
        warnings=_warnings(payload),
    )


@router.get("/{job_id}/report/{fmt}")
async def download_report(
    session: DbSession,
    storage: Storage,
    user: ViewerDep,
    request: Request,
    job_id: uuid.UUID,
    fmt: str,
) -> Response:
    """Stream one rendered report artifact."""
    await _require_job_id(session, job_id, user.org_uuid)
    row = await _reporting_evidence(session, job_id)

    manifest = _manifest(row.payload)
    key = manifest.get(fmt)
    if key is None:
        raise NotFoundError(
            f"Format '{fmt}' was not rendered for this job. Available: "
            f"{', '.join(sorted(manifest)) or 'none'}."
        )

    try:
        data = await storage.load(key)
    except FileNotFoundError:
        # The manifest and storage disagree — the row promises an artifact whose
        # bytes are gone (retention, a wiped volume). Say so rather than 500.
        logger.warning("report_artifact_missing", job_id=str(job_id), fmt=fmt, key=key)
        raise NotFoundError(
            f"The rendered '{fmt}' report is no longer available in storage."
        ) from None

    await AuditRepository(session).record(
        AuditAction.report_downloaded,
        actor_id=uuid.UUID(user.id),
        actor_email=user.email,
        org_id=user.org_uuid,
        target_type="job",
        target_id=str(job_id),
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        trace_id=getattr(request.state, "trace_id", None),
        detail={"format": fmt, "bytes": len(data)},
    )
    await session.commit()

    filename = f"sephela-report-{job_id}.{_EXTENSIONS.get(fmt, fmt)}"
    return Response(
        content=data,
        media_type=_MEDIA_TYPES.get(fmt, "application/octet-stream"),
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
