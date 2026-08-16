"""Upload endpoint — accept an APK and start analysis (Phase 4; secured in Phase 14).

The size cap is enforced *while* reading rather than after. ``await file.read()``
buffers the whole body into memory before anything checks it, so a single
multi-gigabyte POST could exhaust a pod's memory regardless of
``max_upload_bytes`` — the limit was applied to bytes already resident. Reading in
chunks and aborting past the ceiling bounds the damage to one chunk over the limit.

The declared ``Content-Length`` is checked first as a cheap rejection, but it is
attacker-controlled and absent under chunked encoding, so it is an optimisation and
never the enforcement point.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, File, Request, UploadFile, status

from app.api.deps import DbSession, Storage
from app.core.config import settings
from app.core.exceptions import ValidationAppError
from app.core.security import AnalystDep
from app.db.models.audit import AuditAction
from app.events.producer import dispatch_analysis
from app.repositories.audit import AuditRepository
from app.schemas.jobs import UploadResponse
from app.services.upload import UploadService

router = APIRouter(prefix="/uploads", tags=["uploads"])

_CHUNK = 1024 * 1024  # 1 MiB


async def _read_capped(file: UploadFile, limit: int) -> bytes:
    """Read an upload, refusing anything larger than *limit*.

    Reads one chunk past the limit before rejecting, which is what makes an
    over-sized body detectable without trusting the declared length.
    """
    chunks: list[bytes] = []
    total = 0
    while chunk := await file.read(_CHUNK):
        total += len(chunk)
        if total > limit:
            raise ValidationAppError(f"File exceeds maximum upload size of {limit} bytes.")
        chunks.append(chunk)
    return b"".join(chunks)


@router.post("", response_model=UploadResponse, status_code=status.HTTP_202_ACCEPTED)
async def upload_apk(
    session: DbSession,
    storage: Storage,
    user: AnalystDep,
    request: Request,
    file: UploadFile = File(...),
) -> UploadResponse:
    """Validate, deduplicate, store, persist, and enqueue an APK for analysis.

    Analyst-gated: uploading is what causes malware to be executed in the sandbox,
    so it is not a viewer capability. The job is stamped with the caller's org and
    id, which is what makes it visible to their tenant and no one else.
    """
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > settings.max_upload_bytes:
        raise ValidationAppError(
            f"File exceeds maximum upload size of {settings.max_upload_bytes} bytes."
        )

    data = await _read_capped(file, settings.max_upload_bytes)

    svc = UploadService(session, storage)
    result = await svc.ingest(
        data,
        filename=file.filename,
        user_id=uuid.UUID(user.id),
        org_id=user.org_uuid,
    )

    await AuditRepository(session).record(
        AuditAction.sample_uploaded,
        actor_id=uuid.UUID(user.id),
        actor_email=user.email,
        org_id=user.org_uuid,
        target_type="sample",
        target_id=result.sha256,
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        trace_id=getattr(request.state, "trace_id", None),
        detail={
            "job_id": str(result.job_id),
            "filename": file.filename,
            "bytes": len(data),
            "duplicate": result.duplicate,
        },
    )

    # Commit the job row BEFORE enqueuing so the worker can never race ahead of
    # a durable record (error-recovery guarantee).
    await session.commit()
    dispatch_analysis(result.job_id)

    return UploadResponse(
        job_id=result.job_id,
        sample_id=result.sample_id,
        sha256=result.sha256,
        status=result.status,
        duplicate=result.duplicate,
    )
