"""Upload service — the APK ingestion pipeline (Phase 4).

Flow (docs/architecture/07-data-flow.md, DFD-1):
    validate → hash → dedup → store → persist sample+job → enqueue → return job

Designed for error recovery: storage happens before DB commit, and the job is
only enqueued after the row is durably committed, so a crash never leaves a
job pointing at bytes that aren't there (or vice versa).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.exceptions import ValidationAppError
from app.core.logging import get_logger
from app.db.models.analysis import AnalysisJob, JobStatus, Sample
from app.repositories.samples import JobRepository, SampleRepository
from app.services.apk import compute_hashes, validate_apk
from app.storage.base import StorageBackend

logger = get_logger(__name__)


@dataclass
class UploadResult:
    job_id: uuid.UUID
    sample_id: uuid.UUID
    sha256: str
    status: JobStatus
    duplicate: bool


class UploadService:
    def __init__(self, session: AsyncSession, storage: StorageBackend) -> None:
        self.session = session
        self.samples = SampleRepository(session)
        self.jobs = JobRepository(session)
        self.storage = storage

    async def ingest(
        self,
        data: bytes,
        *,
        filename: str | None = None,
        user_id: uuid.UUID | None = None,
        org_id: uuid.UUID | None = None,
    ) -> UploadResult:
        # 1. Size guard (cheap) before doing any work.
        if len(data) > settings.max_upload_bytes:
            raise ValidationAppError(
                f"File exceeds maximum upload size of {settings.max_upload_bytes} bytes."
            )

        # 2. Structural validation.
        validate_apk(data, filename=filename)

        # 3. Content hashing.
        hashes = compute_hashes(data)

        # 4. Duplicate detection by SHA-256.
        sample = await self.samples.get_by_sha256(hashes.sha256)
        duplicate = sample is not None

        # 5. Store bytes (content-addressed) — skip if the sample already exists.
        if sample is None:
            key = StorageBackend.sample_key(hashes.sha256)
            if not await self.storage.exists(key):
                storage_uri = await self.storage.save(key, data)
            else:
                # Content-addressed, so the stored bytes are already these bytes.
                # Ask the backend for the URI rather than assembling one: the literal
                # `file://{key}` this used to build was both scheme-wrong on S3 and
                # path-wrong on local, where save() returns an absolute path.
                storage_uri = self.storage.uri_for(key)
            sample = Sample(
                sha256=hashes.sha256,
                sha1=hashes.sha1,
                md5=hashes.md5,
                file_size=hashes.size,
                original_filename=filename,
                storage_uri=storage_uri,
                created_by=user_id,
            )
            sample = await self.samples.create(sample)
            logger.info("sample_created", sha256=hashes.sha256, size=hashes.size)
        else:
            logger.info("sample_duplicate", sha256=hashes.sha256)

        # 6. Always create a new job (re-analysis of a known sample is valid).
        job = AnalysisJob(
            sample_id=sample.id,
            org_id=org_id,
            requested_by=user_id,
            status=JobStatus.queued,
            pipeline_version=settings.pipeline_version,
        )
        job = await self.jobs.create(job)

        return UploadResult(
            job_id=job.id,
            sample_id=sample.id,
            sha256=hashes.sha256,
            status=job.status,
            duplicate=duplicate,
        )
