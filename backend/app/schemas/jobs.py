"""Upload + job request/response schemas (docs/architecture/06-api-spec.md)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from app.db.models.analysis import JobStatus, StageStatus


class UploadResponse(BaseModel):
    job_id: uuid.UUID
    sample_id: uuid.UUID
    sha256: str
    status: JobStatus
    duplicate: bool


class StageOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    engine: str
    status: StageStatus
    started_at: datetime | None = None
    finished_at: datetime | None = None


class JobOut(BaseModel):
    job_id: uuid.UUID
    sample_id: uuid.UUID
    status: JobStatus
    progress: int
    pipeline_version: str
    stages: list[StageOut]
    error: str | None = None
    created_at: datetime


class JobListOut(BaseModel):
    items: list[JobOut]
    next_cursor: str | None = None


class StageDetailOut(StageOut):
    """Per-stage detail, including why a stage was partial/failed/skipped."""

    engine_version: str
    attempt: int
    error: str | None = None


class EvidenceOut(BaseModel):
    """A raw Evidence Envelope as produced by an engine (RBAC-gated)."""

    model_config = ConfigDict(from_attributes=True)

    evidence_id: uuid.UUID
    engine: str
    envelope_version: str
    payload: dict[str, Any]
    large_artifact_uri: str | None = None
    created_at: datetime


class EvidenceListOut(BaseModel):
    items: list[EvidenceOut]


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    finding_id: str
    source_engine: str
    type: str
    severity: str
    confidence: float | None = None
    detail: str | None = None
    provenance: dict[str, Any] | None = None
    mitre: list[str] = []
    owasp_mobile: list[str] = []


class FindingListOut(BaseModel):
    items: list[FindingOut]
    total: int
