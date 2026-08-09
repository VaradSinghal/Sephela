"""Analysis-domain models (Phase 4 foundation → Phase 11 threat-intel enrichment).

Introduces the sample / job / stage tables needed to accept uploads and track
their lifecycle, the ``evidence`` and ``findings`` tables that engine stages write
into, and the ``enrichments`` table backing the threat-intel cache. Risk scores
and reports arrive with their respective phases (see
docs/architecture/04-data-model.md). No malware-analysis logic lives here — only
the persistence backbone the pipeline hangs off.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDMixin


class JobStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    partial = "partial"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class StageStatus(str, enum.Enum):
    pending = "pending"
    running = "running"
    ok = "ok"
    partial = "partial"
    failed = "failed"
    skipped = "skipped"


class Sample(UUIDMixin, TimestampMixin, Base):
    """A deduplicated APK, keyed by SHA-256. One row per unique file."""

    __tablename__ = "samples"

    sha256: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    sha1: Mapped[str | None] = mapped_column(String(40), nullable=True)
    md5: Mapped[str | None] = mapped_column(String(32), nullable=True)
    file_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    original_filename: Mapped[str | None] = mapped_column(String(512), nullable=True)
    package_name: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    storage_uri: Mapped[str] = mapped_column(Text, nullable=False)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )

    jobs: Mapped[list[AnalysisJob]] = relationship(back_populates="sample")


class AnalysisJob(UUIDMixin, TimestampMixin, Base):
    """One analysis run of a sample. Immutable once terminal; re-analysis = new job."""

    __tablename__ = "analysis_jobs"

    sample_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("samples.id"), nullable=False, index=True
    )
    org_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("organizations.id"), nullable=True, index=True
    )
    requested_by: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    status: Mapped[JobStatus] = mapped_column(
        Enum(JobStatus, name="job_status"), default=JobStatus.queued, nullable=False, index=True
    )
    pipeline_version: Mapped[str] = mapped_column(String(32), nullable=False)
    priority: Mapped[int] = mapped_column(Integer, default=5, nullable=False)
    progress: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(nullable=True)

    sample: Mapped[Sample] = relationship(back_populates="jobs")
    stages: Mapped[list[StageRun]] = relationship(
        back_populates="job", cascade="all, delete-orphan"
    )


class StageRun(UUIDMixin, TimestampMixin, Base):
    """Execution record of one pipeline stage/engine within a job."""

    __tablename__ = "stage_runs"
    __table_args__ = (UniqueConstraint("job_id", "engine_name", name="uq_stage_job_engine"),)

    job_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("analysis_jobs.id", ondelete="CASCADE"), nullable=False
    )
    engine_name: Mapped[str] = mapped_column(String(64), nullable=False)
    engine_version: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[StageStatus] = mapped_column(
        Enum(StageStatus, name="stage_status"), default=StageStatus.pending, nullable=False
    )
    attempt: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    job: Mapped[AnalysisJob] = relationship(back_populates="stages")
    evidence: Mapped[list[Evidence]] = relationship(
        back_populates="stage_run", cascade="all, delete-orphan"
    )


class Evidence(UUIDMixin, TimestampMixin, Base):
    """A raw Evidence Envelope emitted by one StageRun.

    ``payload`` is the engine's envelope verbatim (JSONB, GIN-indexed) so the
    contract can evolve additively without a migration. Bulky by-products
    (decompiled source, pcap) stay in object storage, referenced by
    ``large_artifact_uri``.
    """

    __tablename__ = "evidence"
    __table_args__ = (
        Index("ix_evidence_job_id", "job_id"),
        Index("ix_evidence_payload", "payload", postgresql_using="gin"),
    )

    stage_run_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("stage_runs.id", ondelete="CASCADE"), nullable=False
    )
    job_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("analysis_jobs.id", ondelete="CASCADE"), nullable=False
    )
    engine_name: Mapped[str] = mapped_column(String(64), nullable=False)
    envelope_version: Mapped[str] = mapped_column(String(16), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    large_artifact_uri: Mapped[str | None] = mapped_column(Text, nullable=True)

    stage_run: Mapped[StageRun] = relationship(back_populates="evidence")


class Finding(UUIDMixin, TimestampMixin, Base):
    """A normalized finding, denormalized out of an envelope for querying.

    Envelopes stay authoritative; this table exists so the dashboard and scoring
    engine can filter/aggregate by type and severity without cracking JSONB.
    """

    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_findings_job_id", "job_id"),
        Index("ix_findings_type", "type"),
        UniqueConstraint("job_id", "source_engine", "finding_id", name="uq_finding_job_engine_id"),
    )

    job_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("analysis_jobs.id", ondelete="CASCADE"), nullable=False
    )
    evidence_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("evidence.id", ondelete="CASCADE"), nullable=True
    )
    source_engine: Mapped[str] = mapped_column(String(64), nullable=False)
    # The engine-assigned id, stable across re-runs — makes stage retries idempotent.
    finding_id: Mapped[str] = mapped_column(String(128), nullable=False)
    type: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    provenance: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    mitre: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list, nullable=False)
    owasp_mobile: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list, nullable=False)


class Enrichment(UUIDMixin, TimestampMixin, Base):
    """One provider's verdict on one indicator — and the threat-intel cache.

    This table serves two purposes at once, which is why ``job_id`` is nullable
    and there is no unique constraint on ``(job_id, ioc_type, ioc_value,
    provider)``:

    1. **Per-job record** of what was looked up, so a report can show which feeds
       were consulted for which indicators.
    2. **Cross-job cache**, keyed on ``(ioc_type, ioc_value, provider)`` with
       ``expires_at`` as the TTL. External feeds are metered and the same CDN
       domain or C2 host recurs across every sample in a campaign, so reusing a
       verdict is the difference between an affordable engine and an unusable one
       (docs/architecture/02-services.md: "Caches aggressively").

    Cache reads therefore ignore ``job_id`` and take the freshest non-expired row
    for the indicator/provider pair, whichever job originally fetched it. Rows
    are kept after expiry rather than deleted — a stale verdict is still audit
    evidence of what the feed said at analysis time, which matters when a
    completed job is immutable.
    """

    __tablename__ = "enrichments"
    __table_args__ = (
        # The cache lookup path: indicator + provider + freshness.
        Index("ix_enrich_ioc", "ioc_type", "ioc_value"),
        Index("ix_enrich_cache", "ioc_type", "ioc_value", "provider", "expires_at"),
        Index("ix_enrich_job_id", "job_id"),
    )

    # Nullable: a cached row outlives the job that fetched it, and job deletion
    # must not evict the cache for every other tenant.
    job_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("analysis_jobs.id", ondelete="SET NULL"), nullable=True
    )
    ioc_type: Mapped[str] = mapped_column(String(16), nullable=False)
    ioc_value: Mapped[str] = mapped_column(Text, nullable=False)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    verdict: Mapped[str | None] = mapped_column(String(16), nullable=True)
    raw: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    fetched_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), nullable=False
    )
    expires_at: Mapped[datetime | None] = mapped_column(nullable=True)
