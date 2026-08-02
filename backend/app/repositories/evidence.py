"""Data access for engine output — evidence envelopes and normalized findings.

Both repositories are written for *idempotent* stage re-runs (see
docs/architecture/05-messaging.md "Reliability"): a retried stage replaces its
previous evidence rather than accumulating duplicates.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.analysis import Evidence, Finding


class EvidenceRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def replace_for_stage(
        self,
        *,
        job_id: uuid.UUID,
        stage_run_id: uuid.UUID,
        engine_name: str,
        envelope_version: str,
        payload: dict[str, Any],
        large_artifact_uri: str | None = None,
    ) -> Evidence:
        """Persist an envelope, discarding any envelope from a previous attempt.

        Findings cascade off ``evidence.id``, so the delete also clears the
        previous attempt's findings — no stale rows survive a retry.
        """
        await self.session.execute(delete(Evidence).where(Evidence.stage_run_id == stage_run_id))
        row = Evidence(
            job_id=job_id,
            stage_run_id=stage_run_id,
            engine_name=engine_name,
            envelope_version=envelope_version,
            payload=payload,
            large_artifact_uri=large_artifact_uri,
        )
        self.session.add(row)
        await self.session.flush()
        return row

    async def list_for_job(
        self, job_id: uuid.UUID, *, engine: str | None = None
    ) -> list[Evidence]:
        stmt = (
            select(Evidence)
            .where(Evidence.job_id == job_id)
            .order_by(Evidence.created_at.asc())
        )
        if engine is not None:
            stmt = stmt.where(Evidence.engine_name == engine)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())


class FindingRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def bulk_upsert(self, findings: list[Finding]) -> int:
        """Insert findings, updating on ``(job_id, source_engine, finding_id)`` conflict.

        Engine-assigned finding ids are stable across re-runs, so a retry updates
        in place instead of failing on the unique constraint.
        """
        if not findings:
            return 0

        rows = [
            {
                "id": f.id or uuid.uuid4(),
                "job_id": f.job_id,
                "evidence_id": f.evidence_id,
                "source_engine": f.source_engine,
                "finding_id": f.finding_id,
                "type": f.type,
                "severity": f.severity,
                "confidence": f.confidence,
                "detail": f.detail,
                "provenance": f.provenance,
                "mitre": f.mitre,
                "owasp_mobile": f.owasp_mobile,
            }
            for f in findings
        ]
        stmt = pg_insert(Finding).values(rows)
        stmt = stmt.on_conflict_do_update(
            constraint="uq_finding_job_engine_id",
            set_={
                "evidence_id": stmt.excluded.evidence_id,
                "type": stmt.excluded.type,
                "severity": stmt.excluded.severity,
                "confidence": stmt.excluded.confidence,
                "detail": stmt.excluded.detail,
                "provenance": stmt.excluded.provenance,
                "mitre": stmt.excluded.mitre,
                "owasp_mobile": stmt.excluded.owasp_mobile,
            },
        )
        await self.session.execute(stmt)
        return len(rows)

    async def list_for_job(
        self,
        job_id: uuid.UUID,
        *,
        type_: str | None = None,
        severity: str | None = None,
        limit: int = 200,
    ) -> list[Finding]:
        stmt = (
            select(Finding)
            .where(Finding.job_id == job_id)
            .order_by(Finding.created_at.asc())
            .limit(limit)
        )
        if type_ is not None:
            stmt = stmt.where(Finding.type == type_)
        if severity is not None:
            stmt = stmt.where(Finding.severity == severity)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())
