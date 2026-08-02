"""Stage execution backbone — the seam between engines and the database.

Every analysis engine (static, code_intel, dynamic, threat_intel, ai) returns the
same thing: an **Evidence Envelope**. This module owns what the orchestrator does
with one, so each engine's Celery task stays a thin adapter:

    stage_run → run engine → persist envelope + findings → set stage status

Deliberately engine-agnostic: it consumes envelopes as plain ``dict``s (what
``EvidenceEnvelope.model_dump(mode="json")`` produces) rather than importing any
engine's pydantic classes. The backend therefore does not need every engine
package installed to orchestrate the ones it does have, and the mapping logic is
unit-testable with literals.

Contract reference: docs/architecture/03-communication.md, 05-messaging.md.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.db.models.analysis import AnalysisJob, Finding, StageStatus
from app.repositories.evidence import EvidenceRepository, FindingRepository
from app.repositories.samples import JobRepository

logger = get_logger(__name__)

# Envelope ``status`` → stage status. Engines report ok/partial/failed; anything
# unrecognized is treated as partial so an unknown value never silently reads
# as success.
_ENVELOPE_STATUS_MAP = {
    "ok": StageStatus.ok,
    "partial": StageStatus.partial,
    "failed": StageStatus.failed,
}

MAX_ERROR_CHARS = 4000


@dataclass
class StageOutcome:
    """What a stage did, for the caller to log/propagate."""

    engine: str
    status: StageStatus
    evidence_id: uuid.UUID | None = None
    findings: int = 0
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.status in (StageStatus.ok, StageStatus.partial)


def envelope_status(payload: dict[str, Any]) -> StageStatus:
    """Map an envelope's self-reported status onto a stage status."""
    raw = payload.get("status")
    if not isinstance(raw, str):
        return StageStatus.partial
    return _ENVELOPE_STATUS_MAP.get(raw, StageStatus.partial)


def envelope_error_summary(payload: dict[str, Any]) -> str | None:
    """Condense ``envelope.errors[]`` into a single human-readable string.

    A partial stage is still a success, but the reason it was partial must not be
    lost — this is what an analyst reads on the job detail page.
    """
    errors = payload.get("errors")
    if not isinstance(errors, list) or not errors:
        return None

    parts: list[str] = []
    for err in errors:
        if not isinstance(err, dict):
            continue
        extractor = err.get("extractor", "?")
        message = err.get("message", "")
        parts.append(f"{extractor}: {message}")
    if not parts:
        return None
    return "; ".join(parts)[:MAX_ERROR_CHARS]


def normalize_findings(
    payload: dict[str, Any],
    *,
    job_id: uuid.UUID,
    engine_name: str,
    evidence_id: uuid.UUID | None = None,
) -> list[Finding]:
    """Flatten ``envelope.findings[]`` into ORM rows for the ``findings`` table.

    Malformed entries are skipped rather than raising — evidence comes from an
    environment that ran malware and is treated as untrusted input
    (docs/architecture/09-security.md).
    """
    raw_findings = payload.get("findings")
    if not isinstance(raw_findings, list):
        return []

    rows: list[Finding] = []
    seen: set[str] = set()
    for index, item in enumerate(raw_findings):
        if not isinstance(item, dict):
            continue
        detail = item.get("detail")
        type_ = item.get("type")
        if not isinstance(type_, str) or not type_:
            continue

        # Fall back to a positional id so a finding without one still persists,
        # and de-dupe within the envelope to protect the unique constraint.
        finding_id = str(item.get("id") or f"{engine_name}-{index}")[:128]
        if finding_id in seen:
            continue
        seen.add(finding_id)

        provenance = item.get("provenance")
        raw_mappings = item.get("mappings")
        mappings: dict[str, Any] = raw_mappings if isinstance(raw_mappings, dict) else {}
        confidence = item.get("confidence")

        rows.append(
            Finding(
                id=uuid.uuid4(),
                job_id=job_id,
                evidence_id=evidence_id,
                source_engine=engine_name,
                finding_id=finding_id,
                type=type_[:64],
                severity=str(item.get("severity") or "info")[:16],
                confidence=float(confidence) if isinstance(confidence, (int, float)) else None,
                detail=str(detail) if detail is not None else None,
                provenance=provenance if isinstance(provenance, dict) else None,
                mitre=_str_list(mappings.get("mitre")),
                owasp_mobile=_str_list(mappings.get("owasp_mobile")),
            )
        )
    return rows


def _str_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(v) for v in value if isinstance(v, (str, int, float))]


class StageRunner:
    """Drives one engine stage's DB lifecycle within a job.

    Usage from a Celery task::

        runner = StageRunner(session, job_id, engine_name="dynamic", engine_version="1.0.0")
        await runner.begin()
        try:
            envelope = run_the_engine()
        except Exception as exc:
            return await runner.fail(exc)
        return await runner.complete(envelope.model_dump(mode="json"))

    Each method commits, so a crash between steps leaves the stage row in a
    truthful state instead of silently rolling back to ``pending``.
    """

    def __init__(
        self,
        session: AsyncSession,
        job_id: uuid.UUID,
        *,
        engine_name: str,
        engine_version: str,
    ) -> None:
        self.session = session
        self.job_id = job_id
        self.engine_name = engine_name
        self.engine_version = engine_version
        self.jobs = JobRepository(session)
        self._stage_id: uuid.UUID | None = None

    async def begin(self) -> uuid.UUID:
        stage = await self.jobs.start_stage(self.job_id, self.engine_name, self.engine_version)
        self._stage_id = stage.id
        await self.session.commit()
        logger.info(
            "stage_started",
            job_id=str(self.job_id),
            engine=self.engine_name,
            attempt=stage.attempt,
        )
        return stage.id

    async def complete(
        self, payload: dict[str, Any], *, large_artifact_uri: str | None = None
    ) -> StageOutcome:
        """Persist the envelope + its findings and set the terminal stage status."""
        stage = await self._require_stage()
        status = envelope_status(payload)
        error = envelope_error_summary(payload)

        evidence = await EvidenceRepository(self.session).replace_for_stage(
            job_id=self.job_id,
            stage_run_id=stage.id,
            engine_name=self.engine_name,
            envelope_version=str(payload.get("envelope_version") or "unknown")[:16],
            payload=payload,
            large_artifact_uri=large_artifact_uri,
        )
        rows = normalize_findings(
            payload,
            job_id=self.job_id,
            engine_name=self.engine_name,
            evidence_id=evidence.id,
        )
        count = await FindingRepository(self.session).bulk_upsert(rows)

        await self.jobs.finish_stage(stage, status, error=error)
        await self.session.commit()

        logger.info(
            "stage_completed",
            job_id=str(self.job_id),
            engine=self.engine_name,
            status=status.value,
            findings=count,
        )
        return StageOutcome(
            engine=self.engine_name,
            status=status,
            evidence_id=evidence.id,
            findings=count,
            error=error,
        )

    async def fail(self, exc: BaseException | str) -> StageOutcome:
        """Record a stage that could not produce an envelope at all."""
        stage = await self._require_stage()
        message = exc if isinstance(exc, str) else f"{type(exc).__name__}: {exc}"
        await self.jobs.finish_stage(stage, StageStatus.failed, error=message[:MAX_ERROR_CHARS])
        await self.session.commit()
        logger.warning(
            "stage_failed", job_id=str(self.job_id), engine=self.engine_name, error=message
        )
        return StageOutcome(engine=self.engine_name, status=StageStatus.failed, error=message)

    async def skip(self, reason: str) -> StageOutcome:
        """Record a stage intentionally not run (policy off, prerequisite absent).

        Skipping is written to the DB rather than left absent so the job detail
        view can show *why* dynamic analysis produced nothing.
        """
        stage = await self.jobs.start_stage(self.job_id, self.engine_name, self.engine_version)
        self._stage_id = stage.id
        # A skip is not an attempt at work.
        stage.attempt = max(0, stage.attempt - 1)
        await self.jobs.finish_stage(stage, StageStatus.skipped, error=reason[:MAX_ERROR_CHARS])
        await self.session.commit()
        logger.info(
            "stage_skipped", job_id=str(self.job_id), engine=self.engine_name, reason=reason
        )
        return StageOutcome(engine=self.engine_name, status=StageStatus.skipped, error=reason)

    async def set_progress(self, progress: int) -> None:
        job = await self.session.get(AnalysisJob, self.job_id)
        if job is None:
            return
        job.progress = max(0, min(100, progress))
        await self.session.commit()

    async def _require_stage(self) -> Any:
        if self._stage_id is None:
            raise RuntimeError("StageRunner.begin() must be called before recording an outcome.")
        stage = await self.jobs.get_stage(self.job_id, self.engine_name)
        if stage is None:  # pragma: no cover — begin() guarantees the row exists
            raise RuntimeError(f"Stage row vanished for job={self.job_id} {self.engine_name}")
        return stage
