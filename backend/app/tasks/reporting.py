"""Reporting stage (Phase 9) — score + findings + evidence → report artifacts.

DFD-8 (docs/architecture/07-data-flow.md)::

    job (scored) → q.reporting → assemble AnalysisReport → render json/markdown/
    html/sarif/pdf → persist bytes to object storage → Evidence Envelope carrying
    the format → key manifest

Like scoring, this stage is **independent of the AI stage**: the report is built
from persisted rows by ``app.services.reports.build_report_data``, and an LLM
narrative is layered on when one exists. A bank with no model credential still
gets a downloadable, defensible report.

Rendered bytes go to object storage rather than into the envelope: a PDF is
megabytes and the envelope is a queryable JSON column. The envelope keeps the
report structure plus a ``format → storage key`` manifest, which is what
``/jobs/{id}/report/{format}`` serves from.

Failure policy: a renderer that fails costs that one format (``partial``); only a
total failure to produce anything is a ``failed`` stage. PDF in particular needs
``weasyprint``, which is a heavy optional dependency — its absence must not cost
the four formats that need nothing.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.logging import get_logger
from app.db.models.analysis import AnalysisJob, JobStatus, Sample, StageStatus
from app.db.session import AsyncSessionLocal
from app.repositories.evidence import EvidenceRepository, FindingRepository
from app.services.reports import DEFAULT_FORMATS, build_report_data, report_id_for
from app.services.samples import storage
from app.services.stages import StageOutcome, StageRunner
from app.storage.base import StorageBackend
from app.tasks.celery_app import celery_app
from app.tasks.scoring import MAX_FINDINGS

logger = get_logger(__name__)

ENGINE_NAME = "reporting"
_UNKNOWN_VERSION = "0.0.0"


class ReportingUnavailableError(RuntimeError):
    """The reporting engine distribution is not installed in this worker."""


def _engine() -> tuple[Any, str]:
    """Import the reporting engine lazily (see ``app.tasks.static._engine``)."""
    try:
        import sephela_reporting
        from sephela_reporting import ReportingEngine
    except ImportError as exc:  # pragma: no cover — environment-dependent
        raise ReportingUnavailableError(
            "sephela-reporting-engine is not installed in the worker environment "
            "(pip install -e engines/reporting)."
        ) from exc
    return ReportingEngine, getattr(sephela_reporting, "__version__", _UNKNOWN_VERSION)


async def _run(job_id: str) -> str:
    jid = uuid.UUID(job_id)

    async with AsyncSessionLocal() as session:
        job = await session.get(AnalysisJob, jid)
        if job is None:
            logger.warning("reporting_job_missing", job_id=job_id)
            return "missing"
        if job.status == JobStatus.cancelled:
            return JobStatus.cancelled.value

        sample = await session.get(Sample, job.sample_id)
        if sample is None:  # pragma: no cover — FK guarantees this
            logger.warning("reporting_sample_missing", job_id=job_id)
            return "missing"

        try:
            engine_cls, engine_version = _engine()
        except ReportingUnavailableError as exc:
            stage = StageRunner(
                session, jid, engine_name=ENGINE_NAME, engine_version=_UNKNOWN_VERSION
            )
            await stage.begin()
            return (await stage.fail(exc)).status.value

        stage = StageRunner(session, jid, engine_name=ENGINE_NAME, engine_version=engine_version)
        outcome = await _execute(
            session=session,
            stage=stage,
            engine_cls=engine_cls,
            job=job,
            sample=sample,
            job_id=job_id,
            jid=jid,
        )
        return outcome.status.value


async def _execute(
    *,
    session: AsyncSession,
    stage: StageRunner,
    engine_cls: Any,
    job: AnalysisJob,
    sample: Sample,
    job_id: str,
    jid: uuid.UUID,
) -> StageOutcome:
    """Render and persist the report, mapping every failure onto a stage status."""
    if not settings.reporting_enabled:
        await stage.begin()
        return await stage.skip("Report generation is disabled (SEPHELA_REPORTING_ENABLED).")

    evidence_rows = await EvidenceRepository(session).list_for_job(jid)
    finding_rows = await FindingRepository(session).list_for_job(jid, limit=MAX_FINDINGS)

    if not evidence_rows:
        await stage.begin()
        return await stage.skip(
            "No evidence was produced by any analysis stage, so there is nothing to report."
        )

    await stage.begin()

    try:
        report_data = build_report_data(
            job=job, sample=sample, evidence_rows=evidence_rows, finding_rows=finding_rows
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("reporting_assembly_error", job_id=job_id)
        return await stage.fail(exc)

    try:
        result = await asyncio.to_thread(_render, engine_cls, report_data)
    except Exception as exc:  # noqa: BLE001
        logger.exception("reporting_engine_error", job_id=job_id)
        return await stage.fail(exc)

    artifacts, warnings = result
    if not artifacts:
        return await stage.fail("No report format could be rendered: " + "; ".join(warnings))

    try:
        manifest = await _persist(job_id, artifacts)
    except Exception as exc:  # noqa: BLE001
        logger.exception("reporting_storage_error", job_id=job_id)
        return await stage.fail(exc)

    missing = [fmt for fmt in DEFAULT_FORMATS if fmt not in manifest]
    errors = [{"extractor": "renderer", "message": w} for w in warnings]
    if missing:
        errors.append(
            {"extractor": "renderer", "message": f"Formats not rendered: {', '.join(missing)}"}
        )

    payload: dict[str, Any] = {
        "envelope_version": "1.0.0",
        # A missing optional renderer is a partial result, not a success.
        "status": "partial" if errors else "ok",
        "engine": {"name": ENGINE_NAME, "version": stage.engine_version},
        "job_id": job_id,
        "findings": [],
        "errors": errors,
        "evidence": {
            "report": report_data,
            "artifacts": manifest,
        },
        "report_id": report_id_for(jid),
    }

    # The manifest is the canonical pointer to the rendered bytes; the primary
    # artifact goes in large_artifact_uri so a reader of the row alone can find it.
    primary = manifest.get("pdf") or manifest.get("html") or manifest.get("markdown")
    outcome = await stage.complete(payload, large_artifact_uri=primary)

    logger.info(
        "reporting_completed",
        job_id=job_id,
        formats=sorted(manifest),
        warnings=len(warnings),
    )
    await stage.set_progress(95)
    return outcome


def _render(engine_cls: Any, report_data: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Render every requested format, tolerating individual renderer failures.

    Runs in a worker thread: rendering is synchronous and, for PDF, genuinely
    slow.
    """
    engine = engine_cls()
    warnings: list[str] = []

    try:
        artifacts = engine.generate(report_data, formats=list(DEFAULT_FORMATS))
    except Exception as exc:  # noqa: BLE001
        # Every renderer failed, or the data did not validate. Retry with the two
        # formats that need no optional dependency before giving up, so a broken
        # PDF toolchain cannot cost the whole report.
        warnings.append(f"full render failed ({type(exc).__name__}: {exc})")
        artifacts = engine.generate(report_data, formats=["json", "markdown"])

    return artifacts, warnings


async def _persist(job_id: str, artifacts: dict[str, Any]) -> dict[str, str]:
    """Write rendered bytes to object storage; return a ``format → key`` map."""
    backend = storage()
    manifest: dict[str, str] = {}
    for fmt, artifact in artifacts.items():
        key = StorageBackend.report_key(job_id, artifact.filename)
        await backend.save(key, artifact.content_bytes)
        manifest[str(fmt)] = key
    return manifest


@celery_app.task(
    name="reporting.analyze",
    queue="reporting",
    bind=True,
    max_retries=2,
    default_retry_delay=30,
    acks_late=True,
    # PDF rendering of a long report is the slow path here.
    soft_time_limit=10 * 60,
    time_limit=12 * 60,
)
def analyze_reporting(self, job_id: str) -> str:  # type: ignore[no-untyped-def]
    """Reporting stage for a job. Records outcomes, never re-raises.

    Returns the resulting stage status so a Celery chain can observe it.
    """
    try:
        return asyncio.run(_run(job_id))
    except Exception:  # noqa: BLE001
        logger.exception("reporting_task_error", job_id=job_id)
        return StageStatus.failed.value
