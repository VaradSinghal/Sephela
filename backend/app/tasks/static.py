"""Static analysis stage (Phase 5) — APK → extractor chain → Evidence Envelope.

DFD-3 (docs/architecture/07-data-flow.md)::

    job → q.static → materialize APK from storage → manifest/permissions/certs/
    strings/smali/decompile extractors → Evidence Envelope + findings

This task is the *adapter*, mirroring ``app.tasks.dynamic``: it copies the APK
out of object storage, hands the path to ``sephela_static.analyze()``, and lets
``StageRunner`` persist the result. It holds no analysis logic.

The workspace it unpacks into is deliberately *not* cleaned up here. The static
engine's decompile extractor writes a JADX source tree and reports its path in
the envelope, and the code-intel stage reads that tree for call-graph and API
analysis. Whoever consumes it last removes it — see ``app.tasks.code_intel``.

Failure policy: extractor-level problems are already captured by the engine as a
``partial`` envelope, so this stage fails only when it cannot get the APK or the
engine is not installed. Static evidence is the input to code intel and scoring,
so a failure here degrades everything downstream — but it still must not crash
the job (docs/architecture/05-messaging.md, "Partial success").
"""

from __future__ import annotations

import asyncio
import shutil
import uuid
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.core.logging import get_logger
from app.db.models.analysis import AnalysisJob, JobStatus, Sample, StageStatus
from app.db.session import AsyncSessionLocal
from app.services.samples import job_workspace_dir, materialize_apk
from app.services.stages import StageOutcome, StageRunner
from app.tasks.celery_app import celery_app

logger = get_logger(__name__)

ENGINE_NAME = "static"
# Fallback when the engine package isn't importable; the real version is read
# from sephela_static at runtime.
_UNKNOWN_VERSION = "0.0.0"


class StaticEngineUnavailableError(RuntimeError):
    """The static engine distribution is not installed in this worker."""


def _engine() -> tuple[Any, str]:
    """Import the static engine lazily.

    Engines are separate distributions (``engines/static``). Importing lazily
    means a missing install surfaces as a failed *stage* with a clear message
    rather than a worker that won't boot.
    """
    try:
        import sephela_static
        from sephela_static import ENGINE_VERSION
    except ImportError as exc:  # pragma: no cover — environment-dependent
        raise StaticEngineUnavailableError(
            "sephela-static-engine is not installed in the worker environment "
            "(pip install -e engines/static)."
        ) from exc
    return sephela_static, ENGINE_VERSION


async def _run(job_id: str) -> str:
    jid = uuid.UUID(job_id)

    async with AsyncSessionLocal() as session:
        job = await session.get(AnalysisJob, jid)
        if job is None:
            logger.warning("static_job_missing", job_id=job_id)
            return "missing"
        if job.status == JobStatus.cancelled:
            return JobStatus.cancelled.value

        sample = await session.get(Sample, job.sample_id)
        if sample is None:  # pragma: no cover — FK guarantees this
            logger.warning("static_sample_missing", job_id=job_id)
            return "missing"

        # Resolve the engine before claiming the stage, so a missing install is
        # reported against a truthful version string.
        try:
            engine, engine_version = _engine()
        except StaticEngineUnavailableError as exc:
            stage = StageRunner(
                session, jid, engine_name=ENGINE_NAME, engine_version=_UNKNOWN_VERSION
            )
            await stage.begin()
            return (await stage.fail(exc)).status.value

        stage = StageRunner(session, jid, engine_name=ENGINE_NAME, engine_version=engine_version)
        outcome = await _execute(
            stage=stage,
            engine=engine,
            sample=sample,
            job_id=job_id,
            input_dir=job_workspace_dir(jid) / "input",
        )
        return outcome.status.value


async def _execute(
    *,
    stage: StageRunner,
    engine: Any,
    sample: Sample,
    job_id: str,
    input_dir: Path,
) -> StageOutcome:
    """Run the engine, mapping every failure onto a stage status."""
    if not settings.static_enabled:
        await stage.begin()
        return await stage.skip("Static analysis is disabled (SEPHELA_STATIC_ENABLED).")

    try:
        apk_path = await materialize_apk(sample, input_dir)
    except FileNotFoundError as exc:
        await stage.begin()
        return await stage.fail(f"APK bytes missing from storage: {exc}")

    await stage.begin()

    # The extractor chain shells out to jadx/androguard over untrusted input and
    # is synchronous and CPU-bound — keep it off the event loop.
    try:
        envelope = await asyncio.to_thread(engine.analyze, apk_path, job_id=job_id)
    except Exception as exc:  # noqa: BLE001 — a bad APK must not kill the job
        logger.exception("static_engine_error", job_id=job_id)
        # The workspace is useless without an envelope pointing into it.
        if not settings.keep_engine_artifacts:
            await asyncio.to_thread(shutil.rmtree, input_dir, True)
        return await stage.fail(exc)

    outcome = await stage.complete(envelope.model_dump(mode="json"))
    await stage.set_progress(20)
    return outcome


@celery_app.task(
    name="static.analyze",
    queue="static",
    bind=True,
    max_retries=2,
    default_retry_delay=30,
    acks_late=True,
    # Decompilation of a large APK is minutes, not seconds.
    soft_time_limit=15 * 60,
    time_limit=18 * 60,
)
def analyze_static(self, job_id: str) -> str:  # type: ignore[no-untyped-def]
    """Static-analysis stage for a job. Records outcomes, never re-raises.

    Returns the resulting stage status so a Celery chain can observe it.
    """
    try:
        return asyncio.run(_run(job_id))
    except Exception:  # noqa: BLE001
        # Everything recoverable is already mapped to a stage status inside
        # _run; reaching here means infrastructure trouble (DB down, etc.).
        logger.exception("static_task_error", job_id=job_id)
        return StageStatus.failed.value
