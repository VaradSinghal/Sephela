"""Code intelligence stage (Phase 6) — static evidence → analyzers → Envelope.

DFD-4 (docs/architecture/07-data-flow.md)::

    job (static evidence present) → q.code_intel → load static envelope →
    behavioural analyzers over smali/strings/components (+ JADX tree when
    available) → Evidence Envelope + findings

This task is the *adapter*, mirroring ``app.tasks.static``: it reads the static
engine's envelope back out of the database, hands it to
``sephela_code_intel.analyze()``, and lets ``StageRunner`` persist the result.
It holds no analysis logic.

It is also the *last* consumer of the shared job workspace, so it removes the
decompiled tree on the way out.

A caveat worth knowing (see infra/k8s/README.md): ``artifact_dir`` is a path on
the worker's own filesystem. On a single-worker deployment the static stage's
JADX tree is right there; when static and code-intel land on different workers it
is not, and this stage passes ``None`` instead. The engine treats the tree as
optional, so that costs analysis depth — call-graph and control-flow analyzers
degrade — but never correctness. A storage-backed handoff is the real fix.

Failure policy: no static evidence → ``skipped``; engine missing or exploding →
``failed`` stage, job continues.
"""

from __future__ import annotations

import asyncio
import shutil
import uuid
from pathlib import Path
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.logging import get_logger
from app.db.models.analysis import AnalysisJob, JobStatus, Sample, StageStatus
from app.db.session import AsyncSessionLocal
from app.repositories.evidence import EvidenceRepository
from app.services.samples import job_workspace_dir
from app.services.stages import StageOutcome, StageRunner
from app.tasks.celery_app import celery_app

logger = get_logger(__name__)

ENGINE_NAME = "code_intel"
_UNKNOWN_VERSION = "0.0.0"

STATIC_ENGINE_NAME = "static"


class CodeIntelUnavailableError(RuntimeError):
    """The code-intel engine distribution is not installed in this worker."""


def _engine() -> tuple[Any, str]:
    """Import the code-intel engine lazily (see ``app.tasks.static._engine``)."""
    try:
        import sephela_code_intel
        from sephela_code_intel import ENGINE_VERSION
    except ImportError as exc:  # pragma: no cover — environment-dependent
        raise CodeIntelUnavailableError(
            "sephela-code-intel-engine is not installed in the worker environment "
            "(pip install -e engines/code_intel)."
        ) from exc
    return sephela_code_intel, ENGINE_VERSION


def decompiled_tree(static_payload: dict[str, Any]) -> Path | None:
    """Locate the JADX source tree the static engine reported, if it survived.

    The path is only useful if it is still on *this* worker's disk, so it is
    verified rather than trusted — a stale path would make the analyzers read an
    empty tree and silently report less than they could.
    """
    evidence = static_payload.get("evidence")
    if not isinstance(evidence, dict):
        return None
    decompile = evidence.get("decompile")
    if not isinstance(decompile, dict):
        return None
    raw = decompile.get("artifact_dir")
    if not isinstance(raw, str) or not raw:
        return None
    path = Path(raw)
    return path if path.is_dir() else None


async def _run(job_id: str) -> str:
    jid = uuid.UUID(job_id)

    async with AsyncSessionLocal() as session:
        job = await session.get(AnalysisJob, jid)
        if job is None:
            logger.warning("code_intel_job_missing", job_id=job_id)
            return "missing"
        if job.status == JobStatus.cancelled:
            return JobStatus.cancelled.value

        sample = await session.get(Sample, job.sample_id)
        if sample is None:  # pragma: no cover — FK guarantees this
            logger.warning("code_intel_sample_missing", job_id=job_id)
            return "missing"

        try:
            engine, engine_version = _engine()
        except CodeIntelUnavailableError as exc:
            stage = StageRunner(
                session, jid, engine_name=ENGINE_NAME, engine_version=_UNKNOWN_VERSION
            )
            await stage.begin()
            return (await stage.fail(exc)).status.value

        stage = StageRunner(session, jid, engine_name=ENGINE_NAME, engine_version=engine_version)
        try:
            outcome = await _execute(
                session=session,
                stage=stage,
                engine=engine,
                sample=sample,
                job_id=job_id,
                jid=jid,
            )
        finally:
            # Last consumer of the workspace: the tree is derived from a malware
            # sample, so it does not outlive the stage that needed it.
            if not settings.keep_engine_artifacts:
                await asyncio.to_thread(shutil.rmtree, job_workspace_dir(jid), True)

        return outcome.status.value


async def _execute(
    *,
    session: AsyncSession,
    stage: StageRunner,
    engine: Any,
    sample: Sample,
    job_id: str,
    jid: uuid.UUID,
) -> StageOutcome:
    """Run the engine, mapping every failure onto a stage status."""
    if not settings.code_intel_enabled:
        await stage.begin()
        return await stage.skip("Code intelligence is disabled (SEPHELA_CODE_INTEL_ENABLED).")

    rows = await EvidenceRepository(session).list_for_job(jid, engine=STATIC_ENGINE_NAME)
    if not rows:
        await stage.begin()
        # Recorded as a skip rather than a failure: code intel had nothing to
        # analyze, which is a statement about the static stage, not this one.
        return await stage.skip(
            "No static evidence is available — code intelligence analyzes the static envelope."
        )

    static_payload = rows[-1].payload
    static_evidence = static_payload.get("evidence")
    if not isinstance(static_evidence, dict) or not static_evidence:
        await stage.begin()
        return await stage.skip("The static envelope carries no evidence to analyze.")

    artifact_dir = decompiled_tree(static_payload)
    if artifact_dir is None:
        logger.info("code_intel_no_decompiled_tree", job_id=job_id)

    await stage.begin()

    try:
        envelope = await asyncio.to_thread(
            engine.analyze,
            static_evidence,
            job_id=job_id,
            apk_sha256=sample.sha256,
            artifact_dir=artifact_dir,
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("code_intel_engine_error", job_id=job_id)
        return await stage.fail(exc)

    outcome = await stage.complete(envelope.model_dump(mode="json"))
    await stage.set_progress(35)
    return outcome


@celery_app.task(
    name="code_intel.analyze",
    queue="code_intel",
    bind=True,
    max_retries=2,
    default_retry_delay=30,
    acks_late=True,
    soft_time_limit=20 * 60,
    time_limit=23 * 60,
)
def analyze_code_intel(self, job_id: str) -> str:  # type: ignore[no-untyped-def]
    """Code-intel stage for a job. Records outcomes, never re-raises.

    Returns the resulting stage status so a Celery chain can observe it.
    """
    try:
        return asyncio.run(_run(job_id))
    except Exception:  # noqa: BLE001
        logger.exception("code_intel_task_error", job_id=job_id)
        return StageStatus.failed.value
