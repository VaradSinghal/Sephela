"""Dynamic analysis stage (Phase 10) — sandbox → artifacts → Evidence Envelope.

DFD-5 (docs/architecture/07-data-flow.md)::

    job (policy=dynamic) → q.dynamic → provision ephemeral emulator (isolated,
    egress-firewalled) → install+run APK → Frida hooks + capture → normalize
    runtime events → Evidence Envelope → destroy sandbox

This task is the *adapter*: it materializes the APK from object storage, asks the
sandbox runner for artifacts, hands them to ``sephela_dynamic.analyze()``, and
lets ``StageRunner`` persist the result. It holds no analysis logic and never
executes the sample itself.

Failure policy — a dynamic run is best-effort, so nothing here fails the job:
sandbox disabled → ``skipped``; sandbox/engine error → ``failed`` stage, job
continues. Missing evidence must never crash downstream stages
(docs/architecture/05-messaging.md, "Partial success").
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
from app.services.sandbox import (
    SandboxDisabledError,
    SandboxError,
    get_sandbox_runner,
    job_artifacts_dir,
)
from app.services.stages import StageOutcome, StageRunner
from app.storage.base import StorageBackend
from app.storage.local import LocalStorage
from app.tasks.celery_app import celery_app

logger = get_logger(__name__)

ENGINE_NAME = "dynamic"
# Fallback when the engine package isn't importable; the real version is read
# from sephela_dynamic at runtime.
_UNKNOWN_VERSION = "0.0.0"


def _engine() -> tuple[Any, str]:
    """Import the dynamic engine lazily.

    Engines are separate distributions (``engines/dynamic``). Importing lazily
    means a backend deployment that doesn't run dynamic analysis needn't install
    it, and a missing install surfaces as a failed *stage* with a clear message
    rather than a worker that won't boot.
    """
    try:
        import sephela_dynamic
        from sephela_dynamic.pipeline import ENGINE_VERSION
    except ImportError as exc:  # pragma: no cover — environment-dependent
        raise SandboxError(
            "sephela-dynamic-engine is not installed in the worker environment "
            "(pip install -e engines/dynamic)."
        ) from exc
    return sephela_dynamic, ENGINE_VERSION


def _storage() -> StorageBackend:
    # Mirrors app.api.deps; S3 lands with its phase.
    return LocalStorage(settings.storage_local_root)


async def _materialize_apk(sample: Sample, dest_dir: Path) -> Path:
    """Copy the APK out of object storage into the sandbox's input directory.

    The sandbox bind-mounts this directory read-only, so the APK gets its own
    per-job dir — never the shared storage root.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    apk_path = dest_dir / f"{sample.sha256}.apk"
    data = await _storage().load(StorageBackend.sample_key(sample.sha256))
    await asyncio.to_thread(apk_path.write_bytes, data)
    return apk_path


async def _run(job_id: str) -> str:
    jid = uuid.UUID(job_id)

    async with AsyncSessionLocal() as session:
        job = await session.get(AnalysisJob, jid)
        if job is None:
            logger.warning("dynamic_job_missing", job_id=job_id)
            return "missing"
        if job.status == JobStatus.cancelled:
            return JobStatus.cancelled.value

        sample = await session.get(Sample, job.sample_id)
        if sample is None:  # pragma: no cover — FK guarantees this
            logger.warning("dynamic_sample_missing", job_id=job_id)
            return "missing"

        runner = get_sandbox_runner()

        # Resolve the engine version before claiming the stage, so a missing
        # install is reported against a truthful version string.
        try:
            engine, engine_version = _engine()
        except SandboxError as exc:
            stage = StageRunner(
                session, jid, engine_name=ENGINE_NAME, engine_version=_UNKNOWN_VERSION
            )
            await stage.begin()
            return (await stage.fail(exc)).status.value

        stage = StageRunner(
            session, jid, engine_name=ENGINE_NAME, engine_version=engine_version
        )

        workdir = job_artifacts_dir(jid)
        artifacts_dir = workdir / "artifacts"
        input_dir = workdir / "input"

        try:
            outcome = await _execute(
                stage=stage,
                runner=runner,
                engine=engine,
                sample=sample,
                job_id=job_id,
                input_dir=input_dir,
                artifacts_dir=artifacts_dir,
            )
        finally:
            # Artifacts came from a machine that ran malware — clear them unless
            # explicitly retained for debugging.
            if not settings.dynamic_keep_artifacts:
                await asyncio.to_thread(shutil.rmtree, workdir, True)

        return outcome.status.value


async def _execute(
    *,
    stage: StageRunner,
    runner: Any,
    engine: Any,
    sample: Sample,
    job_id: str,
    input_dir: Path,
    artifacts_dir: Path,
) -> StageOutcome:
    """Run the sandbox + engine, mapping every failure onto a stage status."""
    # Policy gate first: skip before copying a malware sample out of storage for
    # a sandbox that was never going to run it.
    if not runner.available:
        await stage.begin()
        return await stage.skip(runner.unavailable_reason())

    try:
        apk_path = await _materialize_apk(sample, input_dir)
    except FileNotFoundError as exc:
        await stage.begin()
        return await stage.fail(f"APK bytes missing from storage: {exc}")

    await stage.begin()

    try:
        await runner.run(apk_path, artifacts_dir, job_id=job_id)
    except SandboxDisabledError as exc:
        return await stage.skip(str(exc))
    except SandboxError as exc:
        return await stage.fail(exc)
    except Exception as exc:  # noqa: BLE001 — a stuck sandbox must not kill the job
        logger.exception("dynamic_sandbox_unexpected", job_id=job_id)
        return await stage.fail(exc)

    # Parsing is pure data handling, but artifacts are untrusted input.
    try:
        envelope = await asyncio.to_thread(
            engine.analyze, artifacts_dir, job_id=job_id
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("dynamic_engine_error", job_id=job_id)
        return await stage.fail(exc)

    return await stage.complete(envelope.model_dump(mode="json"))


@celery_app.task(
    name="dynamic.analyze",
    queue="dynamic",
    bind=True,
    max_retries=1,
    default_retry_delay=60,
    acks_late=True,
    # A sandbox run is minutes, not seconds; bound it generously but firmly.
    soft_time_limit=45 * 60,
    time_limit=50 * 60,
)
def analyze_dynamic(self, job_id: str) -> str:  # type: ignore[no-untyped-def]
    """Dynamic-analysis stage for a job. Best-effort: records, never re-raises.

    Returns the resulting stage status so a Celery chain can observe it.
    """
    try:
        return asyncio.run(_run(job_id))
    except Exception:  # noqa: BLE001
        # Everything recoverable is already mapped to a stage status inside
        # _run; reaching here means infrastructure trouble (DB down, etc.).
        logger.exception("dynamic_task_error", job_id=job_id)
        return StageStatus.failed.value
