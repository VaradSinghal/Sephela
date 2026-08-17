"""Tests for the stage tasks' DB-driven outer wrappers (``_run``) and entrypoints.

The per-stage suites cover ``_execute`` — the failure-policy mapping. This module
covers the layer around it, which carries three claims that are easy to state in a
docstring and never verify:

- **A missing engine install is a failed stage, not a dead worker.** Engines are
  separate distributions, so a deployment that skipped one must degrade to a
  recorded failure with a readable message.
- **A cancelled job is not restarted.** Every stage re-reads state from the DB
  rather than trusting the message, so a stage that fires after a cancel must
  notice and stop.
- **The Celery entrypoint never re-raises.** Infrastructure trouble returns a
  ``failed`` status so the chain continues to ``finalize`` instead of stranding the
  job as permanently ``running``.

The engine version is resolved *before* the stage row is claimed so a missing
install is reported against a truthful version rather than a fabricated one; that
ordering is asserted here too.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from app.db.models.analysis import AnalysisJob, JobStatus, Sample, StageStatus
from app.tasks import code_intel as ci
from app.tasks import reporting as rpt
from app.tasks import scoring as sc
from app.tasks import static as st

JOB_ID = uuid.uuid4()
SAMPLE_ID = uuid.uuid4()


class FakeSession:
    """Serves ``session.get`` from a dict, as the stages' only DB access."""

    def __init__(self, objects: dict[Any, Any]) -> None:
        self.objects = objects
        self.commits = 0

    async def get(self, model: Any, pk: Any) -> Any:
        return self.objects.get((model, pk))

    async def commit(self) -> None:
        self.commits += 1

    async def __aenter__(self) -> FakeSession:
        return self

    async def __aexit__(self, *_: Any) -> None:
        return None


def _job(status: JobStatus = JobStatus.running) -> AnalysisJob:
    job = AnalysisJob(
        id=JOB_ID,
        sample_id=SAMPLE_ID,
        status=status,
        pipeline_version="1.0.0",
        progress=0,
    )
    return job


def _sample() -> Sample:
    return Sample(id=SAMPLE_ID, sha256="ab" * 32, file_size=1234, storage_uri="file:///tmp/x.apk")


def _session(status: JobStatus = JobStatus.running, *, with_sample: bool = True) -> FakeSession:
    objects: dict[Any, Any] = {(AnalysisJob, JOB_ID): _job(status)}
    if with_sample:
        objects[(Sample, SAMPLE_ID)] = _sample()
    return FakeSession(objects)


class RecordingStage:
    """A StageRunner stand-in that records the version it was constructed with."""

    instances: list[RecordingStage] = []

    def __init__(self, _session: Any, _jid: Any, *, engine_name: str, engine_version: str) -> None:
        self.engine_name = engine_name
        self.engine_version = engine_version
        self.calls: list[str] = []
        self.reason: str | None = None
        RecordingStage.instances.append(self)

    async def begin(self) -> str:
        self.calls.append("begin")
        return "stage-1"

    async def fail(self, exc: BaseException | str) -> Any:
        self.calls.append("fail")
        self.reason = str(exc)

        class Outcome:
            status = StageStatus.failed

        return Outcome()

    async def skip(self, reason: str) -> Any:  # pragma: no cover — not reached here
        self.calls.append("skip")

        class Outcome:
            status = StageStatus.skipped

        return Outcome()


# (module, unavailable-error attribute, expected install hint)
MODULES = [
    (st, "StaticEngineUnavailableError", "engines/static"),
    (ci, "CodeIntelUnavailableError", "engines/code_intel"),
    (rpt, "ReportingUnavailableError", "engines/reporting"),
]


@pytest.fixture(autouse=True)
def _reset():
    RecordingStage.instances.clear()
    yield
    RecordingStage.instances.clear()


@pytest.mark.parametrize(("module", "error_name", "hint"), MODULES)
@pytest.mark.asyncio
async def test_a_missing_engine_install_fails_the_stage(
    module: Any, error_name: str, hint: str, monkeypatch
) -> None:
    exc_type = getattr(module, error_name)

    def _missing() -> Any:
        raise exc_type(f"not installed (pip install -e {hint}).")

    monkeypatch.setattr(module, "_engine", _missing)
    monkeypatch.setattr(module, "AsyncSessionLocal", lambda: _session())
    monkeypatch.setattr(module, "StageRunner", RecordingStage)

    result = await module._run(str(JOB_ID))

    assert result == StageStatus.failed.value
    stage = RecordingStage.instances[-1]
    assert stage.calls == ["begin", "fail"]
    assert hint in (stage.reason or "")
    # Reported against a truthful version, not a fabricated one.
    assert stage.engine_version == module._UNKNOWN_VERSION


@pytest.mark.parametrize(("module", "_error_name", "_hint"), MODULES)
@pytest.mark.asyncio
async def test_a_cancelled_job_stops_the_stage(
    module: Any, _error_name: str, _hint: str, monkeypatch
) -> None:
    # Stages re-read state from the DB rather than trusting the message, so one
    # that fires after a cancel must notice.
    monkeypatch.setattr(module, "AsyncSessionLocal", lambda: _session(JobStatus.cancelled))
    monkeypatch.setattr(module, "StageRunner", RecordingStage)

    assert await module._run(str(JOB_ID)) == JobStatus.cancelled.value
    assert RecordingStage.instances == []


@pytest.mark.asyncio
async def test_scoring_also_stops_on_a_cancelled_job(monkeypatch) -> None:
    monkeypatch.setattr(sc, "AsyncSessionLocal", lambda: _session(JobStatus.cancelled))
    monkeypatch.setattr(sc, "StageRunner", RecordingStage)

    assert await sc._run(str(JOB_ID)) == JobStatus.cancelled.value


@pytest.mark.parametrize("module", [st, ci, rpt, sc])
@pytest.mark.asyncio
async def test_a_missing_job_is_reported_not_raised(module: Any, monkeypatch) -> None:
    monkeypatch.setattr(module, "AsyncSessionLocal", lambda: FakeSession({}))
    monkeypatch.setattr(module, "StageRunner", RecordingStage)

    assert await module._run(str(JOB_ID)) == "missing"


@pytest.mark.parametrize("module", [st, ci, rpt])
@pytest.mark.asyncio
async def test_a_missing_sample_is_reported_not_raised(module: Any, monkeypatch) -> None:
    monkeypatch.setattr(module, "AsyncSessionLocal", lambda: _session(with_sample=False))
    monkeypatch.setattr(module, "StageRunner", RecordingStage)

    assert await module._run(str(JOB_ID)) == "missing"


TASKS = [
    (st, "analyze_static"),
    (ci, "analyze_code_intel"),
    (sc, "analyze_scoring"),
    (rpt, "analyze_reporting"),
]


@pytest.mark.parametrize(("module", "task_name"), TASKS)
def test_the_entrypoint_contains_infrastructure_failures(
    module: Any, task_name: str, monkeypatch
) -> None:
    # A DB outage must not leave the job stranded as `running`: returning `failed`
    # lets the chain reach finalize, which derives a truthful job status.
    async def _boom(_job_id: str) -> str:
        raise OSError("postgres is gone")

    monkeypatch.setattr(module, "_run", _boom)

    assert getattr(module, task_name).run(str(JOB_ID)) == StageStatus.failed.value


@pytest.mark.parametrize(("module", "task_name"), TASKS)
def test_the_entrypoint_returns_the_stage_status(module: Any, task_name: str, monkeypatch) -> None:
    async def _ok(_job_id: str) -> str:
        return StageStatus.ok.value

    monkeypatch.setattr(module, "_run", _ok)

    assert getattr(module, task_name).run(str(JOB_ID)) == StageStatus.ok.value


class TestLazyEngineImports:
    """The engine importers resolve the real distributions when installed."""

    @pytest.mark.parametrize("module", [st, ci, rpt])
    def test_the_engine_and_a_version_are_returned(self, module: Any) -> None:
        engine, version = module._engine()

        assert engine is not None
        assert isinstance(version, str) and version

    def test_scoring_reports_a_missing_ai_package_as_a_failed_stage(self, monkeypatch) -> None:
        # `ai` is a separate distribution too, and the scoring stage imports it
        # inside _execute for exactly this reason.
        import builtins

        real_import = builtins.__import__

        def _blocked(name: str, *args: Any, **kwargs: Any) -> Any:
            if name == "ai.scoring":
                raise ImportError("No module named 'ai'")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", _blocked)

        import asyncio

        class Session:
            async def commit(self) -> None:
                pass

        stage = RecordingStage(None, None, engine_name="scoring", engine_version="1.0.0")
        outcome = asyncio.run(
            sc._execute(
                session=Session(),  # type: ignore[arg-type]
                stage=stage,  # type: ignore[arg-type]
                job=_job(),
                job_id=str(JOB_ID),
                jid=JOB_ID,
            )
        )

        assert outcome.status is StageStatus.failed
        assert "pip install -e ai" in (stage.reason or "")
