"""Tests for the dynamic stage's failure policy (app.tasks.dynamic._execute).

A dynamic run is best-effort: nothing it does may fail the surrounding job. These
tests pin the mapping from each failure mode onto a stage status, using fakes for
the sandbox, the engine, and the DB-backed StageRunner.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from app.db.models.analysis import Sample, StageStatus
from app.services.sandbox import SandboxDisabledError, SandboxError
from app.services.stages import StageOutcome
from app.tasks import dynamic as dyn


class FakeStageRunner:
    """Records which terminal method the task chose."""

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.payload: dict[str, Any] | None = None
        self.reason: str | None = None

    async def begin(self) -> str:
        self.calls.append("begin")
        return "stage-1"

    async def complete(self, payload: dict[str, Any], **_: Any) -> StageOutcome:
        self.calls.append("complete")
        self.payload = payload
        return StageOutcome(engine="dynamic", status=StageStatus.ok, findings=1)

    async def fail(self, exc: BaseException | str) -> StageOutcome:
        self.calls.append("fail")
        self.reason = str(exc)
        return StageOutcome(engine="dynamic", status=StageStatus.failed, error=str(exc))

    async def skip(self, reason: str) -> StageOutcome:
        self.calls.append("skip")
        self.reason = reason
        return StageOutcome(engine="dynamic", status=StageStatus.skipped, error=reason)


class FakeSandbox:
    def __init__(self, exc: BaseException | None = None, *, available: bool = True) -> None:
        self.exc = exc
        self.available = available
        self.ran = False

    def unavailable_reason(self) -> str:
        return "dynamic analysis is disabled"

    async def run(self, apk_path: Path, output_dir: Path, *, job_id: str) -> Path:
        self.ran = True
        if self.exc is not None:
            raise self.exc
        output_dir.mkdir(parents=True, exist_ok=True)
        return output_dir


class FakeEnvelope:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload

    def model_dump(self, **_: Any) -> dict[str, Any]:
        return self._payload


class FakeEngine:
    """Stands in for sephela_dynamic; ``analyze`` is sync, as the real one is."""

    def __init__(self, payload: dict[str, Any] | None = None, exc: Exception | None = None) -> None:
        self.payload = payload or {"envelope_version": "1.0", "status": "ok", "findings": []}
        self.exc = exc

    def analyze(self, artifacts_dir: Any, *, job_id: str | None = None) -> FakeEnvelope:
        if self.exc is not None:
            raise self.exc
        return FakeEnvelope(self.payload)


@pytest.fixture
def sample() -> Sample:
    return Sample(sha256="ab" * 32, file_size=1234, storage_uri="file:///tmp/x.apk")


@pytest.fixture(autouse=True)
def _stub_apk(monkeypatch, tmp_path: Path):
    """Pretend the APK materializes out of object storage."""

    async def _fake(sample: Sample, dest_dir: Path) -> Path:
        dest_dir.mkdir(parents=True, exist_ok=True)
        apk = dest_dir / f"{sample.sha256}.apk"
        apk.write_bytes(b"PK\x03\x04")
        return apk

    monkeypatch.setattr(dyn, "_materialize_apk", _fake)


async def _run(stage: FakeStageRunner, runner: Any, engine: Any, sample: Sample, tmp_path: Path):
    return await dyn._execute(
        stage=stage,  # type: ignore[arg-type]
        runner=runner,
        engine=engine,
        sample=sample,
        job_id="job-1",
        input_dir=tmp_path / "input",
        artifacts_dir=tmp_path / "artifacts",
    )


@pytest.mark.asyncio
async def test_happy_path_completes_with_envelope(sample: Sample, tmp_path: Path) -> None:
    stage, sandbox = FakeStageRunner(), FakeSandbox()
    payload = {"envelope_version": "1.0", "status": "ok", "findings": [{"type": "sms"}]}

    outcome = await _run(stage, sandbox, FakeEngine(payload), sample, tmp_path)

    assert sandbox.ran
    assert stage.calls == ["begin", "complete"]
    assert stage.payload == payload
    assert outcome.status is StageStatus.ok


@pytest.mark.asyncio
async def test_unavailable_sandbox_skips_without_touching_the_apk(
    sample: Sample, tmp_path: Path
) -> None:
    """Policy-off is not an error, and must not copy malware bytes for nothing."""
    stage = FakeStageRunner()
    sandbox = FakeSandbox(available=False)

    outcome = await _run(stage, sandbox, FakeEngine(), sample, tmp_path)

    assert stage.calls == ["begin", "skip"]
    assert outcome.status is StageStatus.skipped
    assert "disabled" in (stage.reason or "")
    assert not sandbox.ran
    assert not (tmp_path / "input").exists()  # APK never materialized


@pytest.mark.asyncio
async def test_disabled_error_from_run_still_skips(sample: Sample, tmp_path: Path) -> None:
    """Defence in depth: a runner that reports available but refuses still skips."""
    stage = FakeStageRunner()
    sandbox = FakeSandbox(SandboxDisabledError("dynamic analysis is disabled"))

    outcome = await _run(stage, sandbox, FakeEngine(), sample, tmp_path)

    assert stage.calls == ["begin", "skip"]
    assert outcome.status is StageStatus.skipped


@pytest.mark.asyncio
async def test_sandbox_error_fails_the_stage_only(sample: Sample, tmp_path: Path) -> None:
    stage = FakeStageRunner()
    sandbox = FakeSandbox(SandboxError("emulator did not boot"))

    outcome = await _run(stage, sandbox, FakeEngine(), sample, tmp_path)

    assert stage.calls == ["begin", "fail"]
    assert outcome.status is StageStatus.failed
    assert "emulator did not boot" in (stage.reason or "")


@pytest.mark.asyncio
async def test_unexpected_sandbox_exception_is_contained(sample: Sample, tmp_path: Path) -> None:
    """An unforeseen sandbox crash must not propagate out of the stage."""
    stage = FakeStageRunner()
    sandbox = FakeSandbox(RuntimeError("docker socket vanished"))

    outcome = await _run(stage, sandbox, FakeEngine(), sample, tmp_path)

    assert stage.calls == ["begin", "fail"]
    assert outcome.status is StageStatus.failed


@pytest.mark.asyncio
async def test_engine_parse_error_fails_the_stage(sample: Sample, tmp_path: Path) -> None:
    """Artifacts are untrusted input; a parser blow-up is a stage failure."""
    stage = FakeStageRunner()
    engine = FakeEngine(exc=ValueError("corrupt frida trace"))

    outcome = await _run(stage, FakeSandbox(), engine, sample, tmp_path)

    assert stage.calls == ["begin", "fail"]
    assert outcome.status is StageStatus.failed
    assert "corrupt frida trace" in (stage.reason or "")


@pytest.mark.asyncio
async def test_missing_apk_bytes_fail_before_the_sandbox_runs(
    sample: Sample, tmp_path: Path, monkeypatch
) -> None:
    async def _boom(sample: Sample, dest_dir: Path) -> Path:
        raise FileNotFoundError("samples/ab/ab/....apk")

    monkeypatch.setattr(dyn, "_materialize_apk", _boom)
    stage, sandbox = FakeStageRunner(), FakeSandbox()

    outcome = await _run(stage, sandbox, FakeEngine(), sample, tmp_path)

    assert not sandbox.ran  # never hand a missing file to the sandbox
    assert stage.calls == ["begin", "fail"]
    assert outcome.status is StageStatus.failed
