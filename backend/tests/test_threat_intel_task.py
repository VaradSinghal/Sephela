"""Tests for the threat-intel stage's failure policy (app.tasks.threat_intel._execute)
and for the IoC gathering that feeds it.

Enrichment is best-effort: nothing it does may fail the surrounding job. These
tests pin the mapping from each condition onto a stage status, using fakes for the
engine and the DB-backed StageRunner — mirroring test_dynamic_task.py.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from app.db.models.analysis import Sample, StageStatus
from app.services import threat_intel as svc
from app.services.stages import StageOutcome
from app.tasks import threat_intel as task


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
        return StageOutcome(engine="threat_intel", status=StageStatus.ok, findings=1)

    async def fail(self, exc: BaseException | str) -> StageOutcome:
        self.calls.append("fail")
        self.reason = str(exc)
        return StageOutcome(engine="threat_intel", status=StageStatus.failed, error=str(exc))

    async def skip(self, reason: str) -> StageOutcome:
        self.calls.append("skip")
        self.reason = reason
        return StageOutcome(engine="threat_intel", status=StageStatus.skipped, error=reason)


class FakeEnvelope:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload

    def model_dump(self, **_: Any) -> dict[str, Any]:
        return self._payload


class FakeEngine:
    """Stands in for sephela_threat_intel; ``analyze`` is async, as the real one is."""

    def __init__(
        self, payload: dict[str, Any] | None = None, exc: Exception | None = None
    ) -> None:
        self.payload = payload or {
            "envelope_version": "1.0",
            "status": "ok",
            "findings": [],
        }
        self.exc = exc
        self.kwargs: dict[str, Any] = {}
        self.iocs: Any = None

    async def analyze(self, iocs: Any, **kwargs: Any) -> FakeEnvelope:
        self.iocs = iocs
        self.kwargs = kwargs
        if self.exc is not None:
            raise self.exc
        return FakeEnvelope(self.payload)


JOB_ID = uuid.uuid4()


@pytest.fixture
def sample() -> Sample:
    return Sample(sha256="ab" * 32, md5="cd" * 16, file_size=1234, storage_uri="file:///tmp/x.apk")


@pytest.fixture(autouse=True)
def _enabled(monkeypatch):
    """Default the policy on and give the deployment one provider."""
    monkeypatch.setattr(task.settings, "threat_intel_enabled", True)
    monkeypatch.setattr(task, "build_providers", lambda: [object()])
    return None


@pytest.fixture(autouse=True)
def _stub_iocs(monkeypatch):
    """Pretend upstream evidence yielded one indicator."""

    async def _fake(session: Any, job_id: uuid.UUID, sample: Sample) -> list[str]:
        return ["hash:" + sample.sha256]

    monkeypatch.setattr(task, "gather_iocs", _fake)
    return None


async def _run(stage: FakeStageRunner, engine: Any, sample: Sample) -> StageOutcome:
    return await task._execute(
        session=None,  # type: ignore[arg-type]
        stage=stage,  # type: ignore[arg-type]
        engine=engine,
        job_id=str(JOB_ID),
        jid=JOB_ID,
        sample=sample,
    )


class TestStagePolicy:
    async def test_happy_path_completes_with_envelope(self, sample: Sample) -> None:
        stage = FakeStageRunner()
        payload = {"envelope_version": "1.0", "status": "ok", "findings": [{"type": "ioc_match"}]}

        outcome = await _run(stage, FakeEngine(payload), sample)

        assert stage.calls == ["begin", "complete"]
        assert stage.payload == payload
        assert outcome.status is StageStatus.ok

    async def test_disabled_by_policy_skips(self, sample: Sample, monkeypatch) -> None:
        monkeypatch.setattr(task.settings, "threat_intel_enabled", False)
        stage = FakeStageRunner()

        outcome = await _run(stage, FakeEngine(), sample)

        assert stage.calls == ["begin", "skip"]
        assert outcome.status is StageStatus.skipped
        assert "disabled" in (stage.reason or "")

    async def test_no_configured_providers_fails_the_stage(
        self, sample: Sample, monkeypatch
    ) -> None:
        # Not a skip: the operator intended enrichment and it silently could not
        # happen, which must be visible rather than read as "nothing found".
        monkeypatch.setattr(task, "build_providers", lambda: [])
        stage = FakeStageRunner()

        outcome = await _run(stage, FakeEngine(), sample)

        assert stage.calls == ["begin", "fail"]
        assert outcome.status is StageStatus.failed
        assert "provider API key" in (stage.reason or "")

    async def test_no_indicators_skips_rather_than_implying_a_clean_result(
        self, sample: Sample, monkeypatch
    ) -> None:
        async def _none(session: Any, job_id: uuid.UUID, sample: Sample) -> list[str]:
            return []

        monkeypatch.setattr(task, "gather_iocs", _none)
        stage, engine = FakeStageRunner(), FakeEngine()

        outcome = await _run(stage, engine, sample)

        assert stage.calls == ["begin", "skip"]
        assert outcome.status is StageStatus.skipped
        assert engine.iocs is None  # engine never invoked

    async def test_ioc_query_failure_fails_the_stage_only(
        self, sample: Sample, monkeypatch
    ) -> None:
        async def _boom(session: Any, job_id: uuid.UUID, sample: Sample) -> list[str]:
            raise RuntimeError("findings query exploded")

        monkeypatch.setattr(task, "gather_iocs", _boom)
        stage = FakeStageRunner()

        outcome = await _run(stage, FakeEngine(), sample)

        assert stage.calls == ["begin", "fail"]
        assert outcome.status is StageStatus.failed
        assert "findings query exploded" in (stage.reason or "")

    async def test_engine_error_fails_the_stage_only(self, sample: Sample) -> None:
        stage = FakeStageRunner()
        engine = FakeEngine(exc=ValueError("provider response was garbage"))

        outcome = await _run(stage, engine, sample)

        assert stage.calls == ["begin", "fail"]
        assert outcome.status is StageStatus.failed
        assert "provider response was garbage" in (stage.reason or "")

    async def test_partial_envelope_still_completes(self, sample: Sample) -> None:
        # A feed outage is a partial result, not a failure — StageRunner derives
        # the status from the envelope, so the task must still call complete().
        stage = FakeStageRunner()
        payload = {
            "envelope_version": "1.0",
            "status": "partial",
            "findings": [],
            "errors": [{"extractor": "virustotal", "message": "rate limited"}],
        }

        await _run(stage, FakeEngine(payload), sample)

        assert stage.calls == ["begin", "complete"]
        assert stage.payload == payload


class TestEngineInvocation:
    async def test_cost_controls_are_passed_through_from_config(
        self, sample: Sample, monkeypatch
    ) -> None:
        monkeypatch.setattr(task.settings, "threat_intel_max_lookups", 42)
        monkeypatch.setattr(task.settings, "threat_intel_concurrency", 3)
        monkeypatch.setattr(task.settings, "threat_intel_timeout_secs", 7.5)
        monkeypatch.setattr(task.settings, "threat_intel_breaker_threshold", 2)
        stage, engine = FakeStageRunner(), FakeEngine()

        await _run(stage, engine, sample)

        assert engine.kwargs["max_lookups"] == 42
        assert engine.kwargs["concurrency"] == 3
        assert engine.kwargs["timeout_secs"] == 7.5
        assert engine.kwargs["breaker_threshold"] == 2

    async def test_the_sample_hash_and_job_id_reach_the_envelope(self, sample: Sample) -> None:
        stage, engine = FakeStageRunner(), FakeEngine()

        await _run(stage, engine, sample)

        assert engine.kwargs["job_id"] == str(JOB_ID)
        assert engine.kwargs["apk_sha256"] == sample.sha256

    async def test_a_postgres_backed_cache_is_supplied(self, sample: Sample) -> None:
        # The cache is what makes the stage affordable and retries cheap.
        from app.repositories.enrichment import EnrichmentCacheRepository

        stage, engine = FakeStageRunner(), FakeEngine()
        await _run(stage, engine, sample)

        cache = engine.kwargs["cache"]
        assert isinstance(cache, EnrichmentCacheRepository)
        assert cache.job_id == JOB_ID


class TestProviderConfiguration:
    def test_api_keys_map_every_provider_name(self) -> None:
        from sephela_threat_intel.providers import PROVIDER_REGISTRY

        # A provider added to the registry without a key mapping here would be
        # permanently unconfigurable.
        assert set(svc.api_keys()) == set(PROVIDER_REGISTRY)

    def test_keyless_providers_survive_an_empty_config(self, monkeypatch) -> None:
        for attr in (
            "virustotal_api_key",
            "otx_api_key",
            "abuseipdb_api_key",
            "urlhaus_api_key",
            "bazaar_api_key",
        ):
            monkeypatch.setattr(svc.settings, attr, None)

        names = {p.name for p in svc.build_providers()}
        assert names == {"urlhaus", "bazaar"}

    def test_configured_keys_add_their_providers(self, monkeypatch) -> None:
        monkeypatch.setattr(svc.settings, "virustotal_api_key", "vt-key")
        monkeypatch.setattr(svc.settings, "otx_api_key", None)
        monkeypatch.setattr(svc.settings, "abuseipdb_api_key", None)

        names = {p.name for p in svc.build_providers()}
        assert "virustotal" in names
        assert "otx" not in names


class TestPipelineWiring:
    def test_the_stage_is_dispatched_when_enabled(self, monkeypatch) -> None:
        from app.tasks import pipeline

        monkeypatch.setattr(pipeline.settings, "dynamic_enabled", False)
        monkeypatch.setattr(pipeline.settings, "threat_intel_enabled", True)

        dispatched: list[Any] = []
        monkeypatch.setattr(pipeline, "chain", lambda *sigs: _FakeChain(sigs, dispatched))
        _stub_claim(monkeypatch)

        pipeline.analyze.run(str(JOB_ID))

        names = [s["task"] for s in dispatched]
        assert names == ["threat_intel.analyze", "pipeline.finalize"]

    def test_the_stage_is_omitted_when_disabled(self, monkeypatch) -> None:
        from app.tasks import pipeline

        monkeypatch.setattr(pipeline.settings, "dynamic_enabled", False)
        monkeypatch.setattr(pipeline.settings, "threat_intel_enabled", False)

        dispatched: list[Any] = []
        monkeypatch.setattr(pipeline, "chain", lambda *sigs: _FakeChain(sigs, dispatched))
        _stub_claim(monkeypatch)

        pipeline.analyze.run(str(JOB_ID))

        assert [s["task"] for s in dispatched] == ["pipeline.finalize"]

    def test_threat_intel_runs_after_dynamic_analysis(self, monkeypatch) -> None:
        # It enriches what the analysis engines produced, so it must come later.
        from app.tasks import pipeline

        monkeypatch.setattr(pipeline.settings, "dynamic_enabled", True)
        monkeypatch.setattr(pipeline.settings, "threat_intel_enabled", True)

        dispatched: list[Any] = []
        monkeypatch.setattr(pipeline, "chain", lambda *sigs: _FakeChain(sigs, dispatched))
        _stub_claim(monkeypatch)

        pipeline.analyze.run(str(JOB_ID))

        names = [s["task"] for s in dispatched]
        assert names.index("dynamic.analyze") < names.index("threat_intel.analyze")


def _stub_claim(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Let ``analyze`` reach its dispatch step without a database.

    Replaces the job-claiming coroutine rather than ``asyncio.run`` itself, so the
    task's real control flow (including the await) is exercised.
    """
    from app.tasks import pipeline

    async def _claimed(job_id: str) -> str:
        return "running"

    monkeypatch.setattr(pipeline, "_start", _claimed)


class _FakeChain:
    """Captures the signatures a dispatch would have enqueued."""

    def __init__(self, signatures: tuple[Any, ...], sink: list[Any]) -> None:
        self.signatures = signatures
        self.sink = sink

    def apply_async(self) -> None:
        self.sink.extend(self.signatures)
