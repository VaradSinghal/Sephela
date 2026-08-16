"""Tests for the AI stage's outcome mapping (app.tasks.ai._execute).

The AI stage is the seam between the Celery pipeline and the multi-agent graph in
``ai/``. What matters here is not the reasoning — that is covered by the graph's own
suite — but that every outcome of a run lands on the right stage status, and that
the evidence envelope handed to the agents is assembled from what the earlier
stages actually produced. Fakes stand in for the graph and the DB-backed
StageRunner, mirroring test_threat_intel_task.py.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from app.db.models.analysis import Sample, StageStatus
from app.services.stages import StageOutcome
from app.tasks import ai as task

JOB_ID = uuid.uuid4()
SHA256 = "a" * 64


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
        return StageOutcome(engine="ai_orchestrator", status=StageStatus.ok, findings=1)

    async def fail(self, exc: BaseException | str) -> StageOutcome:
        self.calls.append("fail")
        self.reason = str(exc)
        return StageOutcome(engine="ai_orchestrator", status=StageStatus.failed, error=str(exc))

    async def skip(self, reason: str) -> StageOutcome:
        self.calls.append("skip")
        self.reason = reason
        return StageOutcome(engine="ai_orchestrator", status=StageStatus.skipped, error=reason)


class FakeEvidenceRow:
    def __init__(self, engine_name: str, payload: dict[str, Any]) -> None:
        self.engine_name = engine_name
        self.payload = payload


class FakePipelineResult:
    def __init__(
        self,
        *,
        agent_results: dict[str, Any] | None = None,
        report: dict[str, Any] | None = None,
        risk_result: dict[str, Any] | None = None,
        errors: list[str] | None = None,
        warnings: list[str] | None = None,
        graph_state: dict[str, Any] | None = None,
    ) -> None:
        self.agent_results = agent_results if agent_results is not None else {}
        self.report = report if report is not None else {"verdict": "malicious"}
        self.risk_result = risk_result if risk_result is not None else {"score": 90}
        self.errors = errors or []
        self.warnings = warnings or []
        self.graph_state = graph_state or {}


class FakePipeline:
    """Stands in for ai.integration.SephelaAnalysisPipeline."""

    def __init__(self, result: Any = None, exc: Exception | None = None) -> None:
        self.result = result if result is not None else FakePipelineResult()
        self.exc = exc
        self.kwargs: dict[str, Any] = {}

    async def analyze(self, **kwargs: Any) -> Any:
        self.kwargs = kwargs
        if self.exc is not None:
            raise self.exc
        return self.result


@pytest.fixture
def sample() -> Sample:
    return Sample(id=uuid.uuid4(), sha256=SHA256)


@pytest.fixture
def evidence_rows(monkeypatch) -> list[FakeEvidenceRow]:
    """Patch the evidence repository to return a controllable set of rows."""
    rows: list[FakeEvidenceRow] = [
        FakeEvidenceRow("static", {"manifest": {"package": "com.example"}}),
        FakeEvidenceRow("threat_intel", {"verdicts": [{"malicious": True}]}),
    ]

    class FakeEvidenceRepo:
        def __init__(self, _session: Any) -> None:
            pass

        async def list_for_job(self, _job_id: uuid.UUID) -> list[FakeEvidenceRow]:
            return list(rows)

    monkeypatch.setattr(task, "EvidenceRepository", FakeEvidenceRepo)
    return rows


def _install_pipeline(monkeypatch, pipeline: FakePipeline) -> FakePipeline:
    class FakeBuilder:
        @staticmethod
        async def build_with_rag() -> FakePipeline:
            return pipeline

    monkeypatch.setattr(task, "SephelaAnalysisPipeline", FakeBuilder)
    return pipeline


async def _execute(stage: FakeStageRunner, sample: Sample) -> StageOutcome:
    return await task._execute(
        session=object(),
        stage=stage,
        job_id=str(JOB_ID),
        jid=JOB_ID,
        sample=sample,
    )


class TestEvidenceGate:
    async def test_no_evidence_skips_rather_than_failing(self, monkeypatch, sample) -> None:
        # With nothing extracted there is nothing to reason over. Failing here would
        # mark a job failed for a stage that was never given any input.
        class EmptyRepo:
            def __init__(self, _session: Any) -> None:
                pass

            async def list_for_job(self, _job_id: uuid.UUID) -> list[Any]:
                return []

        monkeypatch.setattr(task, "EvidenceRepository", EmptyRepo)
        stage = FakeStageRunner()

        outcome = await _execute(stage, sample)

        assert outcome.status is StageStatus.skipped
        assert stage.calls == ["begin", "skip"]
        assert "No evidence" in stage.reason


class TestEnvelopeAssembly:
    async def test_the_envelope_is_keyed_by_engine_name(
        self, monkeypatch, sample, evidence_rows
    ) -> None:
        pipeline = _install_pipeline(monkeypatch, FakePipeline())

        await _execute(FakeStageRunner(), sample)

        envelope = pipeline.kwargs["evidence_envelope"]
        assert set(envelope) == {"static", "threat_intel"}
        assert envelope["static"] == {"manifest": {"package": "com.example"}}

    async def test_the_sample_hash_and_job_id_are_passed_through(
        self, monkeypatch, sample, evidence_rows
    ) -> None:
        # The agents cite the sample they analysed, so a wrong hash here would
        # attribute findings to the wrong APK.
        pipeline = _install_pipeline(monkeypatch, FakePipeline())

        await _execute(FakeStageRunner(), sample)

        assert pipeline.kwargs["apk_sha256"] == SHA256
        assert pipeline.kwargs["job_id"] == str(JOB_ID)


class TestSuccess:
    async def test_a_completed_run_persists_report_risk_and_findings(
        self, monkeypatch, sample, evidence_rows
    ) -> None:
        result = FakePipelineResult(
            agent_results={
                "manifest_agent": {"findings": [{"title": "Exported receiver"}]},
                "network_agent": {"findings": [{"title": "Cleartext C2"}]},
            },
        )
        _install_pipeline(monkeypatch, FakePipeline(result))
        stage = FakeStageRunner()

        outcome = await _execute(stage, sample)

        assert outcome.status is StageStatus.ok
        assert stage.calls == ["begin", "complete"]
        assert stage.payload["report"] == {"verdict": "malicious"}
        assert stage.payload["risk_result"] == {"score": 90}
        assert len(stage.payload["findings"]) == 2

    async def test_findings_without_an_id_get_one_derived_from_their_agent(
        self, monkeypatch, sample, evidence_rows
    ) -> None:
        # Findings are deduplicated and cross-referenced downstream, so each needs a
        # stable identifier even when the agent did not supply one.
        result = FakePipelineResult(
            agent_results={"manifest_agent": {"findings": [{"title": "no id"}]}},
        )
        _install_pipeline(monkeypatch, FakePipeline(result))
        stage = FakeStageRunner()

        await _execute(stage, sample)

        assert stage.payload["findings"][0]["id"].startswith("manifest_agent-")

    async def test_an_agent_supplied_id_is_preserved(
        self, monkeypatch, sample, evidence_rows
    ) -> None:
        result = FakePipelineResult(
            agent_results={"manifest_agent": {"findings": [{"id": "MANIFEST-7"}]}},
        )
        _install_pipeline(monkeypatch, FakePipeline(result))
        stage = FakeStageRunner()

        await _execute(stage, sample)

        assert stage.payload["findings"][0]["id"] == "MANIFEST-7"

    async def test_agent_errors_are_carried_into_the_envelope(
        self, monkeypatch, sample, evidence_rows
    ) -> None:
        # A partial run must be visibly partial: the envelope's errors drive the
        # stage status the job aggregates.
        result = FakePipelineResult(errors=["code_agent: timed out"])
        _install_pipeline(monkeypatch, FakePipeline(result))
        stage = FakeStageRunner()

        await _execute(stage, sample)

        assert stage.payload["errors"] == ["code_agent: timed out"]


class TestFailure:
    async def test_a_crashing_pipeline_fails_the_stage_instead_of_the_worker(
        self, monkeypatch, sample, evidence_rows
    ) -> None:
        _install_pipeline(monkeypatch, FakePipeline(exc=RuntimeError("gateway down")))
        stage = FakeStageRunner()

        outcome = await _execute(stage, sample)

        assert outcome.status is StageStatus.failed
        assert stage.calls == ["begin", "fail"]
        assert "gateway down" in stage.reason

    async def test_a_failure_building_the_pipeline_is_also_contained(
        self, monkeypatch, sample, evidence_rows
    ) -> None:
        # Missing credentials surface here, and must not escape as a worker crash.
        class Exploding:
            @staticmethod
            async def build_with_rag() -> Any:
                raise RuntimeError("ANTHROPIC_API_KEY missing")

        monkeypatch.setattr(task, "SephelaAnalysisPipeline", Exploding)
        stage = FakeStageRunner()

        outcome = await _execute(stage, sample)

        assert outcome.status is StageStatus.failed
        assert "ANTHROPIC_API_KEY missing" in stage.reason
