"""Tests for PipelineRunner — the checkpointed, resumable face of the workflow.

These run the real compiled graph against a real LangGraph checkpointer, because
the thing most worth testing here is precisely the part that is easy to get wrong:
a checkpointer that satisfies the graph engine's contract, and a ``thread_id`` that
makes a half-finished run findable again.
"""

from __future__ import annotations

import pytest

from ai.orchestration.checkpointer import get_checkpointer
from ai.orchestration.graph_state import PipelineStatus
from ai.orchestration.runner import PipelineRunner
from ai.orchestration.workflow import WorkflowConfig
from ai.tests.test_orchestration.test_workflow import (
    _CLASS_BY_AGENT,
    ANALYSIS_AGENTS,
    EVIDENCE,
    StubFleet,
)


@pytest.fixture
def fleet(monkeypatch):
    def _install(behaviours: dict[str, str] | None = None) -> StubFleet:
        f = StubFleet(behaviours)
        for agent_name, class_name in _CLASS_BY_AGENT.items():
            monkeypatch.setattr(
                f"ai.orchestration.workflow.{class_name}", f.factory(agent_name)
            )
        return f

    return _install


def _runner(**kwargs) -> PipelineRunner:
    return PipelineRunner(
        llm_client=object(),
        config=WorkflowConfig(max_retries=0),
        **kwargs,
    )


class TestCheckpointerContract:
    def test_development_gets_a_saver_that_implements_the_async_contract(self) -> None:
        # A saver missing the async methods compiles fine and then fails at the
        # first node boundary, so assert the contract up front.
        cp = get_checkpointer("development")

        for method in ("aget_tuple", "aput", "aput_writes"):
            impl = getattr(type(cp), method)
            assert "BaseCheckpointSaver" not in impl.__qualname__, (
                f"{method} is not implemented by {type(cp).__name__}"
            )

    def test_production_refuses_to_run_without_a_dsn(self) -> None:
        # Falling back to in-memory here would lose every in-flight job on restart.
        with pytest.raises(ValueError, match="Connection string required"):
            get_checkpointer("production")


class TestRun:
    async def test_a_successful_run_reports_completed_with_its_report(self, fleet) -> None:
        fleet()
        result = await _runner().run("job-1", "a" * 64, EVIDENCE)

        assert result.status is PipelineStatus.COMPLETED
        assert result.job_id == "job-1"
        assert result.report == {"summary": "report_agent ok"}
        assert result.risk_score is None  # stub risk output carries no score
        assert result.execution_time_ms >= 0
        assert result.completed_at is not None

    async def test_findings_from_every_analysis_agent_survive_to_the_result(self, fleet) -> None:
        fleet()
        result = await _runner().run("job-2", "b" * 64, EVIDENCE)

        assert len(result.all_findings) == len(ANALYSIS_AGENTS)

    async def test_risk_score_and_tier_are_lifted_out_of_the_risk_result(self, fleet) -> None:
        f = fleet()
        runner = _runner()
        f.agents["risk_agent"].output = {"score": 87.5, "tier": "critical"}

        result = await runner.run("job-3", "c" * 64, EVIDENCE)

        assert result.risk_score == 87.5
        assert result.risk_tier == "critical"

    async def test_missing_evidence_surfaces_as_a_failed_result(self, fleet) -> None:
        fleet()
        result = await _runner().run("job-4", "d" * 64, {})

        assert result.status is PipelineStatus.FAILED
        assert result.error == "Evidence envelope missing"

    async def test_a_graph_level_crash_is_returned_not_raised(self, fleet, monkeypatch) -> None:
        # The Celery task needs a result object to write a stage status from, so a
        # crash inside the graph engine must not propagate out of run().
        fleet()
        runner = _runner()

        async def boom(*_a, **_k):
            raise RuntimeError("graph engine exploded")

        monkeypatch.setattr(runner.compiled_graph, "ainvoke", boom)
        result = await runner.run("job-5", "e" * 64, EVIDENCE)

        assert result.status is PipelineStatus.FAILED
        assert "graph engine exploded" in result.error
        assert result.errors == ["graph engine exploded"]


class TestStatusAndResume:
    async def test_status_is_none_for_a_job_that_never_ran(self, fleet) -> None:
        fleet()
        assert await _runner().get_status("never-seen") is None

    async def test_status_reports_the_agents_completed_so_far(self, fleet) -> None:
        fleet()
        runner = _runner()
        await runner.run("job-6", "f" * 64, EVIDENCE)

        status = await runner.get_status("job-6")

        assert status is not None
        assert status["job_id"] == "job-6"
        assert status["status"] == PipelineStatus.COMPLETED.value
        assert set(status["completed_agents"]) == set(_CLASS_BY_AGENT)

    async def test_resuming_an_unknown_job_is_an_error_not_a_fresh_run(self, fleet) -> None:
        # Silently starting over would re-bill every agent call.
        fleet()
        with pytest.raises(ValueError, match="No checkpoint found"):
            await _runner().resume("never-seen")

    async def test_state_is_keyed_on_the_job_so_runs_do_not_collide(self, fleet) -> None:
        fleet()
        runner = _runner()
        await runner.run("job-a", "1" * 64, EVIDENCE)
        await runner.run("job-b", "2" * 64, EVIDENCE)

        assert (await runner.get_status("job-a"))["job_id"] == "job-a"
        assert (await runner.get_status("job-b"))["job_id"] == "job-b"


class TestConfigWiring:
    def test_explicit_config_keeps_its_timeouts_but_gains_the_wiring(self, fleet) -> None:
        fleet()
        cfg = WorkflowConfig(analysis_timeout_s=7.0, max_retries=0)
        client, knowledge = object(), object()

        runner = PipelineRunner(llm_client=client, knowledge=knowledge, config=cfg)

        assert runner.config.analysis_timeout_s == 7.0
        assert runner.config.llm_client is client
        assert runner.config.knowledge is knowledge
        assert runner.config.checkpointer is runner.checkpointer

    def test_an_explicit_client_on_the_config_is_not_overwritten(self, fleet) -> None:
        fleet()
        own_client = object()
        cfg = WorkflowConfig(llm_client=own_client, max_retries=0)

        runner = PipelineRunner(llm_client=object(), config=cfg)

        assert runner.config.llm_client is own_client
