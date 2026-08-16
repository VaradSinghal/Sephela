"""Tests for the graph's conditional-edge routing policy.

The routers are the pipeline's judgement calls about when partial analysis is still
worth scoring, so the thresholds are worth pinning exactly rather than approximately.
"""

from __future__ import annotations

from ai.orchestration.graph_state import AgentRunStatus, PipelineStatus, initial_state
from ai.orchestration.router import (
    abort_node,
    route_abort,
    route_after_report,
    route_after_risk,
    route_after_start,
    route_analysis_join,
)

ANALYSIS_AGENTS = (
    "manifest_agent",
    "permission_agent",
    "code_agent",
    "api_agent",
    "network_agent",
    "threat_intel_agent",
)


def _state(**overrides):
    state = initial_state(job_id="job-1", apk_sha256="a" * 64, evidence={"manifest": {}})
    state.update(overrides)
    return state


def _results(failed: int = 0, *, status: str = AgentRunStatus.FAILED.value):
    return {
        name: {"status": status if i < failed else AgentRunStatus.COMPLETED.value}
        for i, name in enumerate(ANALYSIS_AGENTS)
    }


class TestStartGate:
    def test_evidence_present_fans_out(self) -> None:
        assert route_after_start(_state()) == "fanout"

    def test_missing_evidence_aborts(self) -> None:
        assert route_after_start(_state(evidence={})) == "abort"

    def test_a_cancelled_job_aborts_even_with_evidence(self) -> None:
        state = _state(pipeline_status=PipelineStatus.CANCELLED.value)
        assert route_after_start(state) == "abort"


class TestAnalysisJoin:
    def test_all_six_succeeding_proceeds_to_risk(self) -> None:
        assert route_analysis_join(_state(agent_results=_results(0))) == "risk"

    def test_two_of_six_failing_still_proceeds(self) -> None:
        # A third of the evidence missing is degraded but still scoreable.
        assert route_analysis_join(_state(agent_results=_results(2))) == "risk"

    def test_three_of_six_failing_is_the_abort_threshold(self) -> None:
        # Exactly 50% — the boundary is inclusive, so this aborts.
        assert route_analysis_join(_state(agent_results=_results(3))) == "abort"

    def test_timeouts_count_as_failures_for_the_threshold(self) -> None:
        # A timed-out agent produced no evidence, same as a failed one.
        results = _results(3, status=AgentRunStatus.TIMED_OUT.value)
        assert route_analysis_join(_state(agent_results=results)) == "abort"

    def test_an_agent_that_never_reported_is_not_counted_as_failed(self) -> None:
        assert route_analysis_join(_state(agent_results={})) == "risk"


class TestRiskGate:
    def test_a_successful_risk_agent_proceeds_to_report(self) -> None:
        state = _state(
            agent_results={"risk_agent": {"status": AgentRunStatus.COMPLETED.value}},
            risk_result={"score": 42},
        )
        assert route_after_risk(state) == "report"

    def test_a_failed_risk_agent_with_no_result_aborts(self) -> None:
        state = _state(
            agent_results={"risk_agent": {"status": AgentRunStatus.FAILED.value}},
            risk_result=None,
        )
        assert route_after_risk(state) == "abort"

    def test_a_failed_risk_agent_that_still_produced_a_score_reports(self) -> None:
        # Degraded risk data is worth reporting; no risk data is not.
        state = _state(
            agent_results={"risk_agent": {"status": AgentRunStatus.FAILED.value}},
            risk_result={"score": 42},
        )
        assert route_after_risk(state) == "report"


class TestTerminalRoutes:
    def test_report_always_finalises_so_telemetry_flushes(self) -> None:
        assert route_after_report(_state()) == "finalise"

    def test_abort_always_finalises_too(self) -> None:
        assert route_abort(_state()) == "finalise"

    async def test_abort_names_missing_evidence_as_the_reason(self) -> None:
        update = await abort_node(_state(evidence={}))

        assert update["pipeline_status"] == PipelineStatus.FAILED.value
        assert update["error"] == "Evidence envelope missing"
        assert update["completed_at"]

    async def test_abort_names_the_agents_that_failed(self) -> None:
        update = await abort_node(_state(agent_results=_results(3)))

        assert "Too many agent failures" in update["error"]
        assert "code_agent" in update["error"]
