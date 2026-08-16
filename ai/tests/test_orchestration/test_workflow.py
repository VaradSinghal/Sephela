"""End-to-end tests for the Phase-13 multi-agent LangGraph workflow.

These drive the *real* compiled graph — the same ``build_workflow`` the Celery AI
stage runs — with the eight agents swapped for stubs. That keeps the assertions on
the parts we own (topology, fan-out/fan-in, per-agent failure isolation, the abort
policy, and how state is reduced) without needing a live LLM.

The agent classes are patched at their import site in ``ai.orchestration.workflow``
rather than at their definitions, because that module binds them at import time.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from ai.agents.base import AgentConfig, AgentResult, AgentStatus
from ai.orchestration.graph_state import (
    AgentRunStatus,
    PipelineStatus,
    all_analysis_agents_done,
    initial_state,
)
from ai.orchestration.workflow import WorkflowConfig, build_workflow

ANALYSIS_AGENTS = (
    "manifest_agent",
    "permission_agent",
    "code_agent",
    "api_agent",
    "network_agent",
    "threat_intel_agent",
)

EVIDENCE = {"manifest": {"package": "com.example.bank"}, "code_intel": {"strings": []}}


# ---------------------------------------------------------------------------
# Stub agent
# ---------------------------------------------------------------------------


class StubAgent:
    """Duck-typed stand-in for BaseAgent.

    The node factories only ever touch ``config.name`` and ``execute()``, so a stub
    does not need the schema/prompt machinery a real agent carries.
    """

    def __init__(
        self,
        name: str,
        *,
        behaviour: str = "ok",
        output: dict[str, Any] | None = None,
        findings: list[dict[str, Any]] | None = None,
        delay_s: float = 0.0,
        **_ignored: Any,
    ) -> None:
        self.config = AgentConfig(name=name)
        self.behaviour = behaviour
        self.output = output if output is not None else {"summary": f"{name} ok"}
        self.findings = findings or []
        self.delay_s = delay_s
        self.calls: list[dict[str, Any]] = []

    async def execute(
        self, evidence: dict[str, Any], context: dict[str, Any]
    ) -> AgentResult:
        self.calls.append({"evidence": evidence, "context": dict(context)})

        if self.delay_s:
            await asyncio.sleep(self.delay_s)
        if self.behaviour == "raise":
            raise RuntimeError(f"{self.config.name} blew up")

        return AgentResult(
            agent_name=self.config.name,
            status=AgentStatus.completed,
            output=self.output,
            findings=list(self.findings),
            tokens_used=11,
            model_name="stub-model",
        )


class StubFleet:
    """Builds and remembers one StubAgent per agent name."""

    def __init__(
        self,
        behaviours: dict[str, str] | None = None,
        delays: dict[str, float] | None = None,
    ):
        self.behaviours = behaviours or {}
        self.delays = delays or {}
        self.agents: dict[str, StubAgent] = {}

    def factory(self, name: str):
        def _build(**kwargs: Any) -> StubAgent:
            agent = StubAgent(
                name,
                behaviour=self.behaviours.get(name, "ok"),
                delay_s=self.delays.get(name, 0.0),
                findings=[{"id": f"{name}-1", "title": f"{name} finding"}]
                if name in ANALYSIS_AGENTS
                else [],
                **kwargs,
            )
            self.agents[name] = agent
            return agent

        return _build


_CLASS_BY_AGENT = {
    "manifest_agent": "ManifestAgent",
    "permission_agent": "PermissionAgent",
    "code_agent": "CodeAgent",
    "api_agent": "APIAgent",
    "network_agent": "NetworkAgent",
    "threat_intel_agent": "ThreatIntelAgent",
    "risk_agent": "RiskAgent",
    "report_agent": "ReportAgent",
}


@pytest.fixture
def fleet(monkeypatch):
    """Patch every agent class in the workflow module with a stub factory."""

    def _install(
        behaviours: dict[str, str] | None = None,
        delays: dict[str, float] | None = None,
    ) -> StubFleet:
        f = StubFleet(behaviours, delays)
        for agent_name, class_name in _CLASS_BY_AGENT.items():
            monkeypatch.setattr(
                f"ai.orchestration.workflow.{class_name}", f.factory(agent_name)
            )
        return f

    return _install


def _config(**kwargs: Any) -> WorkflowConfig:
    # max_retries=0 keeps the failure paths fast: the outer retry loop sleeps
    # 2s, 4s, 8s between attempts, which would dominate the suite.
    kwargs.setdefault("max_retries", 0)
    return WorkflowConfig(llm_client=object(), **kwargs)


async def _run(cfg: WorkflowConfig, evidence: dict[str, Any] | None = EVIDENCE) -> dict[str, Any]:
    graph = build_workflow(cfg)
    state = initial_state(job_id="job-1", apk_sha256="a" * 64, evidence=evidence or {})
    return await graph.ainvoke(state, config={"recursion_limit": 50})


# ---------------------------------------------------------------------------
# Topology
# ---------------------------------------------------------------------------


class TestTopology:
    def test_every_agent_plus_the_gates_is_a_node(self, fleet) -> None:
        fleet()
        graph = build_workflow(_config())

        nodes = set(graph.get_graph().nodes)
        for name in (*ANALYSIS_AGENTS, "risk_agent", "report_agent"):
            assert name in nodes
        for gate in ("orchestrator_start", "check_evidence", "fanout_gate",
                     "analysis_join", "abort", "finalise"):
            assert gate in nodes

    def test_the_six_analysis_agents_share_one_predecessor(self, fleet) -> None:
        # This is what makes them run concurrently — LangGraph fans out to every
        # node reachable from a single completed node.
        fleet()
        graph = build_workflow(_config())

        edges = {(e.source, e.target) for e in graph.get_graph().edges}
        for name in ANALYSIS_AGENTS:
            assert ("fanout_gate", name) in edges
            assert (name, "analysis_join") in edges


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


class TestHappyPath:
    async def test_all_eight_agents_run_and_the_pipeline_completes(self, fleet) -> None:
        f = fleet()
        final = await _run(_config())

        assert set(f.agents) == set(_CLASS_BY_AGENT)
        assert final["pipeline_status"] == PipelineStatus.COMPLETED.value
        assert all_analysis_agents_done(final)
        for name in ANALYSIS_AGENTS:
            assert final["agent_results"][name]["status"] == AgentRunStatus.COMPLETED.value

    async def test_findings_from_parallel_branches_are_concatenated(self, fleet) -> None:
        # The all_findings reducer is operator.add — if a branch overwrote instead
        # of appending, five of the six agents' findings would vanish.
        fleet()
        final = await _run(_config())

        titles = {f["title"] for f in final["all_findings"]}
        assert titles == {f"{name} finding" for name in ANALYSIS_AGENTS}

    async def test_risk_and_report_outputs_land_in_their_own_state_slots(self, fleet) -> None:
        fleet()
        final = await _run(_config())

        assert final["risk_result"] == {"summary": "risk_agent ok"}
        assert final["report"] == {"summary": "report_agent ok"}
        assert final["completed_at"]

    async def test_downstream_agents_see_upstream_outputs(self, fleet) -> None:
        # Risk scoring is only meaningful if the six analysis outputs reached it.
        f = fleet()
        await _run(_config())

        risk_context = f.agents["risk_agent"].calls[0]["context"]
        for name in ANALYSIS_AGENTS:
            assert f"{name}_output" in risk_context

    async def test_agents_receive_the_evidence_envelope(self, fleet) -> None:
        f = fleet()
        await _run(_config())

        assert f.agents["manifest_agent"].calls[0]["evidence"] == EVIDENCE


# ---------------------------------------------------------------------------
# Failure isolation and the abort policy
# ---------------------------------------------------------------------------


class TestFailureIsolation:
    async def test_one_failing_agent_does_not_stop_the_pipeline(self, fleet) -> None:
        fleet(behaviours={"code_agent": "raise"})
        final = await _run(_config())

        assert final["agent_results"]["code_agent"]["status"] == AgentRunStatus.FAILED.value
        assert final["agent_results"]["manifest_agent"]["status"] == AgentRunStatus.COMPLETED.value
        # One failure out of six is below the abort threshold, so we still report.
        assert final["report"] == {"summary": "report_agent ok"}
        assert final["pipeline_status"] == PipelineStatus.COMPLETED.value

    async def test_a_failed_agent_records_its_error_rather_than_raising(self, fleet) -> None:
        fleet(behaviours={"network_agent": "raise"})
        final = await _run(_config())

        errors = final["agent_results"]["network_agent"]["errors"]
        assert errors and "network_agent blew up" in errors[0]["message"]
        assert errors[0]["error_type"] == "RuntimeError"

    async def test_half_the_agents_failing_aborts_before_scoring(self, fleet) -> None:
        # Scoring risk off half-missing evidence would produce a confident-looking
        # verdict from incomplete analysis, so the graph refuses instead.
        fleet(behaviours={"code_agent": "raise", "api_agent": "raise", "network_agent": "raise"})
        final = await _run(_config())

        assert final["pipeline_status"] == PipelineStatus.FAILED.value
        assert "Too many agent failures" in final["error"]
        assert final["risk_result"] is None
        assert final["report"] is None

    async def test_a_timeout_is_recorded_as_timed_out_not_failed(self, fleet) -> None:
        fleet(delays={"manifest_agent": 0.3})
        final = await _run(_config(analysis_timeout_s=0.05))

        assert final["agent_results"]["manifest_agent"]["status"] == AgentRunStatus.TIMED_OUT.value
        assert "timed out" in final["agent_results"]["manifest_agent"]["errors"][0]["message"]


class TestTerminalStatus:
    async def test_a_failed_report_is_not_reported_as_completed(self, fleet) -> None:
        # A job with no report has not delivered its deliverable. Calling that
        # "completed" would let the API hand a SOC analyst an empty verdict.
        fleet(behaviours={"report_agent": "raise"})
        final = await _run(_config())

        assert final["report"] is None
        assert final["pipeline_status"] == PipelineStatus.PARTIAL.value

    async def test_a_failed_risk_agent_aborts_rather_than_reporting_blind(self, fleet) -> None:
        fleet(behaviours={"risk_agent": "raise"})
        final = await _run(_config())

        assert final["pipeline_status"] == PipelineStatus.FAILED.value
        assert final["report"] is None


class TestEvidenceGate:
    async def test_an_empty_envelope_aborts_without_calling_any_agent(self, fleet) -> None:
        f = fleet()
        final = await _run(_config(), evidence={})

        assert final["pipeline_status"] == PipelineStatus.FAILED.value
        assert final["error"] == "Evidence envelope missing"
        assert f.agents == {} or all(not a.calls for a in f.agents.values())

    async def test_the_abort_path_still_finalises(self, fleet) -> None:
        # finalise flushes telemetry, so it must run on the failure path too.
        fleet()
        final = await _run(_config(), evidence={})

        assert final["completed_at"]
