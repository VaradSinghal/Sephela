"""
router.py — Conditional edge routing logic for the LangGraph StateGraph.

Routers are pure functions (GraphState → str) consumed by
``workflow.add_conditional_edges()``. Each returns a routing key that
LangGraph uses to select the next node(s).

Architecture:
    orchestrator_start
          │
    ┌─────┴──────────────────────────────────────┐
    │             [parallel fan-out]              │
    ▼             ▼           ▼    ▼    ▼    ▼
 manifest   permission    code  api  network  threat_intel
    └─────────────────────────────────────────────┘
                          │
                     [fan-in join]
                          │
                       risk_agent
                          │
                      report_agent
                          │
                       finalise
                          │
                         END
"""

from __future__ import annotations

from typing import Any, Literal

from ai.orchestration.graph_state import (
    AgentRunStatus,
    GraphState,
    PipelineStatus,
    all_analysis_agents_done,
)

# ---------------------------------------------------------------------------
# Type aliases for routing keys
# ---------------------------------------------------------------------------

PipelineRoute = Literal["continue", "abort", "retry", "skip"]
AnalysisJoinRoute = Literal["risk", "wait", "abort"]
RiskRoute = Literal["report", "abort"]


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _count_failed(state: GraphState, agent_names: list[str]) -> int:
    """Count how many of the given agents are in a failed/timed-out state."""
    terminal_failure = {AgentRunStatus.FAILED.value, AgentRunStatus.TIMED_OUT.value}
    results = state.get("agent_results", {})
    return sum(
        1
        for name in agent_names
        if results.get(name, {}).get("status") in terminal_failure
    )


# ---------------------------------------------------------------------------
# Router: after orchestrator_start → fan-out to analysis agents
# ---------------------------------------------------------------------------


def route_after_start(state: GraphState) -> Literal["fanout", "abort"]:
    """
    After the orchestrator start node, verify the evidence envelope is present.

    Returns:
        ``"fanout"``  — proceed to parallel analysis agents.
        ``"abort"``   — evidence missing; terminate pipeline.
    """
    evidence = state.get("evidence")
    if not evidence:
        return "abort"
    if state.get("pipeline_status") == PipelineStatus.CANCELLED.value:
        return "abort"
    return "fanout"


# ---------------------------------------------------------------------------
# Router: join node after all parallel analysis agents complete
# ---------------------------------------------------------------------------

# Threshold: if more than this fraction of analysis agents fail we abort
_MAX_FAILURE_FRACTION = 0.5
_ANALYSIS_AGENTS = [
    "manifest_agent",
    "permission_agent",
    "code_agent",
    "api_agent",
    "network_agent",
    "threat_intel_agent",
]


def route_analysis_join(state: GraphState) -> AnalysisJoinRoute:
    """
    Evaluate analysis-agent outcomes after all six have completed.

    Policy:
      • If ≥50 % of analysis agents failed → ``"abort"``
      • Otherwise → ``"risk"`` (proceed to RiskAgent)

    Returns:
        ``"risk"``  — enough data to compute risk.
        ``"abort"`` — too many failures; pipeline terminates.
    """
    failed = _count_failed(state, _ANALYSIS_AGENTS)
    total = len(_ANALYSIS_AGENTS)

    if failed / total >= _MAX_FAILURE_FRACTION:
        return "abort"

    return "risk"


# ---------------------------------------------------------------------------
# Router: after RiskAgent completes
# ---------------------------------------------------------------------------


def route_after_risk(state: GraphState) -> RiskRoute:
    """
    Decide whether to proceed to ReportAgent after risk scoring.

    Returns:
        ``"report"`` — risk result available; generate report.
        ``"abort"``  — risk agent failed fatally; terminate.
    """
    risk_entry = state.get("agent_results", {}).get("risk_agent", {})
    status = risk_entry.get("status")

    if status in (AgentRunStatus.FAILED.value, AgentRunStatus.TIMED_OUT.value):
        # Allow report generation with degraded risk data if possible
        risk_result = state.get("risk_result")
        if risk_result is None:
            return "abort"

    return "report"


# ---------------------------------------------------------------------------
# Router: after ReportAgent completes
# ---------------------------------------------------------------------------


def route_after_report(state: GraphState) -> Literal["finalise", "abort"]:
    """
    After the report agent, always move to the finalise node (even on failure)
    so the pipeline can emit its completion telemetry.

    Returns:
        ``"finalise"`` always.
    """
    return "finalise"


# ---------------------------------------------------------------------------
# Router: abort path — determines pipeline terminal status
# ---------------------------------------------------------------------------


def route_abort(state: GraphState) -> Literal["finalise"]:
    """
    Sink for abort paths. Sets pipeline status to FAILED and forwards to finalise.
    This is used as the abort node body — it mutates state in place.
    """
    return "finalise"


# ---------------------------------------------------------------------------
# Abort node body (pure GraphState update — not a router)
# ---------------------------------------------------------------------------


async def abort_node(state: GraphState) -> dict[str, Any]:
    """
    Terminal abort node.  Sets pipeline_status = FAILED and records reason.
    """
    from datetime import datetime, timezone

    job_id = state.get("job_id", "unknown")
    evidence = state.get("evidence")
    failed_agents = [
        name
        for name in _ANALYSIS_AGENTS + ["risk_agent", "report_agent"]
        if state.get("agent_results", {}).get(name, {}).get("status")
        in (AgentRunStatus.FAILED.value, AgentRunStatus.TIMED_OUT.value)
    ]

    reason: str
    if not evidence:
        reason = "Evidence envelope missing"
    else:
        reason = f"Too many agent failures: {failed_agents}"

    import logging, json
    _log = logging.getLogger("sephela.orchestrator")
    _log.error(json.dumps({
        "ts": datetime.now(timezone.utc).isoformat(),
        "level": "error",
        "event": "pipeline_abort",
        "job_id": job_id,
        "reason": reason,
        "failed_agents": failed_agents,
    }))

    return {
        "pipeline_status": PipelineStatus.FAILED.value,
        "error": reason,
        "completed_at": datetime.now(timezone.utc).isoformat(),
    }
