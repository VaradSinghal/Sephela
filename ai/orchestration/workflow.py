"""
workflow.py — LangGraph StateGraph assembly for the Sephela APK analysis pipeline.

Topology
--------

    orchestrator_start
          │  route_after_start → "fanout" | "abort"
          │
    ┌─────┬─────────┬─────┬─────────┬───────────┐
    ▼     ▼         ▼     ▼         ▼           ▼
 manifest  permission  code  api   network  threat_intel
    └─────┴─────────┴─────┴─────┴─────────┴───────────┘
                        │
                   analysis_join          ← fan-in node
                        │  route_analysis_join → "risk" | "abort"
                        ▼
                    risk_agent
                        │  route_after_risk → "report" | "abort"
                        ▼
                   report_agent
                        │  route_after_report → "finalise"
                        ▼
                      finalise
                        │
                       END

Parallel fan-out is achieved via LangGraph's ``Send`` API — the ``analysis_join``
node is added as a barrier/synchronisation point using a dummy pass-through; the
real parallelism is provided by the graph engine running all six analysis agent
nodes concurrently when they share the same predecessor node (``orchestrator_start``).

Usage
-----

    from ai.agents.manifest import ManifestAgent
    from ai.agents.permission import PermissionAgent
    # ... other agents ...
    from ai.orchestration.workflow import build_workflow, WorkflowConfig

    cfg = WorkflowConfig(llm_client=my_client)
    compiled = build_workflow(cfg)                # CompiledStateGraph
    result = await compiled.ainvoke(initial_state(...), config={...})
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Optional

from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph import END, StateGraph

from ai.agents.api import APIAgent
from ai.agents.code import CodeAgent
from ai.agents.manifest import ManifestAgent
from ai.agents.network import NetworkAgent
from ai.agents.permission import PermissionAgent
from ai.agents.report import ReportAgent
from ai.agents.risk import RiskAgent
from ai.agents.threat_intel import ThreatIntelAgent
from ai.orchestration.graph_state import GraphState
from ai.orchestration.orchestrator import (
    finalise_node,
    make_agent_node,
    make_report_node,
    make_risk_node,
    orchestrator_start_node,
)
from ai.orchestration.router import (
    abort_node,
    route_abort,
    route_after_report,
    route_after_risk,
    route_after_start,
    route_analysis_join,
)

_LOG = logging.getLogger("sephela.workflow")

# ---------------------------------------------------------------------------
# Workflow configuration dataclass
# ---------------------------------------------------------------------------


@dataclass
class WorkflowConfig:
    """
    Configuration for assembling and compiling the LangGraph workflow.

    Attributes:
        llm_client:          Async LLM client passed to every agent.
        checkpointer:        LangGraph checkpointer for state persistence
                             (use InMemoryCheckpointer for development,
                             PostgresCheckpointer for production).
        analysis_timeout_s:  Per-agent wall-clock timeout for the six analysis
                             agents (manifest, permission, code, api, network,
                             threat_intel).
        risk_timeout_s:      Timeout for RiskAgent.
        report_timeout_s:    Timeout for ReportAgent.
        max_retries:         Maximum outer retry attempts per agent.
        graph_debug:         Enable LangGraph debug mode (verbose logging).
        agent_overrides:     Optional dict of {agent_name: AgentConfig} for
                             per-agent configuration overrides.
    """

    llm_client: Any = None
    checkpointer: Optional[BaseCheckpointSaver] = None
    analysis_timeout_s: float = 180.0
    risk_timeout_s: float = 120.0
    report_timeout_s: float = 120.0
    max_retries: int = 3
    graph_debug: bool = False
    agent_overrides: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Analysis-join pass-through node (fan-in synchronisation point)
# ---------------------------------------------------------------------------


async def _analysis_join_node(state: GraphState) -> dict[str, Any]:
    """
    No-op barrier node.

    LangGraph waits for *all* upstream parallel branches to complete before
    entering this node, giving us the synchronisation guarantee required
    before running RiskAgent.  The route_analysis_join function then decides
    whether to proceed or abort.
    """
    job_id = state.get("job_id", "unknown")
    results = state.get("agent_results", {})
    completed = sum(1 for r in results.values() if r.get("status") == "completed")
    total = len(results)
    _LOG.info(
        '{"event": "analysis_join", "job_id": "%s", "completed": %d, "total": %d}',
        job_id,
        completed,
        total,
    )
    return {}  # No state mutation — routing handled by router


async def _check_evidence_node(state: GraphState) -> dict[str, Any]:
    """
    Evidence validation gate — sits between orchestrator_start and the parallel
    fan-out so we can use a conditional edge here without conflicting with the
    unconditional fan-out edges from ``fanout_gate``.

    Returns an empty dict (no state changes); routing is handled by
    route_after_start which reads state.evidence.
    """
    return {}


async def _fanout_gate_node(state: GraphState) -> dict[str, Any]:
    """
    Pass-through node whose sole purpose is to be the common predecessor
    of all six parallel analysis-agent nodes.

    Because LangGraph fans out concurrently to every node connected via
    unconditional edges from a single predecessor, placing all six
    ``add_edge(fanout_gate, agent)`` calls here is the canonical parallel
    fan-out pattern and avoids mixing conditional + unconditional edges on
    the same source node.
    """
    return {}


# ---------------------------------------------------------------------------
# Build & compile
# ---------------------------------------------------------------------------


def build_workflow(cfg: WorkflowConfig) -> Any:  # returns CompiledStateGraph
    """
    Assemble, wire, and compile the full LangGraph StateGraph.

    Args:
        cfg: WorkflowConfig with agent clients, timeouts, and checkpointer.

    Returns:
        A compiled LangGraph graph ready for ``ainvoke`` / ``astream``.
    """
    # ------------------------------------------------------------------
    # 1. Instantiate agents
    # ------------------------------------------------------------------
    llm = cfg.llm_client

    manifest_agent = ManifestAgent(llm_client=llm)
    permission_agent = PermissionAgent(llm_client=llm)
    code_agent = CodeAgent(llm_client=llm)
    api_agent = APIAgent(llm_client=llm)
    network_agent = NetworkAgent(llm_client=llm)
    threat_intel_agent = ThreatIntelAgent(llm_client=llm)
    risk_agent = RiskAgent(llm_client=llm)
    report_agent = ReportAgent(llm_client=llm)

    # Apply per-agent config overrides if provided
    for agent in (
        manifest_agent, permission_agent, code_agent,
        api_agent, network_agent, threat_intel_agent,
        risk_agent, report_agent,
    ):
        overrides = cfg.agent_overrides.get(agent.config.name, {})
        for k, v in overrides.items():
            if hasattr(agent.config, k):
                setattr(agent.config, k, v)

    # ------------------------------------------------------------------
    # 2. Create node callables
    # ------------------------------------------------------------------
    node_manifest = make_agent_node(
        manifest_agent,
        timeout_s=cfg.analysis_timeout_s,
        max_retries=cfg.max_retries,
    )
    node_permission = make_agent_node(
        permission_agent,
        timeout_s=cfg.analysis_timeout_s,
        max_retries=cfg.max_retries,
    )
    node_code = make_agent_node(
        code_agent,
        timeout_s=cfg.analysis_timeout_s,
        max_retries=cfg.max_retries,
    )
    node_api = make_agent_node(
        api_agent,
        timeout_s=cfg.analysis_timeout_s,
        max_retries=cfg.max_retries,
    )
    node_network = make_agent_node(
        network_agent,
        timeout_s=cfg.analysis_timeout_s,
        max_retries=cfg.max_retries,
    )
    node_threat_intel = make_agent_node(
        threat_intel_agent,
        timeout_s=cfg.analysis_timeout_s,
        max_retries=cfg.max_retries,
    )
    node_risk = make_risk_node(
        risk_agent,
        timeout_s=cfg.risk_timeout_s,
        max_retries=cfg.max_retries,
    )
    node_report = make_report_node(
        report_agent,
        timeout_s=cfg.report_timeout_s,
        max_retries=cfg.max_retries,
    )

    # ------------------------------------------------------------------
    # 3. Build StateGraph
    # ------------------------------------------------------------------
    workflow = StateGraph(GraphState)

    # Entry node
    workflow.add_node("orchestrator_start", orchestrator_start_node)

    # Parallel analysis agents (all receive edges from orchestrator_start)
    workflow.add_node("manifest_agent", node_manifest)
    workflow.add_node("permission_agent", node_permission)
    workflow.add_node("code_agent", node_code)
    workflow.add_node("api_agent", node_api)
    workflow.add_node("network_agent", node_network)
    workflow.add_node("threat_intel_agent", node_threat_intel)

    # Fan-in synchronisation barrier
    workflow.add_node("analysis_join", _analysis_join_node)

    # Sequential downstream agents
    workflow.add_node("risk_agent", node_risk)
    workflow.add_node("report_agent", node_report)

    # Abort + finalise
    workflow.add_node("abort", abort_node)
    workflow.add_node("finalise", finalise_node)

    # Add extra gate nodes
    workflow.add_node("check_evidence", _check_evidence_node)
    workflow.add_node("fanout_gate", _fanout_gate_node)

    # ------------------------------------------------------------------
    # 4. Wire edges
    # ------------------------------------------------------------------

    # Entry point
    workflow.set_entry_point("orchestrator_start")

    # orchestrator_start → check_evidence (unconditional)
    workflow.add_edge("orchestrator_start", "check_evidence")

    # check_evidence → fanout_gate | abort  (conditional)
    workflow.add_conditional_edges(
        "check_evidence",
        route_after_start,
        {
            "fanout": "fanout_gate",
            "abort": "abort",
        },
    )

    # fanout_gate → all six analysis agents in PARALLEL
    # LangGraph executes all nodes connected from a single predecessor
    # concurrently via its async task scheduler.
    for agent_name in (
        "manifest_agent",
        "permission_agent",
        "code_agent",
        "api_agent",
        "network_agent",
        "threat_intel_agent",
    ):
        workflow.add_edge("fanout_gate", agent_name)

    # Fan-in: all six analysis agents converge on analysis_join
    for agent_name in (
        "manifest_agent",
        "permission_agent",
        "code_agent",
        "api_agent",
        "network_agent",
        "threat_intel_agent",
    ):
        workflow.add_edge(agent_name, "analysis_join")

    # Post-join routing: proceed to risk or abort
    workflow.add_conditional_edges(
        "analysis_join",
        route_analysis_join,
        {
            "risk": "risk_agent",
            "abort": "abort",
        },
    )

    # Post-risk routing: report or abort
    workflow.add_conditional_edges(
        "risk_agent",
        route_after_risk,
        {
            "report": "report_agent",
            "abort": "abort",
        },
    )

    # Post-report routing: always finalise
    workflow.add_conditional_edges(
        "report_agent",
        route_after_report,
        {
            "finalise": "finalise",
        },
    )

    # Abort always proceeds to finalise for telemetry flush
    workflow.add_conditional_edges(
        "abort",
        route_abort,
        {
            "finalise": "finalise",
        },
    )

    # Finalise → END
    workflow.add_edge("finalise", END)

    # ------------------------------------------------------------------
    # 5. Compile
    # ------------------------------------------------------------------
    compile_kwargs: dict[str, Any] = {}
    if cfg.checkpointer is not None:
        compile_kwargs["checkpointer"] = cfg.checkpointer
    if cfg.graph_debug:
        compile_kwargs["debug"] = True

    compiled = workflow.compile(**compile_kwargs)

    _LOG.info(
        '{"event": "workflow_compiled", "nodes": %d, "parallel_agents": 6}',
        len(workflow.nodes),
    )

    return compiled


# ---------------------------------------------------------------------------
# Convenience: get a Mermaid diagram of the workflow
# ---------------------------------------------------------------------------


def get_mermaid_diagram(cfg: Optional[WorkflowConfig] = None) -> str:
    """
    Return a Mermaid diagram string representing the compiled workflow graph.

    Useful for documentation and debugging.

    Args:
        cfg: Optional WorkflowConfig.  Uses defaults if not provided.

    Returns:
        Mermaid graph string.
    """
    compiled = build_workflow(cfg or WorkflowConfig())
    try:
        return compiled.get_graph().draw_mermaid()
    except Exception:  # noqa: BLE001
        # Fallback: return static diagram
        return """
graph TD
    orchestrator_start --> manifest_agent
    orchestrator_start --> permission_agent
    orchestrator_start --> code_agent
    orchestrator_start --> api_agent
    orchestrator_start --> network_agent
    orchestrator_start --> threat_intel_agent
    manifest_agent --> analysis_join
    permission_agent --> analysis_join
    code_agent --> analysis_join
    api_agent --> analysis_join
    network_agent --> analysis_join
    threat_intel_agent --> analysis_join
    analysis_join -->|risk| risk_agent
    analysis_join -->|abort| abort
    risk_agent -->|report| report_agent
    risk_agent -->|abort| abort
    report_agent --> finalise
    abort --> finalise
    finalise --> END
"""
