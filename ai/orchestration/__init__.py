"""
Sephela AI Orchestration — LangGraph-based parallel multi-agent pipeline.

Public API
----------

New LangGraph layer (graph_state / orchestrator / workflow / router):

    from ai.orchestration import (
        GraphState, initial_state,           # state
        build_workflow, WorkflowConfig,      # workflow
        PipelineRunner,                      # high-level runner
    )

Legacy (preserved for backwards-compatibility):
    AnalysisState, create_analysis_graph
"""

# ── New LangGraph layer ──────────────────────────────────────────────────────
from ai.orchestration.graph_state import (
    AgentResultEntry,
    AgentRunStatus,
    GraphState,
    PipelineStatus,
    all_analysis_agents_done,
    get_agent_result,
    initial_state,
    is_terminal,
)
from ai.orchestration.orchestrator import (
    finalise_node,
    make_agent_node,
    make_report_node,
    make_risk_node,
    orchestrator_start_node,
)
from ai.orchestration.router import (
    abort_node,
    route_after_report,
    route_after_risk,
    route_after_start,
    route_analysis_join,
)
from ai.orchestration.workflow import WorkflowConfig, build_workflow, get_mermaid_diagram

# ── Runner (unchanged) ───────────────────────────────────────────────────────
from ai.orchestration.runner import PipelineRunner, PipelineRunResult

# ── Checkpointers ────────────────────────────────────────────────────────────
from ai.orchestration.checkpointer import (
    InMemoryCheckpointer,
    PostgresCheckpointer,
    get_checkpointer,
)

# ── Legacy graph (backwards-compat) ─────────────────────────────────────────
from ai.orchestration.graph import create_analysis_graph, AnalysisState
from ai.orchestration.state import AgentState

__all__ = [
    # graph_state
    "GraphState",
    "AgentResultEntry",
    "AgentRunStatus",
    "PipelineStatus",
    "initial_state",
    "is_terminal",
    "get_agent_result",
    "all_analysis_agents_done",
    # orchestrator
    "orchestrator_start_node",
    "finalise_node",
    "make_agent_node",
    "make_risk_node",
    "make_report_node",
    # router
    "route_after_start",
    "route_analysis_join",
    "route_after_risk",
    "route_after_report",
    "abort_node",
    # workflow
    "WorkflowConfig",
    "build_workflow",
    "get_mermaid_diagram",
    # runner
    "PipelineRunner",
    "PipelineRunResult",
    # checkpointers
    "InMemoryCheckpointer",
    "PostgresCheckpointer",
    "get_checkpointer",
    # legacy
    "create_analysis_graph",
    "AnalysisState",
    "AgentState",
]