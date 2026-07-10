"""
graph_state.py — LangGraph graph state definitions for the Sephela APK analysis pipeline.

The state is a TypedDict so LangGraph can checkpoint, merge, and diff it cleanly.
All mutable collections use annotated reducers (operator.add for lists, dict merge
for dicts) so parallel branches can write without trampling each other.
"""

from __future__ import annotations

import operator
from datetime import datetime
from enum import Enum
from typing import Annotated, Any, Optional
from uuid import uuid4

from typing_extensions import TypedDict


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class PipelineStatus(str, Enum):
    """Overall pipeline execution status."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"
    CANCELLED = "cancelled"


class AgentRunStatus(str, Enum):
    """Per-agent execution status."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    SKIPPED = "skipped"
    RETRYING = "retrying"


# ---------------------------------------------------------------------------
# Nested state models (plain dicts — keep JSON-serialisable for checkpointing)
# ---------------------------------------------------------------------------


class AgentResultEntry(TypedDict, total=False):
    """Serialisable record stored per agent in graph state."""

    agent_name: str
    status: str                         # AgentRunStatus value
    output: Optional[dict[str, Any]]    # agent's parsed Pydantic model as dict
    findings: list[dict[str, Any]]      # list of Finding.model_dump()
    errors: list[dict[str, Any]]        # list of AgentError dicts
    execution_time_ms: int
    tokens_used: int
    model_name: str
    retry_count: int
    started_at: Optional[str]           # ISO-8601
    completed_at: Optional[str]         # ISO-8601
    span_id: Optional[str]              # OpenTelemetry span ID


# ---------------------------------------------------------------------------
# Primary LangGraph State
# ---------------------------------------------------------------------------

# LangGraph uses annotated reducers to merge state updates from parallel nodes.
# operator.add on lists → concatenation (safe for fan-in from parallel branches).
# _merge_dict → last-write-wins for the agent_results / context dicts.

def _merge_dict(left: dict, right: dict) -> dict:
    """Reducer: merge two dicts, right values override left on key collision."""
    return {**left, **right}


def _merge_errors(left: list[str], right: list[str]) -> list[str]:
    """Reducer: accumulate errors from all branches."""
    return left + right


class GraphState(TypedDict, total=False):
    """
    Complete LangGraph state for one APK analysis job.

    Fields prefixed with ``Annotated[..., reducer]`` use LangGraph's fan-in
    reducer semantics — safe to update from concurrent parallel nodes.

    Non-annotated fields are set exactly once (by orchestrator / sequenced nodes)
    and must not be written by parallel branches to avoid race conditions.
    """

    # ------------------------------------------------------------------
    # Immutable job identity (set once by orchestrator, never mutated)
    # ------------------------------------------------------------------
    job_id: str
    apk_sha256: str

    # ------------------------------------------------------------------
    # Evidence Envelope — read-only input from the caller
    # ------------------------------------------------------------------
    evidence: dict[str, Any]

    # ------------------------------------------------------------------
    # Agent results — parallel branches write their own key; reducer merges
    # ------------------------------------------------------------------
    agent_results: Annotated[dict[str, AgentResultEntry], _merge_dict]

    # ------------------------------------------------------------------
    # Accumulated findings — parallel branches append; reducer concatenates
    # ------------------------------------------------------------------
    all_findings: Annotated[list[dict[str, Any]], operator.add]

    # ------------------------------------------------------------------
    # Shared context written by completed analysis agents so that risk /
    # report agents can read prior outputs without looking into agent_results.
    # ------------------------------------------------------------------
    analysis_context: Annotated[dict[str, Any], _merge_dict]

    # ------------------------------------------------------------------
    # Risk & Report outputs — set sequentially after fan-in
    # ------------------------------------------------------------------
    risk_result: Optional[dict[str, Any]]
    report: Optional[dict[str, Any]]

    # ------------------------------------------------------------------
    # Pipeline-level metadata
    # ------------------------------------------------------------------
    pipeline_status: str                    # PipelineStatus value
    error: Optional[str]                    # last fatal error message
    errors: Annotated[list[str], _merge_errors]   # all non-fatal errors

    # Timing
    started_at: Optional[str]              # ISO-8601
    completed_at: Optional[str]            # ISO-8601

    # OpenTelemetry trace propagation
    trace_id: Optional[str]
    otel_context: Optional[dict[str, str]]

    # Retry bookkeeping (orchestrator-managed)
    retry_counts: Annotated[dict[str, int], _merge_dict]

    # Configuration overrides passed at invocation time
    config_overrides: dict[str, Any]


# ---------------------------------------------------------------------------
# Factory helpers
# ---------------------------------------------------------------------------


def initial_state(
    job_id: str,
    apk_sha256: str,
    evidence: dict[str, Any],
    config_overrides: Optional[dict[str, Any]] = None,
    trace_id: Optional[str] = None,
) -> GraphState:
    """
    Construct a fully-initialised GraphState for a new job.

    Args:
        job_id:           Unique identifier for this analysis job.
        apk_sha256:       SHA-256 digest of the APK under analysis.
        evidence:         Evidence Envelope produced by the extraction engine.
        config_overrides: Optional per-job config overrides (e.g. model, timeout).
        trace_id:         OpenTelemetry trace ID for distributed tracing.

    Returns:
        A GraphState dict ready to be passed to ``graph.ainvoke()``.
    """
    return GraphState(
        job_id=job_id,
        apk_sha256=apk_sha256,
        evidence=evidence,
        agent_results={},
        all_findings=[],
        analysis_context={
            "job_id": job_id,
            "apk_sha256": apk_sha256,
        },
        risk_result=None,
        report=None,
        pipeline_status=PipelineStatus.PENDING.value,
        error=None,
        errors=[],
        started_at=datetime.utcnow().isoformat() + "Z",
        completed_at=None,
        trace_id=trace_id or uuid4().hex,
        otel_context={},
        retry_counts={},
        config_overrides=config_overrides or {},
    )


def is_terminal(state: GraphState) -> bool:
    """Return True if the pipeline has reached a terminal state."""
    return state.get("pipeline_status") in (
        PipelineStatus.COMPLETED.value,
        PipelineStatus.FAILED.value,
        PipelineStatus.CANCELLED.value,
    )


def get_agent_result(state: GraphState, agent_name: str) -> Optional[AgentResultEntry]:
    """Safely retrieve a single agent's result from state."""
    return state.get("agent_results", {}).get(agent_name)


def all_analysis_agents_done(state: GraphState) -> bool:
    """
    Return True when all six parallel analysis agents have completed
    (successfully or with errors — not pending/running).
    """
    terminal_statuses = {
        AgentRunStatus.COMPLETED.value,
        AgentRunStatus.FAILED.value,
        AgentRunStatus.TIMED_OUT.value,
        AgentRunStatus.SKIPPED.value,
    }
    analysis_agents = {
        "manifest_agent",
        "permission_agent",
        "code_agent",
        "api_agent",
        "network_agent",
        "threat_intel_agent",
    }
    results = state.get("agent_results", {})
    return all(
        results.get(name, {}).get("status") in terminal_statuses
        for name in analysis_agents
    )
