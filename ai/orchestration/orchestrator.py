"""
orchestrator.py — Agent node factory and execution logic for the LangGraph pipeline.

Each analysis agent is wrapped in an async node function that:
  • propagates OpenTelemetry spans
  • enforces per-agent timeouts
  • handles retries with exponential back-off
  • emits structured JSON log lines
  • writes results into GraphState using the reducer-safe pattern
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from opentelemetry import context as otel_context
from opentelemetry import trace
from opentelemetry.trace import NonRecordingSpan, SpanContext, TraceFlags
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

from ai.agents.base import AgentConfig, AgentRegistry, AgentResult, AgentStatus, BaseAgent
from ai.orchestration.graph_state import (
    AgentResultEntry,
    AgentRunStatus,
    GraphState,
    PipelineStatus,
)

# ---------------------------------------------------------------------------
# Module-level logger (structured JSON)
# ---------------------------------------------------------------------------

_LOG = logging.getLogger("sephela.orchestrator")

# ---------------------------------------------------------------------------
# OpenTelemetry tracer
# ---------------------------------------------------------------------------

_TRACER = trace.get_tracer("sephela.orchestrator", schema_url="https://opentelemetry.io/schemas/1.24.0")
_PROPAGATOR = TraceContextTextMapPropagator()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Default timeouts by agent tier
_ANALYSIS_AGENT_TIMEOUT_S = 180   # manifest / permission / code / api / network / threat_intel
_RISK_AGENT_TIMEOUT_S = 120
_REPORT_AGENT_TIMEOUT_S = 120

# Retry configuration
_MAX_RETRIES = 3
_RETRY_BASE_DELAY_S = 2.0
_RETRY_MAX_DELAY_S = 30.0


# ---------------------------------------------------------------------------
# Structured logging helpers
# ---------------------------------------------------------------------------


def _log(
    level: str,
    event: str,
    job_id: str,
    agent_name: Optional[str] = None,
    **extra: Any,
) -> None:
    """Emit a single structured JSON log line."""
    record: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "level": level,
        "event": event,
        "job_id": job_id,
    }
    if agent_name:
        record["agent"] = agent_name
    record.update(extra)
    msg = json.dumps(record, default=str)
    getattr(_LOG, level.lower(), _LOG.info)(msg)


# ---------------------------------------------------------------------------
# OTel context helpers
# ---------------------------------------------------------------------------


def _restore_otel_context(otel_carrier: Optional[dict[str, str]]) -> Any:
    """Restore OTel trace context from the carrier stored in GraphState."""
    if not otel_carrier:
        return otel_context.get_current()
    ctx = _PROPAGATOR.extract(otel_carrier)
    return ctx


def _extract_otel_carrier(ctx: Any) -> dict[str, str]:
    """Serialise the current OTel context into a W3C TraceContext carrier dict."""
    carrier: dict[str, str] = {}
    _PROPAGATOR.inject(carrier, context=ctx)
    return carrier


# ---------------------------------------------------------------------------
# Retry / timeout helpers
# ---------------------------------------------------------------------------


async def _run_with_timeout(
    coro: Any,
    timeout_s: float,
    agent_name: str,
    job_id: str,
) -> Any:
    """Await *coro* with a deadline. Raises asyncio.TimeoutError on breach."""
    try:
        return await asyncio.wait_for(coro, timeout=timeout_s)
    except asyncio.TimeoutError:
        _log("warning", "agent_timeout", job_id, agent_name, timeout_s=timeout_s)
        raise


async def _execute_with_retry(
    agent: BaseAgent,
    evidence: dict[str, Any],
    context: dict[str, Any],
    timeout_s: float,
    max_retries: int,
    job_id: str,
) -> AgentResult:
    """
    Execute an agent with exponential back-off retry.

    The agent's own internal retry loop is preserved.  This outer loop handles
    transient infrastructure failures (network blips, rate-limits, etc.) that
    the agent itself cannot recover from.
    """
    last_error: Exception = RuntimeError("No attempt made")

    for attempt in range(max_retries + 1):
        if attempt > 0:
            delay = min(_RETRY_BASE_DELAY_S * (2 ** (attempt - 1)), _RETRY_MAX_DELAY_S)
            _log(
                "info",
                "agent_retry",
                job_id,
                agent.config.name,
                attempt=attempt,
                delay_s=delay,
            )
            await asyncio.sleep(delay)

        try:
            result = await _run_with_timeout(
                agent.execute(evidence, context),
                timeout_s=timeout_s,
                agent_name=agent.config.name,
                job_id=job_id,
            )
            return result
        except asyncio.TimeoutError as exc:
            last_error = exc
            # Timeouts are not retried — surface immediately.
            raise
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            _log(
                "warning",
                "agent_attempt_failed",
                job_id,
                agent.config.name,
                attempt=attempt,
                error=str(exc),
                error_type=type(exc).__name__,
            )

    raise last_error


# ---------------------------------------------------------------------------
# Core node factory
# ---------------------------------------------------------------------------


def make_agent_node(
    agent: BaseAgent,
    timeout_s: float = _ANALYSIS_AGENT_TIMEOUT_S,
    max_retries: int = _MAX_RETRIES,
) -> Callable[[GraphState], dict[str, Any]]:
    """
    Wrap a BaseAgent in a LangGraph async node function.

    The returned callable accepts and returns GraphState-compatible dicts
    (partial updates only — LangGraph merges via reducers).

    Args:
        agent:      The agent instance to wrap.
        timeout_s:  Per-execution wall-clock timeout in seconds.
        max_retries: Maximum number of outer retry attempts.

    Returns:
        An async callable suitable for ``workflow.add_node(name, fn)``.
    """
    agent_name = agent.config.name

    async def _node(state: GraphState) -> dict[str, Any]:
        job_id: str = state.get("job_id", "unknown")
        apk_sha256: str = state.get("apk_sha256", "")
        evidence: dict[str, Any] = state.get("evidence", {})
        analysis_context: dict[str, Any] = state.get("analysis_context", {})
        otel_carrier: dict[str, str] = state.get("otel_context", {})
        retry_counts: dict[str, int] = state.get("retry_counts", {})

        started_at = datetime.now(timezone.utc).isoformat()

        # ------------------------------------------------------------------
        # Restore OTel context and open a span
        # ------------------------------------------------------------------
        parent_ctx = _restore_otel_context(otel_carrier)
        with _TRACER.start_as_current_span(
            f"agent.{agent_name}",
            context=parent_ctx,
            kind=trace.SpanKind.INTERNAL,
            attributes={
                "sephela.job_id": job_id,
                "sephela.apk_sha256": apk_sha256,
                "sephela.agent": agent_name,
            },
        ) as span:
            span_id = format(span.get_span_context().span_id, "016x")

            _log("info", "agent_start", job_id, agent_name, span_id=span_id, apk_sha256=apk_sha256)

            # Mark as running
            running_entry: AgentResultEntry = AgentResultEntry(
                agent_name=agent_name,
                status=AgentRunStatus.RUNNING.value,
                started_at=started_at,
                span_id=span_id,
                retry_count=retry_counts.get(agent_name, 0),
            )
            yield_state: dict[str, Any] = {
                "agent_results": {agent_name: running_entry},
            }

            t0 = time.perf_counter()
            result_entry: AgentResultEntry
            new_findings: list[dict[str, Any]] = []
            new_context: dict[str, Any] = {}

            try:
                result: AgentResult = await _execute_with_retry(
                    agent=agent,
                    evidence=evidence,
                    context=analysis_context,
                    timeout_s=timeout_s,
                    max_retries=max_retries,
                    job_id=job_id,
                )

                exec_ms = int((time.perf_counter() - t0) * 1000)
                completed_at = datetime.now(timezone.utc).isoformat()

                if result.status == AgentStatus.completed:
                    status_val = AgentRunStatus.COMPLETED.value
                elif result.status == AgentStatus.partial:
                    status_val = AgentRunStatus.COMPLETED.value  # treat partial as completed
                else:
                    status_val = AgentRunStatus.FAILED.value

                # Serialise output and findings
                output_dict: Optional[dict[str, Any]] = None
                if result.output is not None:
                    output_dict = (
                        result.output.model_dump()
                        if hasattr(result.output, "model_dump")
                        else dict(result.output)
                    )

                new_findings = [
                    f.model_dump() if hasattr(f, "model_dump") else dict(f)
                    for f in (result.findings or [])
                ]

                errors_list = [
                    e.model_dump() if hasattr(e, "model_dump") else {"message": str(e)}
                    for e in (result.errors or [])
                ]

                result_entry = AgentResultEntry(
                    agent_name=agent_name,
                    status=status_val,
                    output=output_dict,
                    findings=new_findings,
                    errors=errors_list,
                    execution_time_ms=exec_ms,
                    tokens_used=result.tokens_used,
                    model_name=result.model_name,
                    retry_count=retry_counts.get(agent_name, 0),
                    started_at=started_at,
                    completed_at=completed_at,
                    span_id=span_id,
                )

                # Populate shared context for downstream agents
                if output_dict:
                    new_context[f"{agent_name}_output"] = output_dict
                if new_findings:
                    new_context[f"{agent_name}_findings"] = new_findings

                span.set_attribute("sephela.agent.status", status_val)
                span.set_attribute("sephela.agent.findings_count", len(new_findings))
                span.set_attribute("sephela.agent.tokens_used", result.tokens_used)
                span.set_status(trace.StatusCode.OK)

                _log(
                    "info",
                    "agent_complete",
                    job_id,
                    agent_name,
                    status=status_val,
                    exec_ms=exec_ms,
                    findings=len(new_findings),
                    tokens=result.tokens_used,
                )

            except asyncio.TimeoutError:
                exec_ms = int((time.perf_counter() - t0) * 1000)
                completed_at = datetime.now(timezone.utc).isoformat()

                result_entry = AgentResultEntry(
                    agent_name=agent_name,
                    status=AgentRunStatus.TIMED_OUT.value,
                    errors=[{"message": f"Agent timed out after {timeout_s}s"}],
                    execution_time_ms=exec_ms,
                    retry_count=retry_counts.get(agent_name, 0),
                    started_at=started_at,
                    completed_at=completed_at,
                    span_id=span_id,
                )

                span.set_status(trace.StatusCode.ERROR, "timeout")
                span.record_exception(asyncio.TimeoutError(f"Timed out after {timeout_s}s"))

                _log("error", "agent_timeout_fatal", job_id, agent_name, timeout_s=timeout_s)

            except Exception as exc:  # noqa: BLE001
                exec_ms = int((time.perf_counter() - t0) * 1000)
                completed_at = datetime.now(timezone.utc).isoformat()

                result_entry = AgentResultEntry(
                    agent_name=agent_name,
                    status=AgentRunStatus.FAILED.value,
                    errors=[{"message": str(exc), "error_type": type(exc).__name__}],
                    execution_time_ms=exec_ms,
                    retry_count=retry_counts.get(agent_name, 0),
                    started_at=started_at,
                    completed_at=completed_at,
                    span_id=span_id,
                )

                span.set_status(trace.StatusCode.ERROR, str(exc))
                span.record_exception(exc)

                _log(
                    "error",
                    "agent_failed",
                    job_id,
                    agent_name,
                    error=str(exc),
                    error_type=type(exc).__name__,
                )

            # ------------------------------------------------------------------
            # Build partial state update (reducer-safe)
            # ------------------------------------------------------------------
            partial: dict[str, Any] = {
                "agent_results": {agent_name: result_entry},
                "all_findings": new_findings,
            }
            if new_context:
                partial["analysis_context"] = new_context

            return partial

    # Expose agent metadata on the function for introspection
    _node.__name__ = f"node_{agent_name}"
    _node.__qualname__ = f"node_{agent_name}"
    return _node


# ---------------------------------------------------------------------------
# RiskAgent node (sequential — waits for all analysis agents)
# ---------------------------------------------------------------------------


def make_risk_node(
    agent: BaseAgent,
    timeout_s: float = _RISK_AGENT_TIMEOUT_S,
    max_retries: int = _MAX_RETRIES,
) -> Callable[[GraphState], dict[str, Any]]:
    """
    Create the RiskAgent node.

    Enriches the agent context with all previous findings before execution
    and stores the result in ``risk_result`` in addition to ``agent_results``.
    """
    agent_name = agent.config.name

    async def _node(state: GraphState) -> dict[str, Any]:
        job_id: str = state.get("job_id", "unknown")
        evidence: dict[str, Any] = state.get("evidence", {})
        otel_carrier: dict[str, str] = state.get("otel_context", {})

        # Compose full context including all prior agent outputs
        rich_context: dict[str, Any] = {
            **state.get("analysis_context", {}),
            "all_findings": state.get("all_findings", []),
            "job_id": job_id,
            "apk_sha256": state.get("apk_sha256", ""),
        }

        parent_ctx = _restore_otel_context(otel_carrier)
        with _TRACER.start_as_current_span(
            "agent.risk_agent",
            context=parent_ctx,
            kind=trace.SpanKind.INTERNAL,
            attributes={"sephela.job_id": job_id, "sephela.agent": agent_name},
        ) as span:
            span_id = format(span.get_span_context().span_id, "016x")
            started_at = datetime.now(timezone.utc).isoformat()
            t0 = time.perf_counter()

            _log("info", "agent_start", job_id, agent_name, span_id=span_id)

            result_entry: AgentResultEntry
            risk_result: Optional[dict[str, Any]] = None

            try:
                result: AgentResult = await _execute_with_retry(
                    agent=agent,
                    evidence=evidence,
                    context=rich_context,
                    timeout_s=timeout_s,
                    max_retries=max_retries,
                    job_id=job_id,
                )

                exec_ms = int((time.perf_counter() - t0) * 1000)
                completed_at = datetime.now(timezone.utc).isoformat()

                output_dict: Optional[dict[str, Any]] = None
                if result.output is not None:
                    output_dict = (
                        result.output.model_dump()
                        if hasattr(result.output, "model_dump")
                        else dict(result.output)
                    )
                    risk_result = output_dict

                status_val = (
                    AgentRunStatus.COMPLETED.value
                    if result.status in (AgentStatus.completed, AgentStatus.partial)
                    else AgentRunStatus.FAILED.value
                )

                result_entry = AgentResultEntry(
                    agent_name=agent_name,
                    status=status_val,
                    output=output_dict,
                    findings=[],
                    errors=[
                        e.model_dump() if hasattr(e, "model_dump") else {"message": str(e)}
                        for e in (result.errors or [])
                    ],
                    execution_time_ms=exec_ms,
                    tokens_used=result.tokens_used,
                    model_name=result.model_name,
                    started_at=started_at,
                    completed_at=completed_at,
                    span_id=span_id,
                )

                span.set_status(trace.StatusCode.OK)
                _log("info", "agent_complete", job_id, agent_name, exec_ms=exec_ms)

            except Exception as exc:  # noqa: BLE001
                exec_ms = int((time.perf_counter() - t0) * 1000)
                completed_at = datetime.now(timezone.utc).isoformat()

                result_entry = AgentResultEntry(
                    agent_name=agent_name,
                    status=AgentRunStatus.FAILED.value,
                    errors=[{"message": str(exc), "error_type": type(exc).__name__}],
                    execution_time_ms=exec_ms,
                    started_at=started_at,
                    completed_at=completed_at,
                    span_id=span_id,
                )
                span.set_status(trace.StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                _log("error", "agent_failed", job_id, agent_name, error=str(exc))

        partial: dict[str, Any] = {
            "agent_results": {agent_name: result_entry},
            "risk_result": risk_result,
            "all_findings": [],  # RiskAgent emits no new findings
        }
        if risk_result:
            partial["analysis_context"] = {
                f"{agent_name}_output": risk_result,
            }
        return partial

    _node.__name__ = "node_risk_agent"
    _node.__qualname__ = "node_risk_agent"
    return _node


# ---------------------------------------------------------------------------
# ReportAgent node (sequential — waits for RiskAgent)
# ---------------------------------------------------------------------------


def make_report_node(
    agent: BaseAgent,
    timeout_s: float = _REPORT_AGENT_TIMEOUT_S,
    max_retries: int = _MAX_RETRIES,
) -> Callable[[GraphState], dict[str, Any]]:
    """
    Create the ReportAgent node.

    Enriches context with risk result before execution.
    Stores the report in ``report`` field of state.
    """
    agent_name = agent.config.name

    async def _node(state: GraphState) -> dict[str, Any]:
        job_id: str = state.get("job_id", "unknown")
        evidence: dict[str, Any] = {
            **state.get("evidence", {}),
            "job_id": job_id,
            "sample_sha256": state.get("apk_sha256", ""),
        }
        otel_carrier: dict[str, str] = state.get("otel_context", {})

        rich_context: dict[str, Any] = {
            **state.get("analysis_context", {}),
            "all_findings": state.get("all_findings", []),
            "risk_result": state.get("risk_result"),
        }

        parent_ctx = _restore_otel_context(otel_carrier)
        with _TRACER.start_as_current_span(
            "agent.report_agent",
            context=parent_ctx,
            kind=trace.SpanKind.INTERNAL,
            attributes={"sephela.job_id": job_id, "sephela.agent": agent_name},
        ) as span:
            span_id = format(span.get_span_context().span_id, "016x")
            started_at = datetime.now(timezone.utc).isoformat()
            t0 = time.perf_counter()

            _log("info", "agent_start", job_id, agent_name, span_id=span_id)

            result_entry: AgentResultEntry
            report_dict: Optional[dict[str, Any]] = None

            try:
                result: AgentResult = await _execute_with_retry(
                    agent=agent,
                    evidence=evidence,
                    context=rich_context,
                    timeout_s=timeout_s,
                    max_retries=max_retries,
                    job_id=job_id,
                )

                exec_ms = int((time.perf_counter() - t0) * 1000)
                completed_at = datetime.now(timezone.utc).isoformat()

                output_dict: Optional[dict[str, Any]] = None
                if result.output is not None:
                    output_dict = (
                        result.output.model_dump()
                        if hasattr(result.output, "model_dump")
                        else dict(result.output)
                    )
                    report_dict = output_dict

                status_val = (
                    AgentRunStatus.COMPLETED.value
                    if result.status in (AgentStatus.completed, AgentStatus.partial)
                    else AgentRunStatus.FAILED.value
                )

                result_entry = AgentResultEntry(
                    agent_name=agent_name,
                    status=status_val,
                    output=output_dict,
                    findings=[],
                    errors=[
                        e.model_dump() if hasattr(e, "model_dump") else {"message": str(e)}
                        for e in (result.errors or [])
                    ],
                    execution_time_ms=exec_ms,
                    tokens_used=result.tokens_used,
                    model_name=result.model_name,
                    started_at=started_at,
                    completed_at=completed_at,
                    span_id=span_id,
                )

                span.set_status(trace.StatusCode.OK)
                _log("info", "agent_complete", job_id, agent_name, exec_ms=exec_ms)

            except Exception as exc:  # noqa: BLE001
                exec_ms = int((time.perf_counter() - t0) * 1000)
                completed_at = datetime.now(timezone.utc).isoformat()

                result_entry = AgentResultEntry(
                    agent_name=agent_name,
                    status=AgentRunStatus.FAILED.value,
                    errors=[{"message": str(exc), "error_type": type(exc).__name__}],
                    execution_time_ms=exec_ms,
                    started_at=started_at,
                    completed_at=completed_at,
                    span_id=span_id,
                )
                span.set_status(trace.StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                _log("error", "agent_failed", job_id, agent_name, error=str(exc))

        partial: dict[str, Any] = {
            "agent_results": {agent_name: result_entry},
            "report": report_dict,
            "all_findings": [],
            "pipeline_status": PipelineStatus.COMPLETED.value,
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }
        return partial

    _node.__name__ = "node_report_agent"
    _node.__qualname__ = "node_report_agent"
    return _node


# ---------------------------------------------------------------------------
# Orchestrator "start" node — marks pipeline as running
# ---------------------------------------------------------------------------


async def orchestrator_start_node(state: GraphState) -> dict[str, Any]:
    """
    Entry-point node that transitions the pipeline from PENDING → RUNNING
    and injects job metadata into the analysis context.
    """
    job_id = state.get("job_id", "unknown")
    _log("info", "pipeline_start", job_id, apk_sha256=state.get("apk_sha256"))

    # Inject OTel trace context so all downstream spans share the trace
    carrier: dict[str, str] = {}
    _PROPAGATOR.inject(carrier)

    return {
        "pipeline_status": PipelineStatus.RUNNING.value,
        "otel_context": carrier,
        "analysis_context": {
            "job_id": job_id,
            "apk_sha256": state.get("apk_sha256", ""),
        },
    }


# ---------------------------------------------------------------------------
# Finalisation node — emits final structured log
# ---------------------------------------------------------------------------


async def finalise_node(state: GraphState) -> dict[str, Any]:
    """
    Final node that records overall pipeline outcome.
    Called after ReportAgent to flush telemetry.
    """
    job_id = state.get("job_id", "unknown")
    status = state.get("pipeline_status", PipelineStatus.FAILED.value)
    error = state.get("error")
    total_findings = len(state.get("all_findings", []))
    agent_statuses = {
        name: entry.get("status")
        for name, entry in state.get("agent_results", {}).items()
    }

    _log(
        "info",
        "pipeline_complete",
        job_id,
        status=status,
        total_findings=total_findings,
        agents=agent_statuses,
        error=error,
        apk_sha256=state.get("apk_sha256"),
    )

    completed_at = state.get("completed_at") or datetime.now(timezone.utc).isoformat()
    return {
        "completed_at": completed_at,
    }
