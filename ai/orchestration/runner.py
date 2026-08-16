"""High-level runner for the multi-agent analysis graph.

``PipelineRunner`` is the checkpointed, resumable face of the LangGraph workflow
built by :mod:`ai.orchestration.workflow`. It exists alongside
:class:`ai.integration.SephelaAnalysisPipeline` and the two differ in what they
own:

- ``SephelaAnalysisPipeline`` owns *provider wiring* — it builds an LLM gateway
  from the environment, maps each agent to a model, and runs the graph once.
- ``PipelineRunner`` owns *durability* — it holds a checkpointer so a run can be
  resumed from its last completed node after a worker dies mid-job, and it
  exposes the partial state of an in-flight run.

Long-running APK analysis needs both, so neither wraps the other: a caller that
just wants a verdict uses the pipeline, and the Celery worker (which can lose its
process at any point) uses the runner.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from ai.orchestration.checkpointer import get_checkpointer
from ai.orchestration.graph_state import (
    GraphState,
    PipelineStatus,
    initial_state,
)
from ai.orchestration.workflow import WorkflowConfig, build_workflow

if TYPE_CHECKING:
    from langgraph.checkpoint.base import BaseCheckpointSaver

logger = logging.getLogger("sephela.orchestration.runner")

# LangGraph's own guard against a cyclic graph running away. The workflow is a
# DAG whose longest path is ~8 nodes, so this only ever trips on a real bug.
_RECURSION_LIMIT = 50


@dataclass
class PipelineRunResult:
    """Outcome of one graph execution, flattened out of ``GraphState``."""

    job_id: str
    apk_sha256: str
    status: PipelineStatus
    agent_results: dict[str, Any] = field(default_factory=dict)
    all_findings: list[dict[str, Any]] = field(default_factory=list)
    risk_score: float | None = None
    risk_tier: str | None = None
    report: dict[str, Any] | None = None
    execution_time_ms: int = 0
    error: str | None = None
    errors: list[str] = field(default_factory=list)
    completed_at: datetime | None = None


class PipelineRunner:
    """Runs the multi-agent workflow with checkpointing and resume support."""

    def __init__(
        self,
        llm_client: Any = None,
        *,
        knowledge: Any = None,
        checkpointer: BaseCheckpointSaver | None = None,
        env: str = "development",
        connection_string: str | None = None,
        config: WorkflowConfig | None = None,
    ) -> None:
        """
        Args:
            llm_client:        Async LLM gateway handed to every agent.
            knowledge:         Optional RAG knowledge service (Phase 12).
            checkpointer:      Explicit checkpointer; resolved from ``env`` if None.
            env:               Selects the default checkpointer implementation.
            connection_string: Postgres DSN for the production checkpointer.
            config:            Pre-built WorkflowConfig. Its ``checkpointer``,
                               ``llm_client``, and ``knowledge`` are filled in from
                               the arguments above when it leaves them unset, so a
                               caller can override timeouts without re-specifying
                               the wiring.
        """
        self.checkpointer = checkpointer or get_checkpointer(env, connection_string)

        cfg = config or WorkflowConfig()
        if cfg.llm_client is None:
            cfg.llm_client = llm_client
        if cfg.knowledge is None:
            cfg.knowledge = knowledge
        if cfg.checkpointer is None:
            cfg.checkpointer = self.checkpointer
        self.config = cfg

        # build_workflow returns an already-compiled graph — do not compile again.
        self.compiled_graph = build_workflow(cfg)

    # ------------------------------------------------------------------
    # Graph config
    # ------------------------------------------------------------------

    @staticmethod
    def _graph_config(job_id: str, overrides: dict[str, Any] | None = None) -> dict[str, Any]:
        """Build the LangGraph invocation config.

        ``thread_id`` is what the checkpointer keys state on, so it must be the
        job id — that is what makes ``resume`` able to find a half-finished run.
        """
        cfg: dict[str, Any] = {
            "configurable": {"thread_id": job_id, "job_id": job_id},
            "recursion_limit": _RECURSION_LIMIT,
        }
        if overrides:
            configurable = {**cfg["configurable"], **overrides.pop("configurable", {})}
            cfg.update(overrides)
            cfg["configurable"] = configurable
        return cfg

    # ------------------------------------------------------------------
    # Run
    # ------------------------------------------------------------------

    async def run(
        self,
        job_id: str,
        apk_sha256: str,
        evidence: dict[str, Any],
        config_overrides: dict[str, Any] | None = None,
        config: dict[str, Any] | None = None,
    ) -> PipelineRunResult:
        """Execute the full pipeline for one job."""
        started = datetime.now(UTC)
        state = initial_state(
            job_id=job_id,
            apk_sha256=apk_sha256,
            evidence=evidence,
            config_overrides=config_overrides,
        )

        logger.info('{"event": "pipeline_run_start", "job_id": "%s"}', job_id)
        try:
            final_state = await self.compiled_graph.ainvoke(
                state, self._graph_config(job_id, config)
            )
        except Exception as exc:  # noqa: BLE001
            # A crash here means the graph itself failed, not an agent — agent
            # failures are absorbed into state by make_agent_node.
            logger.exception('{"event": "pipeline_run_error", "job_id": "%s"}', job_id)
            return PipelineRunResult(
                job_id=job_id,
                apk_sha256=apk_sha256,
                status=PipelineStatus.FAILED,
                execution_time_ms=_elapsed_ms(started),
                error=str(exc),
                errors=[str(exc)],
                completed_at=datetime.now(UTC),
            )

        return self._to_result(final_state, job_id, apk_sha256, started)

    async def resume(
        self,
        job_id: str,
        apk_sha256: str = "",
        config: dict[str, Any] | None = None,
    ) -> PipelineRunResult:
        """Resume a previously checkpointed run from its last completed node.

        Passing ``None`` as the input is what tells LangGraph to continue from the
        checkpoint rather than start over.
        """
        started = datetime.now(UTC)
        graph_config = self._graph_config(job_id, config)

        checkpoint = await self.checkpointer.aget_tuple(graph_config)
        if not checkpoint:
            raise ValueError(f"No checkpoint found for job {job_id}")

        logger.info('{"event": "pipeline_resume", "job_id": "%s"}', job_id)
        final_state = await self.compiled_graph.ainvoke(None, graph_config)
        return self._to_result(
            final_state,
            job_id,
            apk_sha256 or final_state.get("apk_sha256", ""),
            started,
        )

    async def get_status(self, job_id: str) -> dict[str, Any] | None:
        """Report an in-flight run's progress from its latest checkpoint."""
        checkpoint = await self.checkpointer.aget_tuple(self._graph_config(job_id))
        if not checkpoint:
            return None

        values = checkpoint.checkpoint.get("channel_values", {}) or {}
        agent_results = values.get("agent_results", {}) or {}
        return {
            "job_id": job_id,
            "status": values.get("pipeline_status"),
            "completed_agents": sorted(agent_results),
            "error": values.get("error"),
            "updated_at": (checkpoint.metadata or {}).get("created_at"),
        }

    # ------------------------------------------------------------------
    # State → result
    # ------------------------------------------------------------------

    @staticmethod
    def _to_result(
        state: GraphState,
        job_id: str,
        apk_sha256: str,
        started: datetime,
    ) -> PipelineRunResult:
        risk_result = state.get("risk_result") or {}
        report = state.get("report") or {}
        errors = list(state.get("errors") or [])

        raw_status = state.get("pipeline_status")
        try:
            status = PipelineStatus(raw_status)
        except ValueError:
            status = PipelineStatus.FAILED

        return PipelineRunResult(
            job_id=job_id,
            apk_sha256=apk_sha256,
            status=status,
            agent_results=dict(state.get("agent_results") or {}),
            all_findings=list(state.get("all_findings") or []),
            risk_score=risk_result.get("score") or risk_result.get("risk_score"),
            risk_tier=risk_result.get("tier") or risk_result.get("risk_tier"),
            report=report or None,
            execution_time_ms=_elapsed_ms(started),
            error=state.get("error"),
            errors=errors,
            completed_at=datetime.now(UTC),
        )


def _elapsed_ms(since: datetime) -> int:
    return int((datetime.now(UTC) - since).total_seconds() * 1000)
