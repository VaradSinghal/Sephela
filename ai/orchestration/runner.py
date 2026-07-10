"""Pipeline runner for executing the analysis graph."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, Optional
from dataclasses import dataclass
from datetime import datetime

from langgraph.checkpoint.base import BaseCheckpointSaver

from ai.orchestration.graph import create_analysis_graph, AnalysisState
from ai.orchestration.state import PipelineStatus
from ai.agents.base import AgentRegistry
from ai.orchestration.checkpointer import get_checkpointer

logger = logging.getLogger(__name__)


@dataclass
class PipelineRunResult:
    """Result of a pipeline run."""
    job_id: str
    sample_sha256: str
    status: PipelineStatus
    agent_results: Dict[str, Any]
    all_findings: list
    risk_score: Optional[float] = None
    risk_tier: Optional[str] = None
    report: Optional[Any] = None
    execution_time_ms: int = 0
    error: Optional[str] = None
    completed_at: Optional[datetime] = None


class PipelineRunner:
    """Orchestrates the multi-agent analysis pipeline."""

    def __init__(
        self,
        registry: AgentRegistry,
        checkpointer: Optional[BaseCheckpointSaver] = None,
        env: str = "development",
        connection_string: Optional[str] = None,
    ):
        self.registry = registry
        self.checkpointer = checkpointer or get_checkpointer(env, connection_string)
        self.graph = create_analysis_graph(registry, self.checkpointer)
        self.compiled_graph = self.graph.compile(checkpointer=self.checkpointer)

    async def run(
        self,
        job_id: str,
        sample_sha256: str,
        evidence: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> PipelineRunResult:
        """Run the complete analysis pipeline."""
        start_time = datetime.utcnow()

        # Initialize state
        initial_state = AnalysisState(
            job_id=job_id,
            sample_sha256=sample_sha256,
            evidence=evidence,
            context=context or {},
            status=PipelineStatus.PENDING,
        )

        # Graph config
        graph_config = {
            "configurable": {
                "job_id": job_id,
                "sample_sha256": sample_sha256,
            }
        }
        if config:
            graph_config.update(config)

        try:
            logger.info(f"Starting pipeline for job {job_id}")
            
            # Execute graph
            final_state = await self.compiled_graph.ainvoke(initial_state, graph_config)
            
            execution_time = int((datetime.utcnow() - start_time).total_seconds() * 1000)
            
            # Extract results
            risk_result = final_state.agent_results.get("risk_agent")
            report_result = final_state.agent_results.get("report_agent")
            
            risk_score = None
            risk_tier = None
            if risk_result and risk_result.output:
                risk_score = risk_result.output.score
                risk_tier = risk_result.output.tier.value if hasattr(risk_result.output.tier, 'value') else str(risk_result.output.tier)

            report = None
            if report_result and report_result.output:
                report = report_result.output.report

            status = PipelineStatus.COMPLETED
            if final_state.error:
                status = PipelineStatus.FAILED

            logger.info(f"Pipeline completed for job {job_id} with status {status}")

            return PipelineRunResult(
                job_id=job_id,
                sample_sha256=sample_sha256,
                status=status,
                agent_results={k: v.model_dump() if hasattr(v, 'model_dump') else v for k, v in final_state.agent_results.items()},
                all_findings=[f.model_dump() if hasattr(f, 'model_dump') else f for f in final_state.all_findings],
                risk_score=risk_score,
                risk_tier=risk_tier,
                report=report,
                execution_time_ms=execution_time,
                error=final_state.error,
                completed_at=datetime.utcnow(),
            )

        except Exception as e:
            logger.exception(f"Pipeline failed for job {job_id}: {e}")
            execution_time = int((datetime.utcnow() - start_time).total_seconds() * 1000)
            return PipelineRunResult(
                job_id=job_id,
                sample_sha256=sample_sha256,
                status=PipelineStatus.FAILED,
                agent_results={},
                all_findings=[],
                execution_time_ms=execution_time,
                error=str(e),
                completed_at=datetime.utcnow(),
            )

    async def resume(
        self,
        job_id: str,
        sample_sha256: str,
        config: Optional[Dict[str, Any]] = None,
    ) -> PipelineRunResult:
        """Resume a pipeline from the last checkpoint."""
        graph_config = {
            "configurable": {
                "job_id": job_id,
                "sample_sha256": sample_sha256,
            }
        }
        if config:
            graph_config.update(config)

        # Get last checkpoint
        checkpoint_tuple = await self.checkpointer.aget_tuple(graph_config)
        if not checkpoint_tuple:
            raise ValueError(f"No checkpoint found for job {job_id}")

        logger.info(f"Resuming pipeline for job {job_id} from checkpoint")
        
        # Resume from checkpoint
        final_state = await self.compiled_graph.ainvoke(None, graph_config)
        
        # ... same result extraction as run()
        execution_time = 0  # Would calculate from checkpoint
        
        return PipelineRunResult(
            job_id=job_id,
            sample_sha256=sample_sha256,
            status=PipelineStatus.COMPLETED if not final_state.error else PipelineStatus.FAILED,
            agent_results={k: v.model_dump() if hasattr(v, 'model_dump') else v for k, v in final_state.agent_results.items()},
            all_findings=[f.model_dump() if hasattr(f, 'model_dump') else f for f in final_state.all_findings],
            execution_time_ms=execution_time,
            error=final_state.error,
            completed_at=datetime.utcnow(),
        )

    async def get_status(self, job_id: str, sample_sha256: str) -> Optional[Dict[str, Any]]:
        """Get current pipeline status from checkpoints."""
        config = {
            "configurable": {
                "job_id": job_id,
                "sample_sha256": sample_sha256,
            }
        }
        checkpoint = await self.checkpointer.aget_tuple(config)
        if not checkpoint:
            return None
        
        state = checkpoint.checkpoint
        return {
            "job_id": job_id,
            "status": state.get("status"),
            "current_agent": state.get("current_agent"),
            "completed_agents": list(state.get("agent_results", {}).keys()),
            "error": state.get("error"),
            "updated_at": checkpoint.metadata.get("created_at"),
        }