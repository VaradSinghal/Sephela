"""AI Analysis stage (Phase 12 / 13) — Orchestrates the multi-agent AI pipeline.

Consumes all extracted evidence from previous stages, attaches the RAG Knowledge Service,
and runs the LangGraph-based multi-agent analysis.
"""

from __future__ import annotations

import uuid
from typing import Any

from ai.integration import SephelaAnalysisPipeline
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.core.pipeline_metrics import record_llm_call
from app.db.models.analysis import AnalysisJob, JobStatus, Sample
from app.db.session import AsyncSessionLocal
from app.repositories.evidence import EvidenceRepository
from app.services.stages import StageOutcome, StageRunner
from app.tasks.celery_app import celery_app

logger = get_logger(__name__)

ENGINE_NAME = "ai_orchestrator"
ENGINE_VERSION = "1.0.0"


async def _run(job_id: str) -> str:
    jid = uuid.UUID(job_id)

    async with AsyncSessionLocal() as session:
        job = await session.get(AnalysisJob, jid)
        if job is None:
            logger.warning("ai_job_missing", job_id=job_id)
            return "missing"
        if job.status == JobStatus.cancelled:
            return JobStatus.cancelled.value

        sample = await session.get(Sample, job.sample_id)
        if sample is None:
            logger.warning("ai_sample_missing", job_id=job_id)
            return "missing"

        stage = StageRunner(session, jid, engine_name=ENGINE_NAME, engine_version=ENGINE_VERSION)

        outcome = await _execute(
            session=session, stage=stage, job_id=job_id, jid=jid, sample=sample
        )
        return outcome.status.value


async def _execute(
    *,
    session: AsyncSession,
    stage: StageRunner,
    job_id: str,
    jid: uuid.UUID,
    sample: Sample,
) -> StageOutcome:
    """Run the AI pipeline, mapping outcomes to stage status."""
    await stage.begin()

    # Load all existing evidence to feed the AI
    evidence_repo = EvidenceRepository(session)
    evidence_rows = await evidence_repo.list_for_job(jid)

    if not evidence_rows:
        return await stage.skip("No evidence available to analyze.")

    evidence_envelope = {}
    for ev in evidence_rows:
        evidence_envelope[ev.engine_name] = ev.payload

    try:
        # Build pipeline with Phase 12 RAG
        pipeline = await SephelaAnalysisPipeline.build_with_rag()

        # Execute the AI Graph
        result = await pipeline.analyze(
            apk_sha256=sample.sha256,
            evidence_envelope=evidence_envelope,
            job_id=job_id,
        )

        # Aggregate findings from all agents
        all_findings: list[dict[str, Any]] = []
        for agent_name, agent_res in result.agent_results.items():
            findings = agent_res.get("findings", [])
            for f in findings:
                if "id" not in f:
                    f["id"] = f"{agent_name}-{len(all_findings)}"
                all_findings.append(f)

        _record_agent_costs(result.agent_results)

        # Construct the payload for persistence
        payload = {
            "envelope_version": "1.0.0",
            "errors": result.errors,
            "warnings": result.warnings,
            "findings": all_findings,
            "report": result.report,
            "risk_result": result.risk_result,
            "agent_results": result.agent_results,
            "graph_state": result.graph_state,
        }

        return await stage.complete(payload)

    except Exception as exc:
        logger.exception("ai_pipeline_error", job_id=job_id)
        return await stage.fail(exc)


def _record_agent_costs(agent_results: dict[str, Any]) -> None:
    """Publish per-agent token spend and latency.

    This is the only place the platform can see what a paid credential is costing:
    eight agents per job, each on its own model, and the gateway's own retry and
    self-correction turns are already folded into the totals the agents report. Without
    it, cost per analysis is a line on an invoice rather than a metric.
    """
    for agent_name, entry in agent_results.items():
        if not isinstance(entry, dict):
            continue
        elapsed_ms = entry.get("execution_time_ms")
        record_llm_call(
            # Unknown rather than omitted, so a misconfigured model still shows up as a
            # series instead of silently costing nothing.
            model=str(entry.get("model_name") or "unknown"),
            agent=str(entry.get("agent_name") or agent_name),
            outcome=str(entry.get("status") or "unknown"),
            tokens=int(entry.get("tokens_used") or 0),
            duration_seconds=(elapsed_ms / 1000.0)
            if isinstance(elapsed_ms, (int, float))
            else None,
        )


@celery_app.task(name="ai.analyze", bind=True, max_retries=1)
def analyze_ai(self: Any, job_id: str) -> str:
    """Celery task entrypoint for AI orchestration."""
    import asyncio

    return asyncio.run(_run(job_id))
