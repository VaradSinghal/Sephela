"""Risk scoring stage (Phase 8) — findings → deterministic score → Envelope.

DFD-7 (docs/architecture/07-data-flow.md)::

    job (findings present) → q.scoring → normalize findings → per-domain scores →
    synergy rules → tier + confidence → Evidence Envelope + job.risk_score

This stage is deliberately **independent of the AI stage**. ``RiskScoringEngine``
is pure computation over normalized findings, so a deployment with no LLM
credential still gets a defensible score. When the AI stage did run, its agent
outputs are passed in as an extra signal for threat-family categorisation, but
they are never required.

Scoring is also what makes the score *explainable*: the envelope keeps the
per-domain breakdown and every synergy rule that fired, which is what the report
and the dashboard render. A bare number would not be defensible to an auditor.

Failure policy: no findings → ``skipped`` (nothing to score is not a clean bill
of health, and the skip reason says so); engine error → ``failed`` stage, job
continues.
"""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import asdict
from enum import Enum
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.logging import get_logger
from app.core.pipeline_metrics import record_risk
from app.db.models.analysis import AnalysisJob, Finding, JobStatus, StageStatus
from app.db.session import AsyncSessionLocal
from app.repositories.evidence import EvidenceRepository, FindingRepository
from app.services.stages import StageOutcome, StageRunner
from app.tasks.celery_app import celery_app

logger = get_logger(__name__)

ENGINE_NAME = "scoring"
ENGINE_VERSION = "1.0.0"

AI_ENGINE_NAME = "ai_orchestrator"
STATIC_ENGINE_NAME = "static"

# A findings set large enough to swamp the scoring domains adds nothing to the
# score (each domain takes its maximum), so cap the read rather than loading an
# unbounded set into memory.
MAX_FINDINGS = 5000

# Float confidence → the scoring engine's label buckets.
# ai.scoring.constants.CONFIDENCE_MULTIPLIERS keys: low/medium/high/very_high.
_CONFIDENCE_BUCKETS: tuple[tuple[float, str], ...] = (
    (0.95, "very_high"),
    (0.75, "high"),
    (0.45, "medium"),
    (0.0, "low"),
)
_DEFAULT_CONFIDENCE = "medium"


def confidence_label(value: float | None) -> str:
    """Bucket a 0–1 confidence into the label the scoring engine expects.

    A null confidence means the engine that produced the finding did not commit
    to one; ``medium`` is the neutral bucket rather than the most favourable, so
    an unstated confidence never inflates a score.
    """
    if value is None:
        return _DEFAULT_CONFIDENCE
    for threshold, label in _CONFIDENCE_BUCKETS:
        if value >= threshold:
            return label
    return "low"  # pragma: no cover — the 0.0 bucket is exhaustive


# Engine finding-type → the scoring engine's domain vocabulary.
#
# The engines' ``FindingType`` enum and ``FINDING_TYPE_TO_DOMAIN`` were written
# independently and do not agree. This matters more than a naming nit because
# ``_group_by_domain`` silently defaults an unrecognised type to the ``code``
# domain: a mismatch does not raise, it just files evidence under the wrong
# heading in the score decomposition an analyst has to defend.
#
# ``cert`` is unambiguous — the table spells it ``certificate``. A debug-signed
# certificate on a banking app is one of the strongest fake-app signals there is,
# and it belongs in ``manifest``, not ``code``.
_TYPE_ALIASES = {"cert": "certificate"}

# ``signature`` is genuinely overloaded: the static engine emits it for
# packer/protector/anti-VM matches (obfuscation.py), while the threat-intel engine
# emits it for a feed hit (correlate.py). The table maps it to ``threat_intel``,
# which would attribute a packed APK's findings to threat intelligence even when no
# feed was ever queried — a decomposition claiming corroboration that does not
# exist. Only the source engine disambiguates, and this adapter is the one place
# that knows it.
_TYPE_ALIASES_BY_ENGINE = {
    ("static", "signature"): "anti_analysis",
    ("code_intel", "signature"): "anti_analysis",
}


def scoring_type(source_engine: str, type_: str) -> str:
    """Translate an engine's finding type into the scoring engine's vocabulary."""
    by_engine = _TYPE_ALIASES_BY_ENGINE.get((source_engine, type_))
    if by_engine is not None:
        return by_engine
    return _TYPE_ALIASES.get(type_, type_)


def to_scoring_finding(row: Finding) -> dict[str, Any]:
    """Adapt a persisted ``Finding`` row to what ``RiskScoringEngine`` reads.

    The ORM and the scoring engine were written against different vocabularies
    (``mitre`` vs ``mitre_techniques``, ``detail`` vs ``description``, a float
    confidence vs a label, and the finding-type aliases above). Mapping explicitly
    here keeps that mismatch in one testable place instead of spread across the
    engine.
    """
    return {
        "id": row.finding_id,
        "type": scoring_type(row.source_engine, row.type),
        "severity": row.severity,
        "confidence": confidence_label(row.confidence),
        # Findings carry no separate title; the type is the stable short label.
        "title": row.type,
        "description": row.detail or "",
        "mitre_techniques": list(row.mitre or []),
        "owasp_mobile": list(row.owasp_mobile or []),
        "evidence_refs": [str(row.evidence_id)] if row.evidence_id else [],
    }


def scoring_payload(result: Any) -> dict[str, Any]:
    """Dump a ``ScoringResult`` to plain JSON-safe values.

    ``dataclasses.asdict`` copies field values as-is, so ``tier`` comes out as a
    ``RiskTierEnum`` member rather than its string. That reads back as
    ``"RiskTierEnum.benign"`` anywhere the value is stringified instead of
    JSON-encoded — which is how the tier ended up in a rendered report. Unwrapping
    it here keeps the stored envelope plain data, the way every other engine's is.
    """
    payload = asdict(result)
    payload["tier"] = _enum_value(payload.get("tier"))
    return payload


def _enum_value(value: Any) -> Any:
    return value.value if isinstance(value, Enum) else value


def _permissions(payload: dict[str, Any]) -> list[str]:
    """Pull the requested permission list out of a static envelope."""
    evidence = payload.get("evidence")
    if not isinstance(evidence, dict):
        return []
    block = evidence.get("permissions")
    if not isinstance(block, dict):
        return []
    perms = block.get("permissions")
    if not isinstance(perms, list):
        return []
    return [str(p) for p in perms if isinstance(p, str)]


def _agent_outputs(payload: dict[str, Any]) -> dict[str, Any]:
    """Pull agent results out of an AI envelope, when the AI stage ran."""
    results = payload.get("agent_results")
    return results if isinstance(results, dict) else {}


async def _gather_context(
    session: AsyncSession, jid: uuid.UUID
) -> tuple[list[str], dict[str, Any]]:
    """Collect the optional extra signals the categoriser can use."""
    repo = EvidenceRepository(session)
    permissions: list[str] = []
    agent_outputs: dict[str, Any] = {}

    static_rows = await repo.list_for_job(jid, engine=STATIC_ENGINE_NAME)
    if static_rows:
        permissions = _permissions(static_rows[-1].payload)

    ai_rows = await repo.list_for_job(jid, engine=AI_ENGINE_NAME)
    if ai_rows:
        agent_outputs = _agent_outputs(ai_rows[-1].payload)

    return permissions, agent_outputs


async def _run(job_id: str) -> str:
    jid = uuid.UUID(job_id)

    async with AsyncSessionLocal() as session:
        job = await session.get(AnalysisJob, jid)
        if job is None:
            logger.warning("scoring_job_missing", job_id=job_id)
            return "missing"
        if job.status == JobStatus.cancelled:
            return JobStatus.cancelled.value

        stage = StageRunner(session, jid, engine_name=ENGINE_NAME, engine_version=ENGINE_VERSION)
        outcome = await _execute(session=session, stage=stage, job=job, job_id=job_id, jid=jid)
        return outcome.status.value


async def _execute(
    *,
    session: AsyncSession,
    stage: StageRunner,
    job: AnalysisJob,
    job_id: str,
    jid: uuid.UUID,
) -> StageOutcome:
    """Score the job's findings, mapping every failure onto a stage status."""
    if not settings.scoring_enabled:
        await stage.begin()
        return await stage.skip("Risk scoring is disabled (SEPHELA_SCORING_ENABLED).")

    try:
        from ai.scoring import RiskScoringEngine
    except ImportError as exc:  # pragma: no cover — environment-dependent
        await stage.begin()
        return await stage.fail(
            f"The ai package is not installed in the worker environment (pip install -e ai): {exc}"
        )

    rows = await FindingRepository(session).list_for_job(jid, limit=MAX_FINDINGS)
    if not rows:
        await stage.begin()
        return await stage.skip(
            "No findings were produced by any analysis stage, so there is nothing to score."
        )

    permissions, agent_outputs = await _gather_context(session, jid)
    findings = [to_scoring_finding(r) for r in rows]

    await stage.begin()

    try:
        engine = RiskScoringEngine()
        result = await asyncio.to_thread(
            engine.score, findings, agent_outputs or None, permissions or None
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("scoring_engine_error", job_id=job_id)
        return await stage.fail(exc)

    payload: dict[str, Any] = {
        "envelope_version": "1.0.0",
        "status": "ok",
        "engine": {"name": ENGINE_NAME, "version": ENGINE_VERSION},
        "job_id": job_id,
        # Scoring derives from findings rather than producing new ones, so the
        # envelope carries no findings[] of its own.
        "findings": [],
        "errors": [],
        "evidence": {"scoring": scoring_payload(result)},
        "risk_score": result.final_score,
        "risk_tier": result.tier.value,
        "scored_findings": len(findings),
    }

    outcome = await stage.complete(payload)

    # Denormalise onto the job so job lists can rank and filter by risk without
    # joining evidence.
    job.risk_score = result.final_score
    job.risk_tier = result.tier.value
    await session.commit()

    logger.info(
        "scoring_completed",
        job_id=job_id,
        score=result.final_score,
        tier=result.tier.value,
        findings=len(findings),
    )
    record_risk(result.final_score, result.tier.value)
    await stage.set_progress(85)
    return outcome


@celery_app.task(
    name="scoring.analyze",
    queue="scoring",
    bind=True,
    max_retries=2,
    default_retry_delay=30,
    acks_late=True,
    # Pure computation over a bounded findings set.
    soft_time_limit=5 * 60,
    time_limit=6 * 60,
)
def analyze_scoring(self, job_id: str) -> str:  # type: ignore[no-untyped-def]
    """Risk-scoring stage for a job. Records outcomes, never re-raises.

    Returns the resulting stage status so a Celery chain can observe it.
    """
    try:
        return asyncio.run(_run(job_id))
    except Exception:  # noqa: BLE001
        logger.exception("scoring_task_error", job_id=job_id)
        return StageStatus.failed.value
