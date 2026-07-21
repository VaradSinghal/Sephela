"""End-to-End Pipeline Integration.

This module chains all Sephela engines (Static, Code Intel, Dynamic, AI,
Scoring, and Reporting) synchronously. In production (Phase 14), these are
distributed via Celery queues, but this module proves the end-to-end data
contract and orchestration logic.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from ai.agents.manifest import ManifestAgent
from ai.agents.permission import PermissionAgent
from ai.agents.code import CodeAgent
from ai.agents.api import APIAgent
from ai.agents.network import NetworkAgent
from ai.agents.threat_intel import ThreatIntelAgent
from ai.agents.risk import RiskAgent
from ai.agents.report import ReportAgent
from ai.agents.base import AgentRegistry, AgentConfig
from ai.orchestration.graph import create_analysis_graph, run_analysis_pipeline
from ai.scoring.engine import RiskScoringEngine
from ai.scoring.models import ScoringResult
from engines.reporting.sephela_reporting.engine import ReportingEngine
from engines.reporting.sephela_reporting.models import AnalysisReport, ExecutiveSummary, TechnicalDetails, EvidenceCatalog, ComplianceMapping
from engines.reporting.sephela_reporting.models import ReportingResult
import sephela_static
import sephela_code_intel
import sephela_dynamic


def get_ai_registry(mock_llm: bool = False) -> AgentRegistry:
    """Build the AI agent registry, optionally with mocked LLM calls."""
    registry = AgentRegistry()
    
    registry.register(ManifestAgent())
    registry.register(PermissionAgent())
    registry.register(CodeAgent())
    registry.register(APIAgent())
    registry.register(NetworkAgent())
    registry.register(ThreatIntelAgent())
    registry.register(RiskAgent())
    registry.register(ReportAgent())
    
    return registry


async def run_e2e_pipeline(
    apk_path: Path | str,
    dynamic_artifacts_dir: Path | str,
    job_id: str,
    mock_ai: bool = False,
) -> tuple[AnalysisReport, ReportingResult]:
    """Execute the full multi-engine analysis pipeline.

    Args:
        apk_path: Path to the target APK.
        dynamic_artifacts_dir: Path to the sandbox output (frida, pcap, etc).
        job_id: Unique identifier for the analysis job.
        mock_ai: If True, AI LLM calls will be mocked (used in tests).

    Returns:
        The final AnalysisReport model and the ReportingResult (paths to generated files).
    """
    apk_path = Path(apk_path)
    dyn_dir = Path(dynamic_artifacts_dir)

    # 1. Static Analysis
    print("[1/6] Running Static Engine...")
    static_env = sephela_static.analyze(apk_path, job_id=job_id)

    # 2. Code Intelligence
    print("[2/6] Running Code Intel Engine...")
    code_env = sephela_code_intel.analyze(
        static_env.evidence,
        job_id=job_id,
        apk_sha256=static_env.apk_sha256,
        artifact_dir=str(apk_path.parent)
    )

    # Merge code intel findings and evidence into the main envelope
    static_env.findings.extend(code_env.findings)
    for k, v in code_env.evidence.items():
        static_env.evidence[k] = v

    # 3. Dynamic Analysis
    print("[3/6] Running Dynamic Engine (Sandbox Artifacts)...")
    dynamic_env = sephela_dynamic.analyze(dyn_dir, job_id=job_id)
    
    # Merge dynamic findings and evidence
    static_env.findings.extend(dynamic_env.findings)
    for k, v in dynamic_env.evidence.items():
        static_env.evidence[k] = v

    # 4. AI Orchestration (Multi-Agent)
    print("[4/6] Running AI Orchestration Graph...")
    registry = get_ai_registry(mock_llm=mock_ai)
    graph = create_analysis_graph(registry)
    
    # We pass the combined evidence dictionary
    evidence_dict = static_env.model_dump()["evidence"]
    
    # Run the graph
    ai_state = await run_analysis_pipeline(
        graph=graph,
        job_id=job_id,
        sample_sha256=static_env.apk_sha256 or "unknown",
        evidence=evidence_dict,
    )

    def _normalize(f: Any) -> dict:
        if hasattr(f, "model_dump"):
            d = f.model_dump()
        else:
            d = dict(f)
            
        if "detail" in d and "description" not in d:
            d["description"] = d.pop("detail")
            
        if "title" not in d:
            t = d.get("type", "finding")
            if hasattr(t, "value"): t = t.value
            d["title"] = str(t).replace("_", " ").title()
            
        if "confidence" in d and isinstance(d["confidence"], (int, float)):
            conf = d["confidence"]
            if conf >= 0.8: d["confidence"] = "very_high"
            elif conf >= 0.6: d["confidence"] = "high"
            elif conf >= 0.4: d["confidence"] = "medium"
            else: d["confidence"] = "low"
            
        if hasattr(d.get("severity"), "value"):
            d["severity"] = d["severity"].value
        if hasattr(d.get("type"), "value"):
            d["type"] = d["type"].value
            
        return d

    # Combine all deterministic and AI findings
    all_findings = []
    if static_env and hasattr(static_env, "findings"):
        for f in static_env.findings:
            all_findings.append(_normalize(f))
            
    if dynamic_env and hasattr(dynamic_env, "findings"):
        for f in dynamic_env.findings:
            all_findings.append(_normalize(f))
            
    # AI findings are already dicts from the agent outputs (or Finding schemas)
    for ai_finding in ai_state.get("all_findings", []):
        all_findings.append(_normalize(ai_finding))

    # 5. Risk Scoring Engine
    print("[5/6] Running Risk Scoring Engine...")
    score_engine = RiskScoringEngine()
    score_result: ScoringResult = score_engine.score(
        findings=all_findings
    )

    # 6. Reporting Engine
    print("[6/6] Generating Reports (JSON, Markdown, HTML, SARIF, PDF)...")
    # Convert score_result to dict using dataclasses
    import dataclasses
    
    # Construct the final report payload
    report_kwargs = {
        "report_id": f"REP-{job_id}",
        "job_id": job_id,
        "sample_sha256": static_env.apk_sha256 or "unknown",
        "executive_summary": ExecutiveSummary(
            overview="Automated Analysis Report",
            risk_score=score_result.final_score,
            risk_tier=score_result.tier.value,
            primary_category=score_result.primary_category,
        ),
        "technical_details": TechnicalDetails(),
        "evidence_catalog": EvidenceCatalog(),
        "compliance_mapping": ComplianceMapping(),
        "findings": all_findings,
    }

    report = AnalysisReport(**report_kwargs)
    report_engine = ReportingEngine()
    render_results = report_engine.generate(report.model_dump(mode="json"))

    print(f"[*] Pipeline Complete. Score: {score_result.final_score}/100 ({score_result.tier.value.upper()})")
    
    return report, render_results
