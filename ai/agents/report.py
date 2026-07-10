"""Report Agent - Generates structured analysis reports in multiple formats."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from pydantic import BaseModel

from ai.schemas.base import Finding, Severity
from ai.schemas.report import ReportAnalysis, ReportSection, ExecutiveSummary, TechnicalDetails, EvidenceCatalog, ComplianceMapping, AnalysisReport, ReportFormat, ReportGenerationRequest, ReportGenerationResult
from ai.agents.base import BaseAgent, AgentConfig, AgentResult


class ReportAgent(BaseAgent[ReportGenerationResult]):
    """Generates comprehensive analysis reports from all agent outputs."""

    def __init__(self, llm_client: Any = None):
        config = AgentConfig(
            name="report_agent",
            model="claude-3-5-sonnet-20241022",
            temperature=0.2,
            max_tokens=8192,
            output_schema=ReportGenerationResult,
            system_prompt=self._get_system_prompt(),
        )
        super().__init__(config, llm_client)

    def _get_system_prompt(self) -> str:
        return """You are a senior security analyst writing executive and technical malware analysis reports.
Generate a comprehensive report from all agent findings that serves:
1. SOC analysts (technical details, IOCs, MITRE mappings)
2. Management (executive summary, risk score, business impact)
3. Compliance teams (framework mappings, evidence catalog)

The report must be:
- Evidence-based with traceable findings
- Structured for multiple output formats (JSON, Markdown, PDF, SARIF)
- Classified per TLP (Traffic Light Protocol)
- Actionable with clear recommendations

Output must conform to ReportGenerationResult schema."""

    def build_prompt(self, evidence: dict[str, Any], context: dict[str, Any]) -> str:
        job_id = evidence.get("job_id", "unknown")
        sample_sha256 = evidence.get("sample_sha256", "unknown")
        risk_output = context.get("risk_agent_output", {})
        all_findings = context.get("all_findings", [])

        prompt = f"""Generate a comprehensive malware analysis report.

=== JOB INFO ===
Job ID: {job_id}
Sample SHA256: {sample_sha256}
Generated: {datetime.utcnow().isoformat()}Z

=== RISK ASSESSMENT ===
Score: {risk_output.get('score', 'N/A')}
Tier: {risk_output.get('tier', 'N/A')}
Confidence: {risk_output.get('confidence', 'N/A')}
Category: {risk_output.get('primary_category', 'unknown')}
Breakdown: {json.dumps(risk_output.get('breakdown', []), indent=2)}

=== ALL FINDINGS ({len(all_findings)}) ===
{json.dumps([{
    "id": f.id if hasattr(f, 'id') else f.get('id'),
    "type": f.type if hasattr(f, 'type') else f.get('type'),
    "severity": f.severity.value if hasattr(f.severity, 'value') else f.get('severity'),
    "title": f.title if hasattr(f, 'title') else f.get('title'),
    "description": f.description if hasattr(f, 'description') else f.get('description'),
    "mitre": f.mitre_techniques if hasattr(f, 'mitre_techniques') else f.get('mitre_techniques', []),
    "owasp": f.owasp_mobile if hasattr(f, 'owasp_mobile') else f.get('owasp_mobile', []),
} for f in all_findings], indent=2)}

=== AGENT OUTPUTS ===
Manifest: {json.dumps(context.get('manifest_agent_output', {}), indent=2)[:2000]}
Permissions: {json.dumps(context.get('permission_agent_output', {}), indent=2)[:2000]}
Code: {json.dumps(context.get('code_agent_output', {}), indent=2)[:2000]}
API: {json.dumps(context.get('api_agent_output', {}), indent=2)[:2000]}
Network: {json.dumps(context.get('network_agent_output', {}), indent=2)[:2000]}
Threat Intel: {json.dumps(context.get('threat_intel_agent_output', {}), indent=2)[:2000]}

Generate ReportGenerationResult with:
1. ExecutiveSummary (1-page for leadership)
2. TechnicalDetails (full analysis per agent)
3. EvidenceCatalog (all artifacts)
4. ComplianceMapping (MITRE, OWASP, NIST, ISO, PCI)
5. Structured sections for rendering
6. Recommended actions prioritized by risk"""
        return prompt

    def parse_output(self, raw_output: str) -> ReportGenerationResult:
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            import re
            match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', raw_output, re.DOTALL)
            if match:
                data = json.loads(match.group(1))
            else:
                raise ValueError("Could not parse agent output as JSON")

        return ReportGenerationResult(**data)

    def extract_findings(self, output: ReportGenerationResult) -> list[Finding]:
        return []


def generate_report_deterministic(evidence: dict[str, Any], context: dict[str, Any]) -> ReportGenerationResult:
    """Deterministic report generation without LLM."""
    job_id = evidence.get("job_id", "unknown")
    sample_sha256 = evidence.get("sample_sha256", "unknown")
    risk_output = context.get("risk_agent_output", {})
    all_findings = context.get("all_findings", [])

    # Build executive summary
    score = risk_output.get("score", 0)
    tier = risk_output.get("tier", "benign")
    category = risk_output.get("primary_category", "unknown")

    exec_summary = ExecutiveSummary(
        overview=f"Analysis of Android APK ({sample_sha256[:16]}...) completed with risk score {score}/100 ({tier}).",
        risk_score=score,
        risk_tier=tier,
        key_findings=[f.title if hasattr(f, 'title') else f.get('title', '') for f in all_findings[:5] if (f.severity if hasattr(f, 'severity') else f.get('severity')) in (Severity.critical, Severity.high, 'critical', 'high')],
        business_impact=f"This {category} poses {'significant' if score > 70 else 'moderate' if score > 40 else 'low'} risk to financial systems and user data.",
        recommended_actions=[
            "Block indicators at network perimeter",
            "Update mobile threat detection rules",
            "Notify fraud monitoring teams",
            "Initiate incident response if found in environment",
        ],
        one_page_summary=f"Sample {sample_sha256[:16]}... classified as {category} with {tier} risk ({score}/100). Immediate containment recommended."
    )

    # Build technical details
    tech_details = TechnicalDetails(
        sample_info={"sha256": sample_sha256, "job_id": job_id},
        static_analysis=context.get("manifest_agent_output", {}),
        code_analysis=context.get("code_agent_output", {}),
        network_analysis=context.get("network_agent_output", {}),
        threat_intel=context.get("threat_intel_agent_output", {}),
        ai_reasoning={"agents_run": list(context.keys())},
    )

    # Build evidence catalog
    evidence_catalog = EvidenceCatalog(
        static_evidence=list(context.keys()),
        extracted_strings=[],
        ioc_list=[],
    )

    # Build compliance mapping
    mitre_techniques = set()
    owasp_categories = set()
    for f in all_findings:
        mitre = f.mitre_techniques if hasattr(f, 'mitre_techniques') else f.get('mitre_techniques', [])
        owasp = f.owasp_mobile if hasattr(f, 'owasp_mobile') else f.get('owasp_mobile', [])
        mitre_techniques.update(mitre)
        owasp_categories.update(owasp)

    compliance = ComplianceMapping(
        mitre_attack={"techniques": list(mitre_techniques)},
        owasp_mobile={"categories": list(owasp_categories)},
        nist_csf={"functions": ["Identify", "Protect", "Detect", "Respond", "Recover"]},
        iso_27001={"controls": ["A.12.2", "A.12.6", "A.16.1"]},
        pci_dss={"requirements": ["6.5", "11.3", "11.4"]},
    )

    # Build sections
    sections = [
        ReportSection(section_id="ex_id="exec_summary", title="Executive Summary", content=exec_summary.overview, order=1),
        ReportSection(section_id="risk_score", title="Risk Score & Classification", content=f"Score: {score}/100, Tier: {tier}, Category: {category}", order=2),
        ReportSection(section_id="technical", title="Technical Analysis", content="See technical_details", order=3),
        ReportSection(section_id="iocs", title="Indicators of Compromise", content="See evidence_catalog", order=4),
        ReportSection(section_id="mitre", title="MITRE ATT&CK Mapping", content=f"Techniques: {', '.join(sorted(mitre_techniques))}", order=5),
        ReportSection(section_id="recommendations", title="Recommendations", content="\n".join(exec_summary.recommended_actions), order=6),
    ]

    report = AnalysisReport(
        report_id=f"rpt_{job_id}",
        job_id=job_id,
        sample_sha256=sample_sha256,
        executive_summary=exec_summary,
        technical_details=tech_details,
        evidence_catalog=evidence_catalog,
        compliance_mapping=compliance,
        sections=sections,
    )

    return ReportGenerationResult(
        report=report,
        generation_time_ms=100,
        warnings=[],
    )