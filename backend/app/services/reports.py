"""Report assembly — database rows → the reporting engine's ``AnalysisReport``.

The reporting engine is a pure renderer: it validates an ``AnalysisReport`` dict
and turns it into JSON/Markdown/HTML/PDF/SARIF. Somebody has to build that dict.
Before this module that was the AI orchestrator's job, which made the report
hostage to a paid LLM credential — no key meant no report at all.

So this builds the report *deterministically* from what the pipeline already
persisted: the scoring envelope for the numbers, findings for the body, the
per-engine envelopes for technical detail, and the findings' own framework tags
for compliance mapping. When the AI stage did run, its narrative is layered on
top — ``ai_reasoning`` and a richer overview — but nothing here depends on it.

The prose it generates is templated, and reads that way on purpose. A report that
imitated analyst narrative without an analyst (or a model) behind it would be
worse than an obviously mechanical summary.

Contract reference: engines/reporting/sephela_reporting/models.py.
"""

from __future__ import annotations

import uuid
from enum import Enum
from typing import Any

from app.db.models.analysis import AnalysisJob, Evidence, Finding, Sample

# Mirrors sephela_reporting.models.Severity / Confidence. Anything an engine
# emits outside these sets is coerced rather than allowed to fail validation of
# the whole report.
_SEVERITIES = ("info", "low", "medium", "high", "critical")
_CONFIDENCES = ("low", "medium", "high", "very_high")
_DEFAULT_SEVERITY = "info"
_DEFAULT_CONFIDENCE = "medium"

# Severity ordering for ranking the report body, worst first.
_SEVERITY_RANK = {name: index for index, name in enumerate(reversed(_SEVERITIES))}

# Engine name → the TechnicalDetails field it populates.
_TECHNICAL_SECTIONS = {
    "static": "static_analysis",
    "code_intel": "code_analysis",
    "dynamic": "dynamic_analysis",
    "threat_intel": "threat_intel",
}

AI_ENGINE_NAME = "ai_orchestrator"
SCORING_ENGINE_NAME = "scoring"

# What the report body carries. Findings beyond this are still in the database
# and on /jobs/{id}/findings; a 400-page PDF serves nobody.
MAX_REPORT_FINDINGS = 250

DEFAULT_FORMATS = ("json", "markdown", "html", "sarif", "pdf")


def _severity(value: str | None) -> str:
    v = (value or "").strip().lower()
    return v if v in _SEVERITIES else _DEFAULT_SEVERITY


def _confidence(value: float | None) -> str:
    """Bucket a 0–1 confidence into the renderer's label set.

    Kept consistent with ``app.tasks.scoring.confidence_label`` so the report and
    the score describe the same finding the same way.
    """
    if value is None:
        return _DEFAULT_CONFIDENCE
    if value >= 0.95:
        return "very_high"
    if value >= 0.75:
        return "high"
    if value >= 0.45:
        return "medium"
    return "low"


_TIERS = ("benign", "suspicious", "malicious", "critical")


def _tier_name(value: Any) -> str | None:
    """Normalise a tier to its bare name, whatever wrapper it arrived in."""
    if value is None:
        return None
    raw = value.value if isinstance(value, Enum) else value
    name = str(raw).strip().lower()
    # An enum stringified the wrong way looks like "risktierenum.benign".
    if "." in name:
        name = name.rsplit(".", 1)[1]
    return name if name in _TIERS else None


def report_id_for(job_id: uuid.UUID | str) -> str:
    """A stable report id for a job.

    Deterministic so a re-rendered report keeps its identity — the report is a
    view of the job, not a new artifact each time it is generated.
    """
    return f"rpt-{job_id}"


def to_report_finding(row: Finding) -> dict[str, Any]:
    """Adapt a persisted ``Finding`` row to the renderer's finding shape."""
    return {
        "id": row.finding_id,
        "type": row.type,
        "severity": _severity(row.severity),
        "confidence": _confidence(row.confidence),
        # The ORM has no separate title; type is the stable short label.
        "title": row.type.replace("_", " "),
        "description": row.detail or "",
        "evidence_refs": _evidence_refs(row),
        "mitre_techniques": list(row.mitre or []),
        "owasp_mobile": list(row.owasp_mobile or []),
        "metadata": {"source_engine": row.source_engine},
    }


def _evidence_refs(row: Finding) -> list[dict[str, Any]]:
    """Turn a finding's provenance into renderer ``EvidenceRef`` entries.

    Provenance is what makes a finding checkable rather than asserted, so it is
    carried through to the report even when it is sparse.
    """
    provenance = row.provenance if isinstance(row.provenance, dict) else {}
    path = provenance.get("path") or provenance.get("location") or ""
    snippet = provenance.get("snippet") or provenance.get("evidence")
    return [
        {
            "extractor": str(provenance.get("extractor") or row.source_engine),
            "path": str(path),
            "snippet": str(snippet) if snippet is not None else None,
        }
    ]


def _rank(finding: dict[str, Any]) -> tuple[int, str]:
    return (_SEVERITY_RANK.get(finding["severity"], len(_SEVERITIES)), finding["id"])


def compliance_mapping(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Invert findings' framework tags into technique → finding-ids maps.

    Built from the findings themselves rather than from a curated table, so the
    mapping can never claim coverage the evidence does not support.
    """
    mitre: dict[str, list[str]] = {}
    owasp: dict[str, list[str]] = {}
    for finding in findings:
        for technique in finding.get("mitre_techniques", []):
            mitre.setdefault(str(technique), []).append(finding["id"])
        for category in finding.get("owasp_mobile", []):
            owasp.setdefault(str(category), []).append(finding["id"])
    return {"mitre_attack": mitre, "owasp_mobile": owasp}


def _overview(
    *, sample: Sample, score: float | None, tier: str | None, findings: list[dict[str, Any]]
) -> str:
    """A templated, mechanical summary of the run."""
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
    breakdown = ", ".join(
        f"{counts[name]} {name}" for name in reversed(_SEVERITIES) if counts.get(name)
    )

    if score is None or tier is None:
        return (
            f"Automated analysis of {sample.sha256} produced "
            f"{len(findings)} finding(s) ({breakdown or 'none'}). No risk score was "
            f"computed for this run."
        )
    return (
        f"Automated analysis of {sample.sha256} scored {score:.1f}/100, placing it "
        f"in the '{tier}' tier. {len(findings)} finding(s) were recorded"
        f"{f' ({breakdown})' if breakdown else ''}. Scores are computed "
        f"deterministically from per-domain finding severity and confidence; see the "
        f"score breakdown for the contribution of each domain."
    )


def _recommended_actions(tier: str | None) -> list[str]:
    """Tier-driven next steps. Procedural, not analytical."""
    if tier in ("malicious", "critical"):
        return [
            "Treat this sample as hostile: block its signing certificate and package name.",
            "Escalate to the fraud team for customer-impact assessment.",
            "Submit the extracted indicators to the institution's blocklists.",
            "Preserve the sample and this report for regulatory reporting.",
        ]
    if tier == "suspicious":
        return [
            "Assign to an analyst for manual review before acting on the score.",
            "Cross-check the extracted indicators against internal telemetry.",
        ]
    return ["No automated action recommended. Retain the report for audit purposes."]


def scoring_evidence(rows: list[Evidence]) -> dict[str, Any] | None:
    """Find the scoring envelope's ``ScoringResult`` block, if scoring ran."""
    for row in rows:
        if row.engine_name != SCORING_ENGINE_NAME:
            continue
        evidence = row.payload.get("evidence")
        if isinstance(evidence, dict):
            block = evidence.get("scoring")
            if isinstance(block, dict):
                return block
    return None


def build_report_data(
    *,
    job: AnalysisJob,
    sample: Sample,
    evidence_rows: list[Evidence],
    finding_rows: list[Finding],
) -> dict[str, Any]:
    """Assemble the ``AnalysisReport`` dict for the reporting engine.

    Everything is optional except the sample and the job: a report over a run
    where only static analysis succeeded is still a valid, useful report, and
    saying so is better than refusing to render.
    """
    findings = sorted((to_report_finding(r) for r in finding_rows), key=_rank)[:MAX_REPORT_FINDINGS]

    scoring = scoring_evidence(evidence_rows)
    score = scoring.get("final_score") if scoring else job.risk_score
    # Coerced rather than trusted: the scoring envelope is a dataclass dump, and an
    # enum that slipped through would render as "RiskTierEnum.benign" in the report
    # a bank forwards to a regulator.
    tier = _tier_name(scoring.get("tier") if scoring else job.risk_tier)

    by_engine = {row.engine_name: row.payload for row in evidence_rows}
    technical: dict[str, Any] = {
        "sample_info": {
            "sha256": sample.sha256,
            "md5": sample.md5,
            "sha1": sample.sha1,
            "file_size": sample.file_size,
            "filename": sample.original_filename,
            "package_name": sample.package_name,
            "job_id": str(job.id),
            "pipeline_version": job.pipeline_version,
            "job_status": job.status.value,
        }
    }
    for engine_name, field in _TECHNICAL_SECTIONS.items():
        payload = by_engine.get(engine_name)
        if isinstance(payload, dict):
            evidence = payload.get("evidence")
            technical[field] = evidence if isinstance(evidence, dict) else {}

    ai_payload = by_engine.get(AI_ENGINE_NAME)
    if isinstance(ai_payload, dict):
        technical["ai_reasoning"] = {
            "agent_results": ai_payload.get("agent_results") or {},
            "narrative": (ai_payload.get("report") or {}),
        }

    exec_summary: dict[str, Any] = {
        "overview": _overview(sample=sample, score=score, tier=tier, findings=findings),
        "risk_score": float(score) if score is not None else 0.0,
        # "unknown", never "benign". The schema needs a string here and the score
        # falls back to 0.0, so defaulting the tier to benign would turn "we did not
        # score this" into a clean bill of health.
        "risk_tier": tier or "unknown",
        "recommended_actions": _recommended_actions(tier),
    }
    if scoring:
        exec_summary["primary_category"] = scoring.get("primary_category")
        exec_summary["key_findings"] = [str(k) for k in (scoring.get("key_findings") or [])]

    # An LLM narrative, when present, improves the prose but never the numbers.
    ai_report = ai_payload.get("report") if isinstance(ai_payload, dict) else None
    if isinstance(ai_report, dict):
        ai_exec = ai_report.get("executive_summary")
        if isinstance(ai_exec, dict):
            for field in ("overview", "business_impact", "one_page_summary"):
                value = ai_exec.get(field)
                if isinstance(value, str) and value.strip():
                    exec_summary[field] = value

    return {
        "report_id": report_id_for(job.id),
        "job_id": str(job.id),
        "sample_sha256": sample.sha256,
        "executive_summary": exec_summary,
        "technical_details": technical,
        "evidence_catalog": _evidence_catalog(by_engine),
        "compliance_mapping": compliance_mapping(findings),
        "findings": findings,
        "sections": [],
    }


def _evidence_catalog(by_engine: dict[str, Any]) -> dict[str, Any]:
    """Summarise which envelopes exist, without inlining their bulk.

    The catalog is an index for an analyst deciding what to pull from
    ``/jobs/{id}/evidence``, not a second copy of the evidence.
    """
    catalog: dict[str, Any] = {
        "static_evidence": [],
        "dynamic_evidence": [],
        "ioc_list": [],
    }
    for engine_name, payload in by_engine.items():
        if not isinstance(payload, dict):
            continue
        entry = {
            "engine": engine_name,
            "envelope_version": payload.get("envelope_version"),
            "status": payload.get("status"),
        }
        if engine_name == "dynamic":
            catalog["dynamic_evidence"].append(entry)
        else:
            catalog["static_evidence"].append(entry)

    threat_intel = by_engine.get("threat_intel")
    if isinstance(threat_intel, dict):
        evidence = threat_intel.get("evidence")
        if isinstance(evidence, dict):
            verdicts = evidence.get("verdicts")
            if isinstance(verdicts, list):
                catalog["ioc_list"] = verdicts[:500]

    return catalog
