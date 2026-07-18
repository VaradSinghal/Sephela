"""SARIF renderer — OASIS Static Analysis Results Interchange Format v2.1.0.

Converts analysis findings into SARIF JSON for integration with GitHub
Advanced Security, Azure DevOps, and other SARIF-consuming tools.

Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/
"""

from __future__ import annotations

import json
from typing import Any

from sephela_reporting.models import AnalysisReport, Finding, ReportFormat, RenderedArtifact
from sephela_reporting.renderers import BaseRenderer

# SARIF severity → SARIF level mapping
_SEVERITY_TO_LEVEL: dict[str, str] = {
    "info": "note",
    "low": "note",
    "medium": "warning",
    "high": "error",
    "critical": "error",
}


class SarifRenderer(BaseRenderer):
    """Render findings to SARIF v2.1.0 JSON."""

    name = "sarif"

    def render(self, report: AnalysisReport) -> RenderedArtifact:
        """Build a SARIF v2.1.0 document from the report findings.

        Args:
            report: Validated analysis report.

        Returns:
            SARIF JSON bytes with ``application/sarif+json`` media type.
        """
        sarif = _build_sarif_document(report)
        content = json.dumps(sarif, indent=2, sort_keys=False, ensure_ascii=False)
        return RenderedArtifact(
            format=ReportFormat.sarif,
            content_bytes=content.encode("utf-8"),
            filename=f"report_{report.report_id}.sarif",
            media_type="application/sarif+json",
        )


def _build_sarif_document(report: AnalysisReport) -> dict[str, Any]:
    """Construct the top-level SARIF JSON structure.

    Args:
        report: The analysis report.

    Returns:
        A dict conforming to SARIF v2.1.0 schema.
    """
    rules = _build_rules(report.findings)
    results = _build_results(report)

    return {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Sephela",
                        "informationUri": "https://github.com/sephela/sephela",
                        "version": report.version,
                        "rules": rules,
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "properties": {
                            "jobId": report.job_id,
                            "sampleSha256": report.sample_sha256,
                            "riskScore": report.executive_summary.risk_score,
                            "riskTier": report.executive_summary.risk_tier,
                        },
                    }
                ],
            }
        ],
    }


def _build_rules(findings: list[Finding]) -> list[dict[str, Any]]:
    """Build the SARIF ``rules`` array from unique finding types.

    Args:
        findings: All findings from the report.

    Returns:
        List of SARIF rule descriptors.
    """
    seen: dict[str, dict[str, Any]] = {}
    for f in findings:
        rule_id = f.type
        if rule_id not in seen:
            rule: dict[str, Any] = {
                "id": rule_id,
                "shortDescription": {"text": f.title},
                "properties": {},
            }
            if f.mitre_techniques:
                rule["properties"]["mitre"] = f.mitre_techniques
            if f.owasp_mobile:
                rule["properties"]["owasp"] = f.owasp_mobile
            seen[rule_id] = rule
    return list(seen.values())


def _build_results(report: AnalysisReport) -> list[dict[str, Any]]:
    """Build the SARIF ``results`` array from findings.

    Args:
        report: The analysis report.

    Returns:
        List of SARIF result objects.
    """
    results: list[dict[str, Any]] = []
    for f in report.findings:
        result: dict[str, Any] = {
            "ruleId": f.type,
            "level": _SEVERITY_TO_LEVEL.get(f.severity.value, "note"),
            "message": {"text": f.description},
            "properties": {
                "findingId": f.id,
                "confidence": f.confidence.value,
                "severity": f.severity.value,
            },
        }

        # Add physical location if evidence refs have a locator
        if f.evidence_refs:
            locations: list[dict[str, Any]] = []
            for ref in f.evidence_refs:
                loc: dict[str, Any] = {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": ref.path,
                        }
                    }
                }
                if ref.snippet:
                    loc["physicalLocation"]["region"] = {
                        "snippet": {"text": ref.snippet}
                    }
                locations.append(loc)
            result["locations"] = locations

        results.append(result)

    return results
