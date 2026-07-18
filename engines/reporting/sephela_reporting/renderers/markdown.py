"""Markdown renderer — human-readable report for Git forges and terminals.

Uses Jinja2 to compile an ``AnalysisReport`` into well-structured Markdown
that renders cleanly in GitHub, GitLab, and terminal pagers.
"""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from sephela_reporting.models import AnalysisReport, ReportFormat, RenderedArtifact
from sephela_reporting.renderers import BaseRenderer, RendererError

_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"


class MarkdownRenderer(BaseRenderer):
    """Render an analysis report to Markdown via Jinja2."""

    name = "markdown"

    def __init__(self) -> None:
        self._env = Environment(
            loader=FileSystemLoader(str(_TEMPLATE_DIR)),
            autoescape=select_autoescape([]),  # no HTML escaping for Markdown
            trim_blocks=True,
            lstrip_blocks=True,
            keep_trailing_newline=True,
        )

    def render(self, report: AnalysisReport) -> RenderedArtifact:
        """Compile Jinja2 template with report data.

        Args:
            report: Validated analysis report.

        Returns:
            Markdown bytes with ``text/markdown`` media type.

        Raises:
            RendererError: If the template is missing or rendering fails.
        """
        try:
            template = self._env.get_template("report.md.j2")
        except Exception as exc:
            raise RendererError(self.name, f"Template not found: {exc}") from exc

        ctx = _build_template_context(report)
        try:
            content = template.render(**ctx)
        except Exception as exc:
            raise RendererError(self.name, f"Rendering failed: {exc}") from exc

        return RenderedArtifact(
            format=ReportFormat.markdown,
            content_bytes=content.encode("utf-8"),
            filename=f"report_{report.report_id}.md",
            media_type="text/markdown",
        )


def _build_template_context(report: AnalysisReport) -> dict[str, object]:
    """Flatten the report model into template-friendly dicts.

    Args:
        report: The validated analysis report.

    Returns:
        A dictionary suitable for Jinja2 ``template.render(**ctx)``.
    """
    exec_summary = report.executive_summary
    tech = report.technical_details
    compliance = report.compliance_mapping
    evidence = report.evidence_catalog

    # Risk tier colour mapping for badges / labels
    tier_colours = {
        "benign": "🟢",
        "suspicious": "🟡",
        "malicious": "🟠",
        "critical": "🔴",
    }

    # Severity to emoji for findings
    severity_icons = {
        "info": "ℹ️",
        "low": "🔵",
        "medium": "🟡",
        "high": "🟠",
        "critical": "🔴",
    }

    return {
        "report": report,
        "exec_summary": exec_summary,
        "tech": tech,
        "compliance": compliance,
        "evidence": evidence,
        "findings": report.findings,
        "tier_icon": tier_colours.get(exec_summary.risk_tier, "⚪"),
        "severity_icons": severity_icons,
        "sections": report.sections,
    }
