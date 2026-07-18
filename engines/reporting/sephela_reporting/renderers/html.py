"""HTML renderer — styled browser-ready report.

Compiles an ``AnalysisReport`` into a standalone HTML document via Jinja2
with embedded CSS.  The HTML output is also the intermediate step for the
PDF renderer.
"""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from sephela_reporting.models import AnalysisReport, ReportFormat, RenderedArtifact
from sephela_reporting.renderers import BaseRenderer, RendererError

_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"


class HtmlRenderer(BaseRenderer):
    """Render an analysis report to styled HTML."""

    name = "html"

    def __init__(self) -> None:
        self._env = Environment(
            loader=FileSystemLoader(str(_TEMPLATE_DIR)),
            autoescape=select_autoescape(["html"]),
            trim_blocks=True,
            lstrip_blocks=True,
            keep_trailing_newline=True,
        )

    def render(self, report: AnalysisReport) -> RenderedArtifact:
        """Compile the HTML Jinja2 template with report data.

        Args:
            report: Validated analysis report.

        Returns:
            HTML bytes with ``text/html`` media type.

        Raises:
            RendererError: If the template is missing or rendering fails.
        """
        try:
            template = self._env.get_template("report.html.j2")
        except Exception as exc:
            raise RendererError(self.name, f"Template not found: {exc}") from exc

        ctx = _build_html_context(report)
        try:
            content = template.render(**ctx)
        except Exception as exc:
            raise RendererError(self.name, f"Rendering failed: {exc}") from exc

        return RenderedArtifact(
            format=ReportFormat.html,
            content_bytes=content.encode("utf-8"),
            filename=f"report_{report.report_id}.html",
            media_type="text/html",
        )

    def render_html_string(self, report: AnalysisReport) -> str:
        """Return the rendered HTML as a string (used by the PDF renderer).

        Args:
            report: Validated analysis report.

        Returns:
            The HTML content as a string.
        """
        artifact = self.render(report)
        return artifact.content_bytes.decode("utf-8")


def _build_html_context(report: AnalysisReport) -> dict[str, object]:
    """Build Jinja2 template context for HTML rendering.

    Args:
        report: The validated analysis report.

    Returns:
        A dictionary suitable for Jinja2 ``template.render(**ctx)``.
    """
    exec_summary = report.executive_summary
    tech = report.technical_details
    compliance = report.compliance_mapping
    evidence = report.evidence_catalog

    tier_classes = {
        "benign": "tier-benign",
        "suspicious": "tier-suspicious",
        "malicious": "tier-malicious",
        "critical": "tier-critical",
    }

    severity_classes = {
        "info": "sev-info",
        "low": "sev-low",
        "medium": "sev-medium",
        "high": "sev-high",
        "critical": "sev-critical",
    }

    # Read embedded CSS
    css_path = _TEMPLATE_DIR / "styles.css"
    try:
        css_content = css_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        css_content = ""

    return {
        "report": report,
        "exec_summary": exec_summary,
        "tech": tech,
        "compliance": compliance,
        "evidence": evidence,
        "findings": report.findings,
        "tier_class": tier_classes.get(exec_summary.risk_tier, "tier-unknown"),
        "severity_classes": severity_classes,
        "sections": report.sections,
        "css": css_content,
    }
