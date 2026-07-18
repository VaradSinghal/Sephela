"""PDF renderer — banking-grade executive PDF via WeasyPrint.

Delegates to the HTML renderer for content generation, then uses WeasyPrint
to convert the styled HTML into a PDF buffer.

WeasyPrint is an **optional** dependency (``pip install sephela-reporting[pdf]``)
because it requires system-level libraries (Pango, Cairo) that may not be
available in all environments.  The renderer degrades gracefully if WeasyPrint
is missing.
"""

from __future__ import annotations

from sephela_reporting.models import AnalysisReport, ReportFormat, RenderedArtifact
from sephela_reporting.renderers import BaseRenderer, RendererError
from sephela_reporting.renderers.html import HtmlRenderer


class PdfRenderer(BaseRenderer):
    """Render an analysis report to PDF via HTML → WeasyPrint.

    Raises ``RendererError`` if WeasyPrint is not installed.
    """

    name = "pdf"

    def __init__(self) -> None:
        self._html_renderer = HtmlRenderer()

    def render(self, report: AnalysisReport) -> RenderedArtifact:
        """Convert the HTML report to a PDF buffer.

        Args:
            report: Validated analysis report.

        Returns:
            PDF bytes with ``application/pdf`` media type.

        Raises:
            RendererError: If WeasyPrint is not installed or conversion fails.
        """
        try:
            from weasyprint import HTML  # type: ignore[import-untyped]
        except ImportError as exc:
            raise RendererError(
                self.name,
                "WeasyPrint is not installed. "
                "Install with: pip install sephela-reporting[pdf]",
            ) from exc

        html_string = self._html_renderer.render_html_string(report)

        try:
            pdf_bytes: bytes = HTML(string=html_string).write_pdf()
        except Exception as exc:
            raise RendererError(self.name, f"PDF generation failed: {exc}") from exc

        return RenderedArtifact(
            format=ReportFormat.pdf,
            content_bytes=pdf_bytes,
            filename=f"report_{report.report_id}.pdf",
            media_type="application/pdf",
        )
