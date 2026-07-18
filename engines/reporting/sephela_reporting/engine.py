"""Reporting Engine — orchestrates format-specific renderers.

Public API::

    engine = ReportingEngine()
    artifacts = engine.generate(report_dict, formats=["json", "markdown", "sarif"])
    # artifacts: dict[str, RenderedArtifact]

The engine validates the input dict against the ``AnalysisReport`` model,
then delegates to the appropriate renderer(s).  Renderer failures are
isolated: a failing PDF renderer does not block the JSON/Markdown outputs.

Architecture contract (doc 03):
    Every engine is a pure function of its input — idempotent, cacheable
    by (APK hash + engine version).
"""

from __future__ import annotations

import time
from typing import Any

from sephela_reporting.models import AnalysisReport, ReportFormat, RenderedArtifact, ReportingResult
from sephela_reporting.renderers import BaseRenderer, RendererError
from sephela_reporting.renderers.json_renderer import JsonRenderer
from sephela_reporting.renderers.markdown import MarkdownRenderer
from sephela_reporting.renderers.html import HtmlRenderer
from sephela_reporting.renderers.pdf import PdfRenderer
from sephela_reporting.renderers.sarif import SarifRenderer


# Registry of format → renderer
_DEFAULT_RENDERERS: dict[str, BaseRenderer] = {
    "json": JsonRenderer(),
    "markdown": MarkdownRenderer(),
    "html": HtmlRenderer(),
    "pdf": PdfRenderer(),
    "sarif": SarifRenderer(),
}


class ReportingEngine:
    """Stateless reporting engine.

    Accepts a raw dict (the JSON-serialised ``AnalysisReport`` from the
    AI pipeline) and produces rendered artifacts in the requested formats.

    Args:
        renderers: Override the default renderer registry.  Useful for
            testing or plugging in custom renderers.
    """

    def __init__(
        self,
        renderers: dict[str, BaseRenderer] | None = None,
    ) -> None:
        self._renderers = renderers or dict(_DEFAULT_RENDERERS)

    @property
    def available_formats(self) -> list[str]:
        """Return list of registered format names."""
        return list(self._renderers.keys())

    def generate(
        self,
        report_data: dict[str, Any],
        formats: list[str] | None = None,
    ) -> dict[str, RenderedArtifact]:
        """Generate report artifacts in the requested formats.

        Args:
            report_data: Raw dict matching the ``AnalysisReport`` schema.
                Typically ``AnalysisReport.model_dump(mode="json")``.
            formats: List of format names to render (e.g. ``["json", "sarif"]``).
                Defaults to ``["json", "markdown"]``.

        Returns:
            A dict mapping format name → ``RenderedArtifact``.

        Raises:
            ValueError: If ``report_data`` fails validation.
            RendererError: Only if *all* requested renderers fail.
        """
        if formats is None:
            formats = ["json", "markdown"]

        # Validate input
        report = AnalysisReport.model_validate(report_data)

        artifacts: dict[str, RenderedArtifact] = {}
        warnings: list[str] = []

        for fmt in formats:
            renderer = self._renderers.get(fmt)
            if renderer is None:
                warnings.append(f"Unknown format '{fmt}'; skipped.")
                continue
            try:
                artifacts[fmt] = renderer.render(report)
            except RendererError as exc:
                warnings.append(str(exc))
            except Exception as exc:
                warnings.append(f"[{fmt}] Unexpected error: {exc}")

        if not artifacts and formats:
            raise RendererError(
                "engine",
                f"All requested renderers failed. Warnings: {warnings}",
            )

        return artifacts

    def generate_with_metadata(
        self,
        report_data: dict[str, Any],
        formats: list[str] | None = None,
    ) -> ReportingResult:
        """Generate artifacts and return engine metadata.

        This is the preferred entry point for the orchestration pipeline
        as it includes timing and warning information.

        Args:
            report_data: Raw dict matching the ``AnalysisReport`` schema.
            formats: List of format names to render.

        Returns:
            A ``ReportingResult`` with artifact filenames and metadata.
        """
        t0 = time.monotonic()

        report = AnalysisReport.model_validate(report_data)
        artifacts = self.generate(report_data, formats)

        elapsed_ms = int((time.monotonic() - t0) * 1000)

        return ReportingResult(
            report_id=report.report_id,
            artifacts={fmt: art.filename for fmt, art in artifacts.items()},
            generation_time_ms=elapsed_ms,
        )
