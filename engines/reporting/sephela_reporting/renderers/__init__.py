"""Abstract base renderer — Strategy pattern for output formats.

Every concrete renderer (JSON, Markdown, HTML, PDF, SARIF) implements this
interface.  The engine iterates over the requested formats and delegates to
the appropriate renderer.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from sephela_reporting.models import AnalysisReport, RenderedArtifact


class BaseRenderer(ABC):
    """Abstract renderer for a single output format.

    Attributes:
        name: Human-readable renderer name (used in logs/warnings).
    """

    name: str = "base"

    @abstractmethod
    def render(self, report: AnalysisReport) -> RenderedArtifact:
        """Render the report into its target format.

        Args:
            report: Validated analysis report data.

        Returns:
            A ``RenderedArtifact`` containing the bytes, filename, and
            media type.

        Raises:
            RendererError: If rendering fails for any reason.
        """


class RendererError(Exception):
    """Raised when a renderer cannot produce output."""

    def __init__(self, renderer: str, message: str) -> None:
        self.renderer = renderer
        super().__init__(f"[{renderer}] {message}")
