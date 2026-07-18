"""JSON renderer — canonical structured output.

Emits the ``AnalysisReport`` as pretty-printed, deterministic JSON.
This is the reference format; all other renderers are lossy projections.
"""

from __future__ import annotations

import json

from sephela_reporting.models import AnalysisReport, ReportFormat, RenderedArtifact
from sephela_reporting.renderers import BaseRenderer


class JsonRenderer(BaseRenderer):
    """Render to canonical JSON."""

    name = "json"

    def render(self, report: AnalysisReport) -> RenderedArtifact:
        """Serialise the report to indented, deterministic JSON.

        Args:
            report: Validated analysis report.

        Returns:
            JSON bytes with ``application/json`` media type.
        """
        payload = report.model_dump(mode="json")
        content = json.dumps(payload, indent=2, sort_keys=False, ensure_ascii=False)
        return RenderedArtifact(
            format=ReportFormat.json,
            content_bytes=content.encode("utf-8"),
            filename=f"report_{report.report_id}.json",
            media_type="application/json",
        )
