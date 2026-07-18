"""Tests for the ReportingEngine orchestrator."""

from __future__ import annotations

from typing import Any

import pytest

from sephela_reporting.engine import ReportingEngine
from sephela_reporting.models import RenderedArtifact
from sephela_reporting.renderers import RendererError


class TestEngineGenerate:
    """Tests for ``ReportingEngine.generate()``."""

    def test_default_formats_json_and_markdown(self, sample_report_data: dict[str, Any]) -> None:
        """Default formats are json and markdown."""
        engine = ReportingEngine()
        artifacts = engine.generate(sample_report_data)
        assert "json" in artifacts
        assert "markdown" in artifacts
        assert len(artifacts) == 2

    def test_explicit_formats(self, sample_report_data: dict[str, Any]) -> None:
        """Only requested formats are rendered."""
        engine = ReportingEngine()
        artifacts = engine.generate(sample_report_data, formats=["json"])
        assert "json" in artifacts
        assert "markdown" not in artifacts

    def test_all_non_pdf_formats(self, sample_report_data: dict[str, Any]) -> None:
        """JSON, Markdown, HTML, and SARIF all render successfully."""
        engine = ReportingEngine()
        artifacts = engine.generate(
            sample_report_data,
            formats=["json", "markdown", "html", "sarif"],
        )
        assert len(artifacts) == 4
        for fmt in ("json", "markdown", "html", "sarif"):
            assert fmt in artifacts
            assert isinstance(artifacts[fmt], RenderedArtifact)
            assert len(artifacts[fmt].content_bytes) > 0

    def test_unknown_format_skipped(self, sample_report_data: dict[str, Any]) -> None:
        """Unknown format names are skipped without raising."""
        engine = ReportingEngine()
        artifacts = engine.generate(sample_report_data, formats=["json", "unknown_fmt"])
        assert "json" in artifacts
        assert "unknown_fmt" not in artifacts

    def test_invalid_report_data_raises(self) -> None:
        """Malformed report data raises ValueError."""
        engine = ReportingEngine()
        with pytest.raises(Exception):  # Pydantic ValidationError
            engine.generate({"bad": "data"}, formats=["json"])

    def test_all_renderers_fail_raises(self, sample_report_data: dict[str, Any]) -> None:
        """RendererError raised when all renderers fail."""
        from sephela_reporting.renderers import BaseRenderer
        from sephela_reporting.models import AnalysisReport

        class FailRenderer(BaseRenderer):
            name = "fail"
            def render(self, report: AnalysisReport) -> RenderedArtifact:
                raise RendererError("fail", "always fails")

        engine = ReportingEngine(renderers={"fail": FailRenderer()})
        with pytest.raises(RendererError):
            engine.generate(sample_report_data, formats=["fail"])


class TestEngineGenerateWithMetadata:
    """Tests for ``ReportingEngine.generate_with_metadata()``."""

    def test_returns_reporting_result(self, sample_report_data: dict[str, Any]) -> None:
        """Returns a ReportingResult with timing and artifact info."""
        engine = ReportingEngine()
        result = engine.generate_with_metadata(sample_report_data, formats=["json"])
        assert result.report_id == "rpt_test_001"
        assert "json" in result.artifacts
        assert result.generation_time_ms >= 0

    def test_artifact_filenames(self, sample_report_data: dict[str, Any]) -> None:
        """Artifact filenames include the report ID."""
        engine = ReportingEngine()
        result = engine.generate_with_metadata(
            sample_report_data,
            formats=["json", "markdown"],
        )
        assert result.artifacts["json"].endswith(".json")
        assert result.artifacts["markdown"].endswith(".md")


class TestEdgeCases:
    """Edge case tests."""

    def test_minimal_report_no_findings(self, minimal_report_data: dict[str, Any]) -> None:
        """Report with zero findings renders cleanly."""
        engine = ReportingEngine()
        artifacts = engine.generate(minimal_report_data, formats=["json", "markdown", "sarif"])
        assert len(artifacts) == 3
        for art in artifacts.values():
            assert len(art.content_bytes) > 0

    def test_unicode_content(self, unicode_report_data: dict[str, Any]) -> None:
        """Unicode content is preserved through rendering."""
        engine = ReportingEngine()
        artifacts = engine.generate(unicode_report_data, formats=["json", "markdown"])
        json_str = artifacts["json"].content_bytes.decode("utf-8")
        assert "样本分析" in json_str
        assert "détecté" in json_str
        md_str = artifacts["markdown"].content_bytes.decode("utf-8")
        assert "Обнаружен троян" in md_str

    def test_available_formats(self) -> None:
        """Engine lists all registered formats."""
        engine = ReportingEngine()
        fmts = engine.available_formats
        assert "json" in fmts
        assert "markdown" in fmts
        assert "html" in fmts
        assert "sarif" in fmts

    def test_deterministic_json(self, sample_report_data: dict[str, Any]) -> None:
        """JSON output is deterministic across calls."""
        engine = ReportingEngine()
        a = engine.generate(sample_report_data, formats=["json"])
        b = engine.generate(sample_report_data, formats=["json"])
        assert a["json"].content_bytes == b["json"].content_bytes
