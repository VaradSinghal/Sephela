"""Tests for individual renderers (JSON, Markdown, HTML, SARIF)."""

from __future__ import annotations

import json
from typing import Any

import pytest

from sephela_reporting.models import AnalysisReport
from sephela_reporting.renderers.json_renderer import JsonRenderer
from sephela_reporting.renderers.markdown import MarkdownRenderer
from sephela_reporting.renderers.html import HtmlRenderer
from sephela_reporting.renderers.sarif import SarifRenderer


def _validate(data: dict[str, Any]) -> AnalysisReport:
    return AnalysisReport.model_validate(data)


# ---------------------------------------------------------------------------
# JSON Renderer
# ---------------------------------------------------------------------------

class TestJsonRenderer:
    """Tests for ``JsonRenderer``."""

    def test_produces_valid_json(self, sample_report_data: dict[str, Any]) -> None:
        """Output is valid, parseable JSON."""
        report = _validate(sample_report_data)
        artifact = JsonRenderer().render(report)
        parsed = json.loads(artifact.content_bytes)
        assert parsed["report_id"] == "rpt_test_001"
        assert parsed["executive_summary"]["risk_score"] == 92.5

    def test_media_type(self, sample_report_data: dict[str, Any]) -> None:
        """Media type is application/json."""
        report = _validate(sample_report_data)
        artifact = JsonRenderer().render(report)
        assert artifact.media_type == "application/json"

    def test_filename_contains_report_id(self, sample_report_data: dict[str, Any]) -> None:
        """Filename includes the report ID."""
        report = _validate(sample_report_data)
        artifact = JsonRenderer().render(report)
        assert "rpt_test_001" in artifact.filename
        assert artifact.filename.endswith(".json")

    def test_findings_in_output(self, sample_report_data: dict[str, Any]) -> None:
        """All findings are present in JSON output."""
        report = _validate(sample_report_data)
        artifact = JsonRenderer().render(report)
        parsed = json.loads(artifact.content_bytes)
        assert len(parsed["findings"]) == 4

    def test_unicode_preserved(self, unicode_report_data: dict[str, Any]) -> None:
        """Unicode characters survive serialisation."""
        report = _validate(unicode_report_data)
        artifact = JsonRenderer().render(report)
        text = artifact.content_bytes.decode("utf-8")
        assert "样本分析" in text
        assert "détecté" in text


# ---------------------------------------------------------------------------
# Markdown Renderer
# ---------------------------------------------------------------------------

class TestMarkdownRenderer:
    """Tests for ``MarkdownRenderer``."""

    def test_produces_markdown(self, sample_report_data: dict[str, Any]) -> None:
        """Output contains Markdown headings and tables."""
        report = _validate(sample_report_data)
        artifact = MarkdownRenderer().render(report)
        text = artifact.content_bytes.decode("utf-8")
        assert "# " in text  # at least one heading
        assert "Report ID" in text
        assert "rpt_test_001" in text

    def test_risk_score_present(self, sample_report_data: dict[str, Any]) -> None:
        """Risk score appears in the Markdown output."""
        report = _validate(sample_report_data)
        artifact = MarkdownRenderer().render(report)
        text = artifact.content_bytes.decode("utf-8")
        assert "92.5" in text
        assert "CRITICAL" in text

    def test_findings_table(self, sample_report_data: dict[str, Any]) -> None:
        """Findings are rendered in a Markdown table."""
        report = _validate(sample_report_data)
        artifact = MarkdownRenderer().render(report)
        text = artifact.content_bytes.decode("utf-8")
        assert "SMS Interception Permission" in text
        assert "C2 Communication Detected" in text

    def test_media_type(self, sample_report_data: dict[str, Any]) -> None:
        """Media type is text/markdown."""
        report = _validate(sample_report_data)
        artifact = MarkdownRenderer().render(report)
        assert artifact.media_type == "text/markdown"

    def test_minimal_report(self, minimal_report_data: dict[str, Any]) -> None:
        """Minimal report renders without errors."""
        report = _validate(minimal_report_data)
        artifact = MarkdownRenderer().render(report)
        text = artifact.content_bytes.decode("utf-8")
        assert "No findings" in text or "0" in text

    def test_ioc_table(self, sample_report_data: dict[str, Any]) -> None:
        """IOC list renders as a table."""
        report = _validate(sample_report_data)
        artifact = MarkdownRenderer().render(report)
        text = artifact.content_bytes.decode("utf-8")
        assert "evil.example.com" in text
        assert "198.51.100.42" in text


# ---------------------------------------------------------------------------
# HTML Renderer
# ---------------------------------------------------------------------------

class TestHtmlRenderer:
    """Tests for ``HtmlRenderer``."""

    def test_produces_html(self, sample_report_data: dict[str, Any]) -> None:
        """Output is a valid HTML document."""
        report = _validate(sample_report_data)
        artifact = HtmlRenderer().render(report)
        text = artifact.content_bytes.decode("utf-8")
        assert "<!DOCTYPE html>" in text
        assert "<html" in text
        assert "</html>" in text

    def test_css_embedded(self, sample_report_data: dict[str, Any]) -> None:
        """CSS is embedded in the HTML."""
        report = _validate(sample_report_data)
        artifact = HtmlRenderer().render(report)
        text = artifact.content_bytes.decode("utf-8")
        assert "--bg-primary" in text  # CSS custom property

    def test_score_card_present(self, sample_report_data: dict[str, Any]) -> None:
        """Score card section is in the HTML."""
        report = _validate(sample_report_data)
        artifact = HtmlRenderer().render(report)
        text = artifact.content_bytes.decode("utf-8")
        assert "score-card" in text
        assert "tier-critical" in text

    def test_media_type(self, sample_report_data: dict[str, Any]) -> None:
        """Media type is text/html."""
        report = _validate(sample_report_data)
        artifact = HtmlRenderer().render(report)
        assert artifact.media_type == "text/html"

    def test_render_html_string(self, sample_report_data: dict[str, Any]) -> None:
        """``render_html_string`` returns a str."""
        report = _validate(sample_report_data)
        html = HtmlRenderer().render_html_string(report)
        assert isinstance(html, str)
        assert "<!DOCTYPE html>" in html

    def test_findings_in_html(self, sample_report_data: dict[str, Any]) -> None:
        """Findings appear in the HTML table."""
        report = _validate(sample_report_data)
        artifact = HtmlRenderer().render(report)
        text = artifact.content_bytes.decode("utf-8")
        assert "SMS Interception Permission" in text
        assert "sev-critical" in text


# ---------------------------------------------------------------------------
# SARIF Renderer
# ---------------------------------------------------------------------------

class TestSarifRenderer:
    """Tests for ``SarifRenderer``."""

    def test_valid_sarif_structure(self, sample_report_data: dict[str, Any]) -> None:
        """Output matches SARIF v2.1.0 top-level structure."""
        report = _validate(sample_report_data)
        artifact = SarifRenderer().render(report)
        sarif = json.loads(artifact.content_bytes)
        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        assert len(sarif["runs"]) == 1

    def test_tool_info(self, sample_report_data: dict[str, Any]) -> None:
        """Tool driver info is populated."""
        report = _validate(sample_report_data)
        artifact = SarifRenderer().render(report)
        sarif = json.loads(artifact.content_bytes)
        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["name"] == "Sephela"
        assert len(driver["rules"]) > 0

    def test_results_count(self, sample_report_data: dict[str, Any]) -> None:
        """SARIF results match the number of findings."""
        report = _validate(sample_report_data)
        artifact = SarifRenderer().render(report)
        sarif = json.loads(artifact.content_bytes)
        results = sarif["runs"][0]["results"]
        assert len(results) == 4

    def test_severity_mapping(self, sample_report_data: dict[str, Any]) -> None:
        """Severities are mapped to SARIF levels."""
        report = _validate(sample_report_data)
        artifact = SarifRenderer().render(report)
        sarif = json.loads(artifact.content_bytes)
        results = sarif["runs"][0]["results"]
        levels = {r["level"] for r in results}
        assert "error" in levels  # critical → error
        assert "warning" in levels  # medium → warning

    def test_locations_from_evidence(self, sample_report_data: dict[str, Any]) -> None:
        """Evidence refs are mapped to SARIF locations."""
        report = _validate(sample_report_data)
        artifact = SarifRenderer().render(report)
        sarif = json.loads(artifact.content_bytes)
        results = sarif["runs"][0]["results"]
        # First finding has evidence_refs
        result_with_loc = [r for r in results if "locations" in r]
        assert len(result_with_loc) >= 1
        loc = result_with_loc[0]["locations"][0]
        assert "physicalLocation" in loc

    def test_media_type(self, sample_report_data: dict[str, Any]) -> None:
        """Media type is application/sarif+json."""
        report = _validate(sample_report_data)
        artifact = SarifRenderer().render(report)
        assert artifact.media_type == "application/sarif+json"

    def test_minimal_report_empty_results(self, minimal_report_data: dict[str, Any]) -> None:
        """Minimal report produces SARIF with zero results."""
        report = _validate(minimal_report_data)
        artifact = SarifRenderer().render(report)
        sarif = json.loads(artifact.content_bytes)
        assert len(sarif["runs"][0]["results"]) == 0

    def test_invocation_metadata(self, sample_report_data: dict[str, Any]) -> None:
        """SARIF invocation carries job metadata."""
        report = _validate(sample_report_data)
        artifact = SarifRenderer().render(report)
        sarif = json.loads(artifact.content_bytes)
        invocation = sarif["runs"][0]["invocations"][0]
        assert invocation["executionSuccessful"] is True
        assert invocation["properties"]["jobId"] == "job_abc123"
        assert invocation["properties"]["riskScore"] == 92.5

    def test_mitre_in_rules(self, sample_report_data: dict[str, Any]) -> None:
        """MITRE techniques are attached to SARIF rules."""
        report = _validate(sample_report_data)
        artifact = SarifRenderer().render(report)
        sarif = json.loads(artifact.content_bytes)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        rules_with_mitre = [r for r in rules if r.get("properties", {}).get("mitre")]
        assert len(rules_with_mitre) >= 1
