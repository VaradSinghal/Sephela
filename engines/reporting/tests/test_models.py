"""Tests for the decoupled Pydantic models."""

from __future__ import annotations

from typing import Any

import pytest

from sephela_reporting.models import (
    AnalysisReport,
    Confidence,
    EvidenceCatalog,
    EvidenceRef,
    ExecutiveSummary,
    Finding,
    ReportFormat,
    ReportSection,
    RenderedArtifact,
    ReportingResult,
    RiskTier,
    Severity,
    TechnicalDetails,
    ComplianceMapping,
)


class TestEnums:
    """Tests for enum types."""

    def test_severity_values(self) -> None:
        assert Severity.info.value == "info"
        assert Severity.critical.value == "critical"

    def test_confidence_values(self) -> None:
        assert Confidence.low.value == "low"
        assert Confidence.very_high.value == "very_high"

    def test_risk_tier_values(self) -> None:
        assert RiskTier.benign.value == "benign"
        assert RiskTier.critical.value == "critical"

    def test_report_format_values(self) -> None:
        assert ReportFormat.json.value == "json"
        assert ReportFormat.sarif.value == "sarif"
        assert ReportFormat.pdf.value == "pdf"


class TestFinding:
    """Tests for the Finding model."""

    def test_finding_creation(self) -> None:
        f = Finding(
            id="test_001",
            type="permission_risk",
            severity=Severity.high,
            confidence=Confidence.high,
            title="Test Finding",
            description="A test finding.",
        )
        assert f.id == "test_001"
        assert f.severity == Severity.high
        assert f.evidence_refs == []
        assert f.mitre_techniques == []

    def test_finding_with_evidence_refs(self) -> None:
        ref = EvidenceRef(extractor="manifest", path="permissions[0]", snippet="READ_SMS")
        f = Finding(
            id="test_002",
            type="api",
            severity=Severity.medium,
            confidence=Confidence.medium,
            title="API Finding",
            description="Test.",
            evidence_refs=[ref],
            mitre_techniques=["T1636"],
        )
        assert len(f.evidence_refs) == 1
        assert f.evidence_refs[0].snippet == "READ_SMS"
        assert "T1636" in f.mitre_techniques


class TestAnalysisReport:
    """Tests for the AnalysisReport model."""

    def test_report_from_dict(self, sample_report_data: dict[str, Any]) -> None:
        report = AnalysisReport.model_validate(sample_report_data)
        assert report.report_id == "rpt_test_001"
        assert report.executive_summary.risk_score == 92.5
        assert len(report.findings) == 4

    def test_report_roundtrip(self, sample_report_data: dict[str, Any]) -> None:
        """Model validates, dumps to JSON, and re-validates identically."""
        report = AnalysisReport.model_validate(sample_report_data)
        dumped = report.model_dump(mode="json")
        report2 = AnalysisReport.model_validate(dumped)
        assert report.report_id == report2.report_id
        assert len(report.findings) == len(report2.findings)

    def test_minimal_report(self, minimal_report_data: dict[str, Any]) -> None:
        report = AnalysisReport.model_validate(minimal_report_data)
        assert report.executive_summary.risk_tier == "benign"
        assert len(report.findings) == 0


class TestReportingResult:
    """Tests for the engine output model."""

    def test_result_creation(self) -> None:
        result = ReportingResult(
            report_id="rpt_001",
            artifacts={"json": "report.json"},
            generation_time_ms=42,
        )
        assert result.report_id == "rpt_001"
        assert result.generation_time_ms == 42

    def test_result_warnings(self) -> None:
        result = ReportingResult(
            report_id="rpt_001",
            warnings=["PDF renderer unavailable"],
        )
        assert len(result.warnings) == 1
