"""Schemas for Report Generation Agent output."""

from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum


class ReportFormat(str, Enum):
    """Supported report output formats."""
    json = "json"
    markdown = "markdown"
    pdf = "pdf"
    html = "html"
    sarif = "sarif"


class ReportSection(BaseModel):
    """Individual report section."""
    section_id: str
    title: str
    content: str
    order: int
    subsections: list[ReportSection] = Field(default_factory=list)
    findings_refs: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)


class ExecutiveSummary(BaseModel):
    """Executive summary for leadership."""
    overview: str
    risk_score: float
    risk_tier: str
    key_findings: list[str] = Field(default_factory=list)
    business_impact: str = ""
    recommended_actions: list[str] = Field(default_factory=list)
    one_page_summary: str = ""


class TechnicalDetails(BaseModel):
    """Technical analysis details."""
    sample_info: dict[str, Any] = Field(default_factory=dict)
    static_analysis: dict[str, Any] = Field(default_factory=dict)
    code_analysis: dict[str, Any] = Field(default_factory=dict)
    dynamic_analysis: dict[str, Any] | None = None
    network_analysis: dict[str, Any] = Field(default_factory=dict)
    threat_intel: dict[str, Any] = Field(default_factory=dict)
    ai_reasoning: dict[str, Any] = Field(default_factory=dict)


class EvidenceCatalog(BaseModel):
    """Catalog of all evidence artifacts."""
    static_evidence: list[dict[str, Any]] = Field(default_factory=list)
    dynamic_evidence: list[dict[str, Any]] = Field(default_factory=list)
    network_captures: list[dict[str, Any]] = Field(default_factory=list)
    decompiled_sources: list[dict[str, Any]] = Field(default_factory=list)
    extracted_strings: list[str] = Field(default_factory=list)
    ioc_list: list[dict[str, Any]] = Field(default_factory=list)


class ComplianceMapping(BaseModel):
    """Compliance framework mappings."""
    mitre_attack: dict[str, list[str]] = Field(default_factory=dict)
    owasp_mobile: dict[str, list[str]] = Field(default_factory=dict)
    nist_csf: dict[str, list[str]] = Field(default_factory=dict)
    iso_27001: dict[str, list[str]] = Field(default_factory=dict)
    pci_dss: dict[str, list[str]] = Field(default_factory=dict)


class AnalysisReport(BaseModel):
    """Complete analysis report."""
    # Metadata
    report_id: str
    job_id: str
    sample_sha256: str
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    generated_by: str = "Sephela AI Analysis Pipeline"
    version: str = "1.0"
    format: ReportFormat = ReportFormat.json
    
    # Core content
    executive_summary: ExecutiveSummary
    technical_details: TechnicalDetails
    evidence_catalog: EvidenceCatalog
    compliance_mapping: ComplianceMapping
    
    # Sections for rendered output
    sections: list[ReportSection] = Field(default_factory=list)
    
    # Classification
    classification: str = "TLP:AMBER"
    distribution_restrictions: list[str] = Field(default_factory=list)
    
    def get_section(self, section_id: str) -> ReportSection | None:
        """Get section by ID (recursive)."""
        for section in self.sections:
            if section.section_id == section_id:
                return section
            for sub in section.subsections:
                if sub.section_id == section_id:
                    return sub
        return None


class ReportGenerationRequest(BaseModel):
    """Request to generate a report."""
    job_id: str
    format: ReportFormat = ReportFormat.json
    include_sections: list[str] = Field(default_factory=lambda: [
        "executive_summary", "technical_details", "evidence_catalog", 
        "compliance_mapping", "recommendations"
    ])
    classification: str = "TLP:AMBER"
    custom_template: str | None = None


class ReportGenerationResult(BaseModel):
    """Result of report generation."""
    report: AnalysisReport
    artifacts: dict[str, str] = Field(default_factory=dict)  # format -> storage URI
    generation_time_ms: int
    warnings: list[str] = Field(default_factory=list)