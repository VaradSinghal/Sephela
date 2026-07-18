"""Decoupled Pydantic models for the Reporting Engine.

These mirror the ``ai.schemas.report`` types but are owned by this engine,
keeping the engine free of imports from the ``ai/`` package.  The orchestrator
serialises the upstream ``AnalysisReport`` to JSON and hands the dict to the
engine — these models deserialise it back with full validation.

Architecture rule (doc 11 / CONTRIBUTING.md):
    Engines depend only on ``sephela_evidence`` + ``sephela_contracts``; never
    import backend/worker/AI code.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ReportFormat(str, Enum):
    """Supported output formats."""

    json = "json"
    markdown = "markdown"
    html = "html"
    pdf = "pdf"
    sarif = "sarif"


class Severity(str, Enum):
    """Finding severity levels (mirrors ``ai.schemas.base.Severity``)."""

    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Confidence(str, Enum):
    """Finding confidence levels."""

    low = "low"
    medium = "medium"
    high = "high"
    very_high = "very_high"


class RiskTier(str, Enum):
    """Risk tier classification."""

    benign = "benign"
    suspicious = "suspicious"
    malicious = "malicious"
    critical = "critical"


# ---------------------------------------------------------------------------
# Evidence / Finding models (flat, serialisable)
# ---------------------------------------------------------------------------

class EvidenceRef(BaseModel):
    """Reference to a piece of evidence."""

    extractor: str
    path: str
    snippet: str | None = None
    envelope_version: str = "1.0"


class Finding(BaseModel):
    """A single finding from the analysis pipeline."""

    id: str
    type: str
    severity: Severity
    confidence: Confidence
    title: str
    description: str
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    owasp_mobile: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Report sub-sections
# ---------------------------------------------------------------------------

class ReportSection(BaseModel):
    """Individual report section (recursive via subsections)."""

    section_id: str
    title: str
    content: str
    order: int
    subsections: list[ReportSection] = Field(default_factory=list)
    findings_refs: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)


class ExecutiveSummary(BaseModel):
    """Executive summary for leadership / SOC leads."""

    overview: str
    risk_score: float
    risk_tier: str
    primary_category: str | None = None
    key_findings: list[str] = Field(default_factory=list)
    business_impact: str = ""
    recommended_actions: list[str] = Field(default_factory=list)
    one_page_summary: str = ""


class TechnicalDetails(BaseModel):
    """Technical analysis details across all engines."""

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
    """Compliance framework mappings (MITRE, OWASP, NIST, etc.)."""

    mitre_attack: dict[str, list[str]] = Field(default_factory=dict)
    owasp_mobile: dict[str, list[str]] = Field(default_factory=dict)
    nist_csf: dict[str, list[str]] = Field(default_factory=dict)
    iso_27001: dict[str, list[str]] = Field(default_factory=dict)
    pci_dss: dict[str, list[str]] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Top-level report
# ---------------------------------------------------------------------------

class AnalysisReport(BaseModel):
    """Complete analysis report — the input to every renderer."""

    # Metadata
    report_id: str
    job_id: str
    sample_sha256: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
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

    # Findings (denormalised from all agents for convenient iteration)
    findings: list[Finding] = Field(default_factory=list)

    # Classification
    classification: str = "TLP:AMBER"
    distribution_restrictions: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Engine output
# ---------------------------------------------------------------------------

class RenderedArtifact(BaseModel):
    """A single rendered output from the engine."""

    format: ReportFormat
    content_bytes: bytes
    filename: str
    media_type: str


class ReportingResult(BaseModel):
    """Result of a report generation run."""

    report_id: str
    artifacts: dict[str, str] = Field(default_factory=dict)  # format → filename
    generation_time_ms: int = 0
    warnings: list[str] = Field(default_factory=list)
