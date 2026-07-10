"""
ai/schemas/results.py — Canonical analysis result schemas consumed by agents and the graph.

These are the top-level output types each agent writes into GraphState.agent_results.
They extend (or aggregate) the domain schemas in the individual agent schema files.

Hierarchy
---------
GraphState.agent_results["manifest_agent"] → ManifestAnalysisResult
GraphState.agent_results["permission_agent"] → PermissionAnalysisResult
... etc.
GraphState.risk_result → RiskAssessmentResult
GraphState.report → ReportResult

Every result carries the full Finding list and top-level summary counts for
easy downstream consumption without traversing nested structures.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, Field, model_validator

from ai.schemas.base import Confidence, EvidenceRef, Finding, Severity


# ---------------------------------------------------------------------------
# Cross-schema canonical types
# ---------------------------------------------------------------------------


class MitreMapping(BaseModel):
    """MITRE ATT&CK technique mapping."""

    technique_id: str = Field(..., description="ATT&CK technique ID, e.g. T1417.001")
    technique_name: str = Field(..., description="Human-readable name")
    tactic: str = Field(..., description="ATT&CK tactic, e.g. 'Collection'")
    sub_technique: Optional[str] = None
    relevance: str = Field(
        ...,
        description="Why this technique applies to the finding",
    )
    confidence: Confidence = Confidence.medium


class OwaspMapping(BaseModel):
    """OWASP Mobile Top 10 mapping."""

    category_id: str = Field(..., description="OWASP Mobile category, e.g. M1")
    category_name: str = Field(..., description="Human-readable name")
    description: str = Field(..., description="Why this category applies")


class EvidenceReference(BaseModel):
    """
    Traceable reference back to a specific field in the Evidence Envelope.

    This is a richer version of EvidenceRef from base.py — it includes
    a human-readable path and a content snippet for report rendering.
    """

    extractor: str = Field(..., description="Name of the extractor that produced the evidence")
    path: str = Field(..., description="Dot-separated path within the extractor payload")
    field_name: str = Field("", description="Specific field name")
    snippet: str = Field("", description="Verbatim excerpt from the evidence")
    envelope_version: str = "1.0"


# ---------------------------------------------------------------------------
# Base result type
# ---------------------------------------------------------------------------


class BaseAnalysisResult(BaseModel):
    """
    Base class shared by all agent analysis results.

    Contains provenance, timing, and quality fields that every agent must populate.
    """

    agent_name: str
    model_used: str
    analysis_timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    analysis_id: str = Field(default_factory=lambda: uuid4().hex)

    # Quality indicators
    confidence_overall: Confidence
    data_quality: str = Field(
        ...,
        description="Quality of the input evidence: complete | partial | minimal",
    )
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)

    # All findings (flat list for easy downstream use)
    findings: list[Finding] = Field(default_factory=list)

    # Summary counts (derived in model_post_init)
    finding_count_critical: int = 0
    finding_count_high: int = 0
    finding_count_medium: int = 0
    finding_count_low: int = 0
    finding_count_info: int = 0
    total_findings: int = 0

    def model_post_init(self, __context: Any) -> None:
        """Compute summary counts from findings list."""
        for f in self.findings:
            sev = f.severity if isinstance(f.severity, str) else f.severity.value
            if sev == "critical":
                self.finding_count_critical += 1
            elif sev == "high":
                self.finding_count_high += 1
            elif sev == "medium":
                self.finding_count_medium += 1
            elif sev == "low":
                self.finding_count_low += 1
            else:
                self.finding_count_info += 1
        self.total_findings = len(self.findings)


# ---------------------------------------------------------------------------
# Per-agent result schemas
# ---------------------------------------------------------------------------


class ManifestAnalysisResult(BaseAnalysisResult):
    """
    Output schema for ManifestAgent.

    Wraps ManifestAnalysis (domain schema) with provenance and quality metadata.
    """

    agent_name: str = "manifest_agent"

    # Core manifest facts
    package_name: str
    version_name: Optional[str] = None
    version_code: Optional[int] = None
    min_sdk: Optional[int] = None
    target_sdk: Optional[int] = None

    # Security flags
    debuggable: bool = False
    allow_backup: bool = True
    uses_cleartext_traffic: bool = False
    network_security_config_present: bool = False
    test_only: bool = False

    # Component counts
    exported_activities: int = 0
    exported_services: int = 0
    exported_receivers: int = 0
    exported_providers: int = 0

    # Permission facts
    declared_permissions: list[str] = Field(default_factory=list)
    dangerous_permissions: list[str] = Field(default_factory=list)
    permission_count: int = 0

    # Certificate flags
    debug_certificate_detected: bool = False
    certificate_sha256: Optional[str] = None

    # MITRE / OWASP aggregated across findings
    mitre_mappings: list[MitreMapping] = Field(default_factory=list)
    owasp_mappings: list[OwaspMapping] = Field(default_factory=list)
    evidence_references: list[EvidenceReference] = Field(default_factory=list)


class PermissionAnalysisResult(BaseAnalysisResult):
    """Output schema for PermissionAgent."""

    agent_name: str = "permission_agent"

    # Risk summary
    permission_risk_score: float = Field(0.0, ge=0.0, le=100.0)
    dangerous_permission_count: int = 0
    critical_permission_count: int = 0

    # Capability flags derived from permissions
    can_intercept_sms: bool = False
    can_record_audio: bool = False
    can_access_location: bool = False
    can_access_camera: bool = False
    can_read_contacts: bool = False
    can_send_sms: bool = False
    can_access_accounts: bool = False
    can_draw_overlay: bool = False
    can_use_accessibility: bool = False
    can_be_device_admin: bool = False
    can_install_packages: bool = False

    # Detailed permission entries
    permissions: list[dict[str, Any]] = Field(default_factory=list)

    mitre_mappings: list[MitreMapping] = Field(default_factory=list)
    owasp_mappings: list[OwaspMapping] = Field(default_factory=list)
    evidence_references: list[EvidenceReference] = Field(default_factory=list)


class CodeAnalysisResult(BaseAnalysisResult):
    """Output schema for CodeAgent."""

    agent_name: str = "code_agent"

    # Structural
    total_classes: int = 0
    total_methods: int = 0
    app_classes: int = 0
    app_methods: int = 0

    # Obfuscation / anti-analysis
    string_obfuscation_detected: bool = False
    class_encryption_detected: bool = False
    anti_analysis_techniques: list[str] = Field(default_factory=list)
    emulator_detection: bool = False
    root_detection: bool = False

    # Dangerous patterns
    reflection_used: bool = False
    dynamic_code_loading: bool = False
    native_libraries: list[str] = Field(default_factory=list)

    # Banking-specific
    overlay_attack_code: bool = False
    accessibility_abuse: bool = False
    sms_interception_code: bool = False
    keylogger_patterns: bool = False
    screen_recording_patterns: bool = False

    # High-value code paths
    suspicious_classes: list[str] = Field(default_factory=list)
    suspicious_methods: list[str] = Field(default_factory=list)
    crypto_usages: list[str] = Field(default_factory=list)

    mitre_mappings: list[MitreMapping] = Field(default_factory=list)
    owasp_mappings: list[OwaspMapping] = Field(default_factory=list)
    evidence_references: list[EvidenceReference] = Field(default_factory=list)


class APIAnalysisResult(BaseAnalysisResult):
    """Output schema for APIAgent."""

    agent_name: str = "api_agent"

    total_dangerous_api_calls: int = 0
    reflection_api_calls: int = 0
    dynamic_loading_calls: int = 0

    # Dangerous API categories detected
    crypto_misuse: bool = False
    network_exfil_apis: bool = False
    location_apis: bool = False
    camera_microphone_apis: bool = False
    sms_apis: bool = False
    contact_apis: bool = False
    ipc_abuse_apis: bool = False
    runtime_exec_apis: bool = False
    accessibility_apis: bool = False
    admin_apis: bool = False
    overlay_apis: bool = False

    # Detailed API calls
    api_calls: list[dict[str, Any]] = Field(default_factory=list)
    dangerous_api_categories: list[dict[str, Any]] = Field(default_factory=list)

    mitre_mappings: list[MitreMapping] = Field(default_factory=list)
    owasp_mappings: list[OwaspMapping] = Field(default_factory=list)
    evidence_references: list[EvidenceReference] = Field(default_factory=list)


class NetworkAnalysisResult(BaseAnalysisResult):
    """Output schema for NetworkAgent."""

    agent_name: str = "network_agent"

    # Network counts
    total_domains: int = 0
    total_ips: int = 0
    total_urls: int = 0
    malicious_domain_count: int = 0
    malicious_ip_count: int = 0
    suspicious_connection_count: int = 0

    # Flags
    c2_detected: bool = False
    data_exfil_detected: bool = False
    cleartext_traffic: bool = False
    pinning_bypass_detected: bool = False
    dga_detected: bool = False

    # IOCs
    domains: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)

    # Certificate
    self_signed_certs: int = 0
    expired_certs: int = 0

    mitre_mappings: list[MitreMapping] = Field(default_factory=list)
    owasp_mappings: list[OwaspMapping] = Field(default_factory=list)
    evidence_references: list[EvidenceReference] = Field(default_factory=list)


class ThreatIntelAnalysisResult(BaseAnalysisResult):
    """Output schema for ThreatIntelAgent."""

    agent_name: str = "threat_intel_agent"

    # IOC matches
    total_ioc_matches: int = 0
    malicious_hash_matches: int = 0
    malicious_domain_matches: int = 0
    malicious_ip_matches: int = 0

    # Attribution
    malware_families: list[str] = Field(default_factory=list)
    malware_family_confidence: Confidence = Confidence.low
    threat_actors: list[str] = Field(default_factory=list)
    campaigns: list[str] = Field(default_factory=list)

    # Highest-confidence classification
    primary_classification: Optional[str] = None
    classification_confidence: Confidence = Confidence.low

    # Detailed IOC records
    ioc_matches: list[dict[str, Any]] = Field(default_factory=list)

    mitre_mappings: list[MitreMapping] = Field(default_factory=list)
    owasp_mappings: list[OwaspMapping] = Field(default_factory=list)
    evidence_references: list[EvidenceReference] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Risk Assessment Result
# ---------------------------------------------------------------------------


class RiskScoreFactor(BaseModel):
    """Individual contribution to the overall risk score."""

    factor_id: str
    name: str
    weight: float = Field(..., ge=0.0, le=1.0)
    raw_score: float = Field(..., ge=0.0, le=100.0)
    weighted_score: float = Field(..., ge=0.0)
    source_agent: str
    contributing_findings: list[str] = Field(
        default_factory=list, description="Finding IDs that drove this factor"
    )
    explanation: str = ""
    mitre_techniques: list[str] = Field(default_factory=list)
    owasp_categories: list[str] = Field(default_factory=list)


class RiskAssessmentResult(BaseAnalysisResult):
    """
    Output schema for RiskAgent.

    The risk agent aggregates all previous agent outputs and computes an
    explainable, weighted risk score.
    """

    agent_name: str = "risk_agent"

    # Primary score
    score: float = Field(..., ge=0.0, le=100.0, description="Overall risk score 0–100")
    tier: str = Field(
        ...,
        description="Risk tier: benign | suspicious | malicious | critical",
    )
    confidence: float = Field(..., ge=0.0, le=1.0)

    # Breakdown
    factors: list[RiskScoreFactor] = Field(
        default_factory=list,
        description="Weighted factors contributing to the score",
    )

    # Scores by domain (for dashboard cards)
    manifest_score: float = Field(0.0, ge=0.0, le=100.0)
    permission_score: float = Field(0.0, ge=0.0, le=100.0)
    code_score: float = Field(0.0, ge=0.0, le=100.0)
    api_score: float = Field(0.0, ge=0.0, le=100.0)
    network_score: float = Field(0.0, ge=0.0, le=100.0)
    threat_intel_score: float = Field(0.0, ge=0.0, le=100.0)

    # Classification
    primary_category: str = Field(
        ...,
        description="Malware category: banking_trojan | spyware | ransomware | adware | dropper | rootkit | unknown",
    )
    secondary_categories: list[str] = Field(default_factory=list)

    # Aggregated MITRE / OWASP across all agents
    mitre_techniques: list[str] = Field(default_factory=list)
    owasp_categories: list[str] = Field(default_factory=list)

    # Narrative
    risk_narrative: str = Field(..., description="1–3 sentence plain English explanation")
    key_risk_indicators: list[str] = Field(
        default_factory=list, description="Top 5 most impactful findings in plain English"
    )

    # Actions
    recommended_actions: list[str] = Field(default_factory=list)

    mitre_mappings: list[MitreMapping] = Field(default_factory=list)
    owasp_mappings: list[OwaspMapping] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Report Result
# ---------------------------------------------------------------------------


class ReportFinding(BaseModel):
    """Normalised finding for the report (all agents collapsed into one list)."""

    id: str
    type: str
    severity: str
    confidence: str
    title: str
    description: str
    source_agent: str
    mitre_techniques: list[str] = Field(default_factory=list)
    owasp_categories: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    remediation: str = ""


class ExecutiveSummarySection(BaseModel):
    """One-page executive summary."""

    overview: str
    risk_score: float
    risk_tier: str
    primary_category: str
    key_findings: list[str] = Field(default_factory=list)
    business_impact: str
    recommended_actions: list[str] = Field(default_factory=list)
    one_page_summary: str


class TechnicalAnalysisSection(BaseModel):
    """Full technical narrative."""

    manifest_summary: str
    permission_summary: str
    code_summary: str
    api_summary: str
    network_summary: str
    threat_intel_summary: str
    risk_summary: str

    # Inline agent outputs (trimmed for readability)
    agent_findings: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)


class MitreSectionEntry(BaseModel):
    """Single entry in the MITRE ATT&CK section."""

    technique_id: str
    technique_name: str
    tactic: str
    finding_titles: list[str] = Field(default_factory=list)
    severity: str


class OwaspSectionEntry(BaseModel):
    """Single entry in the OWASP Mobile section."""

    category_id: str
    category_name: str
    finding_titles: list[str] = Field(default_factory=list)
    severity: str


class ReportResult(BaseAnalysisResult):
    """
    Complete report output from ReportAgent.

    Structured for multi-format rendering (JSON / Markdown / PDF / SARIF).
    """

    agent_name: str = "report_agent"

    # Metadata
    report_id: str = Field(default_factory=lambda: f"rpt_{uuid4().hex[:12]}")
    job_id: str
    apk_sha256: str
    classification: str = "TLP:AMBER"
    generated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    pipeline_version: str = "1.0"

    # Sections
    executive_summary: ExecutiveSummarySection
    technical_analysis: TechnicalAnalysisSection
    all_findings: list[ReportFinding] = Field(default_factory=list)

    # MITRE / OWASP index sections
    mitre_section: list[MitreSectionEntry] = Field(default_factory=list)
    owasp_section: list[OwaspSectionEntry] = Field(default_factory=list)

    # Final verdict
    verdict: str = Field(
        ...,
        description="MALICIOUS | SUSPICIOUS | BENIGN — top-level classification",
    )
    verdict_confidence: Confidence

    # All IOCs extracted during analysis
    indicators_of_compromise: list[dict[str, Any]] = Field(default_factory=list)

    # Compliance mappings
    nist_csf_functions: list[str] = Field(default_factory=list)
    iso27001_controls: list[str] = Field(default_factory=list)
    pci_dss_requirements: list[str] = Field(default_factory=list)

    mitre_mappings: list[MitreMapping] = Field(default_factory=list)
    owasp_mappings: list[OwaspMapping] = Field(default_factory=list)
    evidence_references: list[EvidenceReference] = Field(default_factory=list)
