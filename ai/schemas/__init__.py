"""Pydantic v2 schemas for GenAI subsystem structured outputs."""

# ── Base primitives ──────────────────────────────────────────────────────────
from ai.schemas.api import APIAnalysis, APICall, DangerousAPI
from ai.schemas.base import AgentResult, Confidence, EvidenceRef, Finding, Severity
from ai.schemas.code import ClassInfo, CodeAnalysis, ControlFlowFinding, MethodInfo

# ── Domain schemas (per-agent analysis models) ───────────────────────────────
from ai.schemas.manifest import ComponentInfo, ManifestAnalysis, PermissionFinding
from ai.schemas.network import NetworkAnalysis, NetworkConnection, NetworkFinding
from ai.schemas.permission import PermissionAnalysis, PermissionRisk
from ai.schemas.report import (
    AnalysisReport,
    ComplianceMapping,
    EvidenceCatalog,
    ExecutiveSummary,
    ReportGenerationResult,
    ReportSection,
    TechnicalDetails,
)

# ── Canonical result schemas (what GraphState stores) ────────────────────────
from ai.schemas.results import (
    APIAnalysisResult,
    # Base
    BaseAnalysisResult,
    CodeAnalysisResult,
    EvidenceReference,
    ExecutiveSummarySection,
    # Per-agent results
    ManifestAnalysisResult,
    # Cross-schema types
    MitreMapping,
    MitreSectionEntry,
    NetworkAnalysisResult,
    OwaspMapping,
    OwaspSectionEntry,
    PermissionAnalysisResult,
    ReportFinding,
    # Report
    ReportResult,
    # Risk
    RiskAssessmentResult,
    RiskScoreFactor,
    TechnicalAnalysisSection,
    ThreatIntelAnalysisResult,
)
from ai.schemas.risk import RiskAnalysis, RiskBreakdown, RiskFactor, RiskTier
from ai.schemas.threat_intel import IOCMatch, MalwareFamily, ThreatIntelAnalysis

__all__ = [
    # Base
    "AgentResult",
    "EvidenceRef",
    "Finding",
    "Severity",
    "Confidence",
    # Domain
    "ManifestAnalysis",
    "ComponentInfo",
    "PermissionFinding",
    "PermissionAnalysis",
    "PermissionRisk",
    "CodeAnalysis",
    "ClassInfo",
    "MethodInfo",
    "ControlFlowFinding",
    "APIAnalysis",
    "APICall",
    "DangerousAPI",
    "NetworkAnalysis",
    "NetworkConnection",
    "NetworkFinding",
    "ThreatIntelAnalysis",
    "IOCMatch",
    "MalwareFamily",
    "RiskAnalysis",
    "RiskFactor",
    "RiskBreakdown",
    "RiskTier",
    "AnalysisReport",
    "ExecutiveSummary",
    "ReportSection",
    "TechnicalDetails",
    "EvidenceCatalog",
    "ComplianceMapping",
    "ReportGenerationResult",
    # Canonical cross-schema types
    "MitreMapping",
    "OwaspMapping",
    "EvidenceReference",
    # Result schemas
    "BaseAnalysisResult",
    "ManifestAnalysisResult",
    "PermissionAnalysisResult",
    "CodeAnalysisResult",
    "APIAnalysisResult",
    "NetworkAnalysisResult",
    "ThreatIntelAnalysisResult",
    "RiskAssessmentResult",
    "RiskScoreFactor",
    "ReportResult",
    "ReportFinding",
    "ExecutiveSummarySection",
    "TechnicalAnalysisSection",
    "MitreSectionEntry",
    "OwaspSectionEntry",
]
