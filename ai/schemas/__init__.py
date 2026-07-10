"""Pydantic v2 schemas for GenAI subsystem structured outputs."""

# ── Base primitives ──────────────────────────────────────────────────────────
from ai.schemas.base import AgentResult, EvidenceRef, Finding, Severity, Confidence

# ── Domain schemas (per-agent analysis models) ───────────────────────────────
from ai.schemas.manifest import ManifestAnalysis, ComponentInfo, PermissionFinding
from ai.schemas.permission import PermissionAnalysis, PermissionRisk
from ai.schemas.code import CodeAnalysis, ClassInfo, MethodInfo, ControlFlowFinding
from ai.schemas.api import APIAnalysis, APICall, DangerousAPI
from ai.schemas.network import NetworkAnalysis, NetworkConnection, NetworkFinding
from ai.schemas.threat_intel import ThreatIntelAnalysis, IOCMatch, MalwareFamily
from ai.schemas.risk import RiskAnalysis, RiskFactor, RiskBreakdown, RiskTier
from ai.schemas.report import (
    AnalysisReport,
    ExecutiveSummary,
    ReportSection,
    TechnicalDetails,
    EvidenceCatalog,
    ComplianceMapping,
    ReportGenerationResult,
)

# ── Canonical result schemas (what GraphState stores) ────────────────────────
from ai.schemas.results import (
    # Cross-schema types
    MitreMapping,
    OwaspMapping,
    EvidenceReference,
    # Base
    BaseAnalysisResult,
    # Per-agent results
    ManifestAnalysisResult,
    PermissionAnalysisResult,
    CodeAnalysisResult,
    APIAnalysisResult,
    NetworkAnalysisResult,
    ThreatIntelAnalysisResult,
    # Risk
    RiskAssessmentResult,
    RiskScoreFactor,
    # Report
    ReportResult,
    ReportFinding,
    ExecutiveSummarySection,
    TechnicalAnalysisSection,
    MitreSectionEntry,
    OwaspSectionEntry,
)

__all__ = [
    # Base
    "AgentResult", "EvidenceRef", "Finding", "Severity", "Confidence",
    # Domain
    "ManifestAnalysis", "ComponentInfo", "PermissionFinding",
    "PermissionAnalysis", "PermissionRisk",
    "CodeAnalysis", "ClassInfo", "MethodInfo", "ControlFlowFinding",
    "APIAnalysis", "APICall", "DangerousAPI",
    "NetworkAnalysis", "NetworkConnection", "NetworkFinding",
    "ThreatIntelAnalysis", "IOCMatch", "MalwareFamily",
    "RiskAnalysis", "RiskFactor", "RiskBreakdown", "RiskTier",
    "AnalysisReport", "ExecutiveSummary", "ReportSection",
    "TechnicalDetails", "EvidenceCatalog", "ComplianceMapping",
    "ReportGenerationResult",
    # Canonical cross-schema types
    "MitreMapping", "OwaspMapping", "EvidenceReference",
    # Result schemas
    "BaseAnalysisResult",
    "ManifestAnalysisResult",
    "PermissionAnalysisResult",
    "CodeAnalysisResult",
    "APIAnalysisResult",
    "NetworkAnalysisResult",
    "ThreatIntelAnalysisResult",
    "RiskAssessmentResult", "RiskScoreFactor",
    "ReportResult", "ReportFinding",
    "ExecutiveSummarySection", "TechnicalAnalysisSection",
    "MitreSectionEntry", "OwaspSectionEntry",
]