"""Schemas for Permission Agent analysis output."""

from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field

from ai.schemas.base import Finding, Severity, Confidence, EvidenceRef


class PermissionRisk(BaseModel):
    """Risk assessment for a single permission."""
    permission: str
    protection_level: str
    risk_score: float = Field(..., ge=0.0, le=1.0)
    severity: Severity
    confidence: Confidence
    rationale: str
    mitre_techniques: list[str] = Field(default_factory=list)
    owasp_categories: list[str] = Field(default_factory=list)
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)
    
    # Context
    is_runtime_requested: bool = False
    is_used_by_component: list[str] = Field(default_factory=list)
    related_permissions: list[str] = Field(default_factory=list)


class PermissionGroupRisk(BaseModel):
    """Risk assessment for a permission group (e.g., SMS, Location)."""
    group_name: str
    permissions: list[PermissionRisk]
    aggregate_risk: float = Field(..., ge=0.0, le=1.0)
    severity: Severity
    capabilities_enabled: list[str] = Field(default_factory=list)


class PermissionAnalysis(BaseModel):
    """Complete permission analysis output."""
    total_permissions: int = 0
    dangerous_permissions: list[PermissionRisk] = Field(default_factory=list)
    signature_permissions: list[PermissionRisk] = Field(default_factory=list)
    custom_permissions: list[PermissionRisk] = Field(default_factory=list)
    normal_permissions: list[PermissionRisk] = Field(default_factory=list)
    
    # Grouped risk
    permission_groups: list[PermissionGroupRisk] = Field(default_factory=list)
    
    # Banking-specific
    banking_relevant_permissions: list[PermissionRisk] = Field(default_factory=list)
    financial_risk_score: float = Field(0.0, ge=0.0, le=1.0)
    
    # Findings
    findings: list[Finding] = Field(default_factory=list)
    
    # Summary counts
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0

    def model_post_init(self, __context: Any) -> None:
        """Compute summary counts."""
        all_risks = (
            self.dangerous_permissions + self.signature_permissions + 
            self.custom_permissions + self.normal_permissions
        )
        for risk in all_risks:
            if risk.severity == Severity.critical:
                self.critical_count += 1
            elif risk.severity == Severity.high:
                self.high_count += 1
            elif risk.severity == Severity.medium:
                self.medium_count += 1
            elif risk.severity == Severity.low:
                self.low_count += 1
        
        self.total_permissions = len(all_risks)