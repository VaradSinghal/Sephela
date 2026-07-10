"""Schemas for Manifest Agent analysis output."""

from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field

from ai.schemas.base import Finding, Severity, Confidence, EvidenceRef


class ComponentInfo(BaseModel):
    """Android component metadata."""
    name: str
    component_type: str = Field(..., pattern="^(activity|service|receiver|provider)$")
    exported: bool = False
    permission: str | None = None
    intent_filters: list[dict[str, Any]] = Field(default_factory=list)
    enabled: bool = True


class PermissionFinding(Finding):
    """Permission-specific finding."""
    permission_name: str
    protection_level: str | None = None
    is_custom: bool = False
    risk_rationale: str = ""


class ManifestAnalysis(BaseModel):
    """Complete manifest analysis output."""
    package_name: str
    version_name: str | None = None
    version_code: int | None = None
    min_sdk: int | None = None
    target_sdk: int | None = None
    max_sdk: int | None = None
    
    permissions: list[PermissionFinding] = Field(default_factory=list)
    components: list[ComponentInfo] = Field(default_factory=list)
    
    # Security-relevant manifest attributes
    debuggable: bool = False
    allow_backup: bool = True
    uses_cleartext_traffic: bool = False
    network_security_config: str | None = None
    
    # Certificates
    certificates: list[dict[str, Any]] = Field(default_factory=list)
    
    # Derived risk indicators
    exported_component_count: int = 0
    dangerous_permission_count: int = 0
    custom_permission_count: int = 0
    
    # Findings summary
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    info_findings: int = 0

    def model_post_init(self, __context: Any) -> None:
        """Compute derived fields."""
        self.exported_component_count = sum(1 for c in self.components if c.exported)
        self.dangerous_permission_count = sum(1 for p in self.permissions if p.severity in (Severity.high, Severity.critical))
        self.custom_permission_count = sum(1 for p in self.permissions if p.is_custom)
        
        for p in self.permissions:
            if p.severity == Severity.critical:
                self.critical_findings += 1
            elif p.severity == Severity.high:
                self.high_findings += 1
            elif p.severity == Severity.medium:
                self.medium_findings += 1
            elif p.severity == Severity.low:
                self.low_findings += 1
            else:
                self.info_findings += 1