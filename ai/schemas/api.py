"""API analysis schemas."""

from __future__ import annotations

from typing import Any, List, Optional
from pydantic import BaseModel, Field

from ai.schemas.base import Finding, Severity, Confidence, EvidenceRef


class APICall(BaseModel):
    """Single dangerous API call with context."""
    api_class: str
    api_method: str
    api_package: str
    call_sites: List[str] = Field(default_factory=list)  # method signatures
    data_flow: List[str] = Field(default_factory=list)  # tainted variable traces
    is_reflection: bool = False
    is_dynamic_loading: bool = False
    severity: Severity = Severity.medium
    confidence: Confidence = Confidence.medium
    mitre_techniques: List[str] = Field(default_factory=list)
    owasp_categories: List[str] = Field(default_factory=list)
    evidence_refs: List[EvidenceRef] = Field(default_factory=list)


class DangerousAPI(BaseModel):
    """Category of dangerous API with aggregated info."""
    category: str
    severity: Severity
    description: str
    mitre_techniques: List[str] = Field(default_factory=list)
    owasp_categories: List[str] = Field(default_factory=list)
    matched_apis: List[str] = Field(default_factory=list)
    total_call_sites: int = 0
    reflection_count: int = 0
    dynamic_loading_count: int = 0


class APIAnalysis(BaseModel):
    """Complete API analysis output."""
    api_calls: List[APICall] = Field(default_factory=list)
    dangerous_apis: List[DangerousAPI] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    
    # Summary counts
    total_dangerous_calls: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    reflection_calls: int = 0
    dynamic_loading_calls: int = 0

    def model_post_init(self, __context: Any) -> None:
        """Aggregate findings and counts."""
        self.findings.extend(self._create_findings_from_calls())
        self._update_counts()
    
    def _create_findings_from_calls(self) -> List[Finding]:
        findings = []
        for call in self.api_calls:
            findings.append(Finding(
                id=f"api_{call.api_class}_{call.api_method}",
                type="dangerous_api",
                severity=call.severity,
                confidence=call.confidence,
                title=f"Dangerous API: {call.api_class}.{call.api_method}",
                description=f"API called from {len(call.call_sites)} site(s). Reflection: {call.is_reflection}, Dynamic: {call.is_dynamic_loading}",
                evidence_refs=call.evidence_refs,
                mitre_techniques=call.mitre_techniques,
                owasp_mobile=call.owasp_categories,
            ))
        return findings
    
    def _update_counts(self):
        self.total_dangerous_calls = len(self.api_calls)
        for call in self.api_calls:
            if call.severity == Severity.critical:
                self.critical_count += 1
            elif call.severity == Severity.high:
                self.high_count += 1
            elif call.severity == Severity.medium:
                self.medium_count += 1
            elif call.severity == Severity.low:
                self.low_count += 1
            if call.is_reflection:
                self.reflection_calls += 1
            if call.is_dynamic_loading:
                self.dynamic_loading_calls += 1