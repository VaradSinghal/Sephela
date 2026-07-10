"""Schemas for Risk Scoring Agent output."""

from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field


class RiskFactor(BaseModel):
    """Individual risk factor contribution."""
    factor_id: str
    name: str
    category: str = Field(..., pattern="^(static|dynamic|code|network|threat_intel|permissions|manifest)$")
    weight: float = Field(..., ge=0.0, le=1.0)
    raw_score: float = Field(..., ge=0.0, le=100.0)
    weighted_contribution: float = Field(..., ge=0.0)
    evidence_refs: list[str] = Field(default_factory=list)
    description: str = ""
    mitre_techniques: list[str] = Field(default_factory=list)
    owasp_categories: list[str] = Field(default_factory=list)


class RiskBreakdown(BaseModel):
    """Complete risk score breakdown."""
    factors: list[RiskFactor] = Field(default_factory=list)
    total_weight: float = Field(1.0, ge=0.0, le=1.0)
    base_score: float = Field(..., ge=0.0, le=100.0)
    adjustments: list[dict[str, Any]] = Field(default_factory=list)
    final_score: float = Field(..., ge=0.0, le=100.0)
    
    # Metadata
    scoring_version: str = "1.0"
    computed_at: str
    confidence: float = Field(..., ge=0.0, le=1.0)

    def model_post_init(self, __context: Any) -> None:
        """Validate score computation."""
        computed = sum(f.weighted_contribution for f in self.factors)
        for adj in self.adjustments:
            computed += adj.get("value", 0)
        # Allow small floating point differences
        assert abs(computed - self.final_score) < 0.01, f"Score mismatch: {computed} != {self.final_score}"


class RiskTier(str):
    """Risk tier classification."""
    benign = "benign"
    suspicious = "suspicious"
    malicious = "malicious"
    critical = "critical"

    @classmethod
    def from_score(cls, score: float) -> RiskTier:
        if score >= 90:
            return cls.critical
        elif score >= 70:
            return cls.malicious
        elif score >= 40:
            return cls.suspicious
        else:
            return cls.benign


class RiskAnalysis(BaseModel):
    """Complete risk scoring output."""
    score: float = Field(..., ge=0.0, le=100.0)
    tier: RiskTier
    confidence: float = Field(..., ge=0.0, le=1.0)
    
    breakdown: RiskBreakdown
    
    # Category scores
    static_score: float = Field(0.0, ge=0.0, le=100.0)
    dynamic_score: float = Field(0.0, ge=0.0, le=100.0)
    code_score: float = Field(0.0, ge=0.0, le=100.0)
    network_score: float = Field(0.0, ge=0.0, le=100.0)
    threat_intel_score: float = Field(0.0, ge=0.0, le=100.0)
    permission_score: float = Field(0.0, ge=0.0, le=100.0)
    manifest_score: float = Field(0.0, ge=0.0, le=100.0)
    
    # Classification
    primary_category: str | None = None  # e.g., "banking_trojan", "spyware", "adware"
    categories: list[str] = Field(default_factory=list)
    
    # MITRE / OWASP mapping
    mitre_techniques: list[str] = Field(default_factory=list)
    owasp_mobile_categories: list[str] = Field(default_factory=list)
    
    # Explainability
    key_findings: list[str] = Field(default_factory=list)
    risk_narrative: str = ""
    
    # Recommendations
    recommended_actions: list[str] = Field(default_factory=list)
    
    def model_post_init(self, __context: Any) -> None:
        """Set tier from score."""
        self.tier = RiskTier.from_score(self.score)