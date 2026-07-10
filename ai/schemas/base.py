"""Base schemas for GenAI agent outputs."""

from __future__ import annotations

from enum import Enum
from typing import Any, Generic, TypeVar
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    """Finding severity levels aligned with CVSS/OWASP."""
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

    @property
def weight(self) -> float:
        """Numeric weight for risk scoring."""
        return {
            Severity.info: 0.1,
            Severity.low: 0.25,
            Severity.medium: 0.5,
            Severity.high: 0.75,
            Severity.critical: 1.0,
        }[self]


class Confidence(str, Enum):
    """Confidence levels for findings."""
    low = "low"
    medium = "medium"
    high = "high"
    very_high = "very_high"

    @property
def score(self) -> float:
        return {
            Confidence.low: 0.3,
            Confidence.medium: 0.6,
            Confidence.high: 0.85,
            Confidence.very_high: 0.95,
        }[self]


class EvidenceRef(BaseModel):
    """Reference to evidence in the Evidence Envelope."""
    extractor: str = Field(..., description="Name of the extractor that produced this evidence")
    path: str = Field(..., description="JSON path within the extractor's evidence")
    snippet: str | None = Field(None, description="Relevant excerpt for human review")
    envelope_version: str = Field(default="1.0")


class Finding(BaseModel):
    """Base finding structure with provenance."""
    id: str = Field(..., description="Unique finding identifier")
    type: str = Field(..., description="Finding category (e.g., permission, api, network)")
    severity: Severity
    confidence: Confidence
    title: str = Field(..., max_length=200)
    description: str = Field(..., max_length=2000)
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list, description="MITRE ATT&CK technique IDs")
    owasp_mobile: list[str] = Field(default_factory=list, description="OWASP Mobile Top 10 categories")
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("id", mode="before")
    @classmethod
def _gen_id(cls, v: str | None) -> str:
        return v or f"finding_{uuid4().hex[:12]}"


T = TypeVar("T")


class AgentResult(BaseModel, Generic[T]):
    """Standardized result from any agent."""
    agent_name: str
    success: bool
    findings: list[Finding] = Field(default_factory=list)
    analysis: T | None = None
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    processing_time_ms: int = 0
    tokens_used: int = 0
    model_used: str | None = None

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def add_error(self, error: str) -> None:
        self.success = False
        self.errors.append(error)

    def add_warning(self, warning: str) -> None:
        self.warnings.append(warning)