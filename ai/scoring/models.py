"""Scoring-specific models — decoupled from the schema layer.

These dataclasses are used internally by the scoring engine. The engine
converts its output into the ``RiskAnalysis`` / ``RiskBreakdown`` Pydantic
models from ``ai.schemas.risk`` only at the boundary when emitting the
final result. This keeps the scoring math free of validation overhead and
allows the schemas to evolve independently.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class RiskTierEnum(str, Enum):
    """Risk tier classification."""
    benign = "benign"
    suspicious = "suspicious"
    malicious = "malicious"
    critical = "critical"


@dataclass
class DomainScore:
    """Per-domain scoring result."""
    domain: str
    weight: float
    raw_score: float          # 0-100 — max severity-weighted finding in this domain
    weighted_score: float     # raw_score × weight
    finding_count: int = 0
    evidence_refs: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    owasp_categories: list[str] = field(default_factory=list)
    description: str = ""


@dataclass
class SynergyBonus:
    """A synergy rule that fired, adding bonus points."""
    rule_id: str
    name: str
    description: str
    bonus: float              # points added to the base score
    matched_domains: list[str] = field(default_factory=list)
    matched_techniques: list[str] = field(default_factory=list)
    confidence: float = 0.80


@dataclass
class ScoringResult:
    """Complete output of the deterministic scoring engine.

    This is the internal representation. The public API converts it to the
    Pydantic ``RiskAnalysis`` model from ``ai.schemas.risk``.
    """
    base_score: float         # sum of weighted domain scores (0-100)
    synergy_bonus: float      # additional points from synergy rules
    final_score: float        # min(100, base_score + synergy_bonus)
    tier: RiskTierEnum
    confidence: float         # 0.0-1.0 — overall confidence in the score
    primary_category: str     # "banking_trojan", "spyware", etc.
    secondary_categories: list[str] = field(default_factory=list)

    domain_scores: list[DomainScore] = field(default_factory=list)
    synergy_bonuses: list[SynergyBonus] = field(default_factory=list)

    mitre_techniques: list[str] = field(default_factory=list)
    owasp_categories: list[str] = field(default_factory=list)

    key_findings: list[str] = field(default_factory=list)
    scoring_version: str = "1.0.0"
