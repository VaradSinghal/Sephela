"""Risk Scoring Engine — deterministic, explainable APK threat scoring.

This is the Phase 8 core (``ai/scoring/`` per 02-services.md §8). It
computes a reproducible 0-100 risk score from all upstream findings with
full breakdown, synergy amplification, MITRE/OWASP mapping, and malware
category classification.

Architecture contract:
- **No LLM call in the scoring math** — everything is pure arithmetic.
- Input: a list of ``Finding`` objects (from Phase 7 agents) + optional
  agent outputs dict for threat-intel metadata.
- Output: a ``ScoringResult`` dataclass with full explainability.

The ``RiskAgent`` (``ai/agents/risk.py``) wraps this engine: it calls
``score()`` to get the deterministic baseline, then optionally asks the
LLM to narrate/contextualize the result.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from ai.scoring.categorizer import classify
from ai.scoring.constants import (
    CONFIDENCE_MULTIPLIERS,
    DOMAIN_WEIGHTS,
    FINDING_TYPE_TO_DOMAIN,
    SEVERITY_SCORES,
    TIER_THRESHOLDS,
)
from ai.scoring.models import (
    DomainScore,
    RiskTierEnum,
    ScoringResult,
    SynergyBonus,
)
from ai.scoring.synergy import evaluate_synergy


class RiskScoringEngine:
    """Deterministic risk scoring engine.

    Usage::

        from ai.scoring import RiskScoringEngine

        engine = RiskScoringEngine()
        result = engine.score(findings, agent_outputs)
        print(result.final_score, result.tier, result.primary_category)
    """

    def __init__(
        self,
        *,
        domain_weights: dict[str, float] | None = None,
        scoring_version: str = "1.0.0",
    ) -> None:
        self.weights = domain_weights or dict(DOMAIN_WEIGHTS)
        self.scoring_version = scoring_version
        self._validate_weights()

    def _validate_weights(self) -> None:
        """Ensure weights sum to ~1.0 (tolerance for floating-point)."""
        total = sum(self.weights.values())
        if abs(total - 1.0) > 0.01:
            raise ValueError(
                f"Domain weights must sum to 1.0, got {total:.4f}. "
                f"Weights: {self.weights}"
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def score(
        self,
        findings: list[Any],
        agent_outputs: dict[str, Any] | None = None,
        permissions: list[str] | None = None,
    ) -> ScoringResult:
        """Compute the deterministic risk score.

        Args:
            findings: List of Finding-like objects. Each must have at least
                ``type``, ``severity``, and ``confidence`` attributes or
                dict keys. May also have ``mitre_techniques``,
                ``owasp_mobile``, ``id``, ``title``.
            agent_outputs: Optional dict of agent name → output dict.
                Used for threat-intel family matching in the categorizer.
            permissions: Optional list of Android permission strings.
                Used for permission-combo category hints.

        Returns:
            A fully populated ``ScoringResult``.
        """
        # Step 1: Normalize findings into a uniform format
        normalized = [self._normalize_finding(f) for f in findings]

        # Step 2: Group findings by domain
        domain_findings = self._group_by_domain(normalized)

        # Step 3: Compute per-domain scores
        domain_scores = self._compute_domain_scores(domain_findings)

        # Step 4: Compute base score (sum of weighted domain scores)
        base_score = sum(ds.weighted_score for ds in domain_scores)

        # Step 5: Evaluate synergy rules
        active_domains = {ds.domain for ds in domain_scores if ds.finding_count > 0}
        active_types = {f["type"] for f in normalized}
        active_mitre: set[str] = set()
        for f in normalized:
            active_mitre.update(f.get("mitre_techniques", []))

        synergy_results = evaluate_synergy(active_domains, active_types, active_mitre)
        synergy_bonuses: list[SynergyBonus] = []
        total_synergy = 0.0
        for rule, matched in synergy_results:
            if matched:
                synergy_bonuses.append(
                    SynergyBonus(
                        rule_id=rule.rule_id,
                        name=rule.name,
                        description=rule.description,
                        bonus=rule.bonus,
                        matched_domains=sorted(
                            s.split(":")[1]
                            for s in rule.required_signals
                            if s.startswith("domain:")
                        ),
                        matched_techniques=sorted(
                            s.split(":")[1]
                            for s in rule.required_signals
                            if s.startswith("mitre:")
                        ),
                        confidence=rule.confidence,
                    )
                )
                total_synergy += rule.bonus

        # Step 6: Final score = base + synergy, capped at 100
        final_score = min(100.0, base_score + total_synergy)

        # Step 7: Determine tier
        tier = self._tier_from_score(final_score)

        # Step 8: Compute overall confidence
        confidence = self._compute_confidence(normalized, domain_scores, synergy_bonuses)

        # Step 9: Classify malware category
        all_types = [f["type"] for f in normalized]
        all_mitre: list[str] = []
        for f in normalized:
            all_mitre.extend(f.get("mitre_techniques", []))
        primary_cat, secondary_cats = classify(
            all_types, all_mitre, agent_outputs, permissions
        )

        # Step 10: Collect all MITRE/OWASP mappings
        all_owasp: set[str] = set()
        for f in normalized:
            all_owasp.update(f.get("owasp_mobile", []))
        for ds in domain_scores:
            all_owasp.update(ds.owasp_categories)

        # Step 11: Extract key findings (top severity)
        key_findings = self._extract_key_findings(normalized)

        return ScoringResult(
            base_score=round(base_score, 2),
            synergy_bonus=round(total_synergy, 2),
            final_score=round(final_score, 2),
            tier=tier,
            confidence=round(confidence, 3),
            primary_category=primary_cat,
            secondary_categories=secondary_cats,
            domain_scores=domain_scores,
            synergy_bonuses=synergy_bonuses,
            mitre_techniques=sorted(set(all_mitre)),
            owasp_categories=sorted(all_owasp),
            key_findings=key_findings,
            scoring_version=self.scoring_version,
        )

    # ------------------------------------------------------------------
    # Internal methods
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_finding(f: Any) -> dict[str, Any]:
        """Normalize a Finding object or dict into a uniform dict."""
        if isinstance(f, dict):
            return {
                "id": f.get("id", ""),
                "type": f.get("type", ""),
                "severity": _str_val(f.get("severity", "info")),
                "confidence": _str_val(f.get("confidence", "medium")),
                "title": f.get("title", ""),
                "description": f.get("description", ""),
                "mitre_techniques": f.get("mitre_techniques", []),
                "owasp_mobile": f.get("owasp_mobile", []),
                "evidence_refs": f.get("evidence_refs", []),
            }
        # Pydantic model or dataclass with attributes
        return {
            "id": getattr(f, "id", ""),
            "type": _str_val(getattr(f, "type", "")),
            "severity": _str_val(getattr(f, "severity", "info")),
            "confidence": _str_val(getattr(f, "confidence", "medium")),
            "title": getattr(f, "title", ""),
            "description": getattr(f, "description", ""),
            "mitre_techniques": getattr(f, "mitre_techniques", []),
            "owasp_mobile": getattr(f, "owasp_mobile", []),
            "evidence_refs": getattr(f, "evidence_refs", []),
        }

    def _group_by_domain(
        self, findings: list[dict[str, Any]]
    ) -> dict[str, list[dict[str, Any]]]:
        """Group normalized findings by scoring domain."""
        groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for f in findings:
            domain = FINDING_TYPE_TO_DOMAIN.get(f["type"], "code")
            groups[domain].append(f)
        return dict(groups)

    def _compute_domain_scores(
        self, domain_findings: dict[str, list[dict[str, Any]]]
    ) -> list[DomainScore]:
        """Compute a DomainScore for every domain (including empty ones)."""
        scores: list[DomainScore] = []
        for domain, weight in self.weights.items():
            findings = domain_findings.get(domain, [])
            if not findings:
                scores.append(
                    DomainScore(
                        domain=domain,
                        weight=weight,
                        raw_score=0.0,
                        weighted_score=0.0,
                        finding_count=0,
                        description=f"No findings in {domain}",
                    )
                )
                continue

            # Compute individual finding scores: severity × confidence
            finding_scores: list[float] = []
            mitre: set[str] = set()
            owasp: set[str] = set()
            evidence: list[str] = []

            for f in findings:
                sev_score = SEVERITY_SCORES.get(f["severity"], 10.0)
                conf_mult = CONFIDENCE_MULTIPLIERS.get(f["confidence"], 0.5)
                finding_scores.append(sev_score * conf_mult)
                mitre.update(f.get("mitre_techniques", []))
                owasp.update(f.get("owasp_mobile", []))
                if f.get("id"):
                    evidence.append(f["id"])

            # Domain raw score = max finding score in this domain.
            # We use max (not average) because one critical finding in a
            # domain is more significant than many info findings.
            raw = max(finding_scores) if finding_scores else 0.0
            weighted = raw * weight

            scores.append(
                DomainScore(
                    domain=domain,
                    weight=weight,
                    raw_score=round(raw, 2),
                    weighted_score=round(weighted, 2),
                    finding_count=len(findings),
                    evidence_refs=evidence[:50],  # cap
                    mitre_techniques=sorted(mitre),
                    owasp_categories=sorted(owasp),
                    description=(
                        f"{len(findings)} finding(s), max severity-weighted "
                        f"score {raw:.1f}"
                    ),
                )
            )
        return scores

    @staticmethod
    def _tier_from_score(score: float) -> RiskTierEnum:
        """Map a 0-100 score to a risk tier."""
        for threshold, tier_name in TIER_THRESHOLDS:
            if score >= threshold:
                return RiskTierEnum(tier_name)
        return RiskTierEnum.benign

    @staticmethod
    def _compute_confidence(
        findings: list[dict[str, Any]],
        domain_scores: list[DomainScore],
        synergy_bonuses: list[SynergyBonus],
    ) -> float:
        """Compute an overall confidence score for the assessment.

        Confidence increases with:
        - More high/critical severity findings
        - More domains having findings (broader evidence base)
        - Synergy rules firing (compound patterns are more reliable)
        """
        if not findings:
            return 0.5  # no data → moderate confidence

        # Base confidence from finding count and severity
        high_sev_count = sum(
            1 for f in findings
            if f["severity"] in ("high", "critical")
        )
        base = min(1.0, 0.40 + high_sev_count * 0.08)

        # Domain coverage bonus: more domains with findings = more confident
        active_domains = sum(1 for ds in domain_scores if ds.finding_count > 0)
        total_domains = len(domain_scores)
        if total_domains > 0:
            coverage = active_domains / total_domains
            base += coverage * 0.15

        # Synergy bonus: fired synergy rules increase confidence
        if synergy_bonuses:
            synergy_conf = max(sb.confidence for sb in synergy_bonuses)
            base += synergy_conf * 0.10

        return min(1.0, base)

    @staticmethod
    def _extract_key_findings(findings: list[dict[str, Any]]) -> list[str]:
        """Extract the top findings by severity for the summary."""
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            findings,
            key=lambda f: severity_order.get(f["severity"], 5),
        )
        key: list[str] = []
        for f in sorted_findings[:10]:
            title = f.get("title") or f.get("type", "unknown")
            sev = f["severity"].upper()
            key.append(f"[{sev}] {title}")
        return key


def _str_val(v: Any) -> str:
    """Extract string value from an enum or raw string."""
    if hasattr(v, "value"):
        return v.value
    return str(v) if v else ""
