"""Unit tests for the Risk Scoring Engine core logic."""

from __future__ import annotations

import pytest

from ai.scoring.engine import RiskScoringEngine
from ai.scoring.models import RiskTierEnum


def _finding(
    ftype: str = "api_usage",
    severity: str = "medium",
    confidence: str = "high",
    mitre: list[str] | None = None,
    owasp: list[str] | None = None,
    title: str = "Test finding",
) -> dict:
    """Helper to create a minimal finding dict."""
    return {
        "id": f"test-{ftype}-{severity}",
        "type": ftype,
        "severity": severity,
        "confidence": confidence,
        "title": title,
        "description": f"Test {ftype} finding",
        "mitre_techniques": mitre or [],
        "owasp_mobile": owasp or [],
    }


class TestEngineBasics:
    """Test the fundamental scoring mechanics."""

    def test_empty_findings_produce_benign(self) -> None:
        """No findings → 0 score, benign tier."""
        engine = RiskScoringEngine()
        result = engine.score([])
        assert result.final_score == 0.0
        assert result.tier == RiskTierEnum.benign
        assert result.primary_category == "unknown"

    def test_single_info_finding(self) -> None:
        """A single info finding with medium confidence produces a low score."""
        engine = RiskScoringEngine()
        result = engine.score([_finding(severity="info", confidence="medium")])
        # info=10 × medium=0.60 = 6.0 raw, ×0.15 (api weight) = 0.90
        assert result.final_score < 10.0
        assert result.tier == RiskTierEnum.benign

    def test_single_critical_finding(self) -> None:
        """A single critical finding with very_high confidence."""
        engine = RiskScoringEngine()
        result = engine.score([
            _finding(severity="critical", confidence="very_high"),
        ])
        # critical=100 × very_high=1.0 = 100 raw, ×0.15 (api weight) = 15.0
        assert result.final_score == 15.0
        assert result.tier == RiskTierEnum.benign  # still below 40

    def test_domain_weights_sum_to_one(self) -> None:
        """Default domain weights must sum to 1.0."""
        engine = RiskScoringEngine()
        total = sum(engine.weights.values())
        assert abs(total - 1.0) < 0.001

    def test_custom_weights_rejected_if_wrong_sum(self) -> None:
        """Custom weights that don't sum to 1.0 are rejected."""
        with pytest.raises(ValueError, match="must sum to 1.0"):
            RiskScoringEngine(domain_weights={"code": 0.5, "api": 0.3})

    def test_max_score_capped_at_100(self) -> None:
        """Score never exceeds 100 even with many critical findings + synergy."""
        engine = RiskScoringEngine()
        findings = [
            _finding("control_flow", "critical", "very_high", mitre=["T1417.001"]),
            _finding("api_usage", "critical", "very_high", mitre=["T1417.002"]),
            _finding("permission_risk", "critical", "very_high", mitre=["T1636.004"]),
            _finding("c2", "critical", "very_high", mitre=["T1626"]),
            _finding("ioc_match", "critical", "very_high"),
            _finding("exported_component", "critical", "very_high"),
            _finding("obfuscation", "critical", "very_high", mitre=["T1027"]),
        ]
        result = engine.score(findings)
        assert result.final_score <= 100.0


class TestDomainScoring:
    """Test per-domain scoring logic."""

    def test_findings_grouped_correctly(self) -> None:
        """Different finding types route to the correct domains."""
        engine = RiskScoringEngine()
        result = engine.score([
            _finding("debuggable", "medium", "high"),        # manifest
            _finding("permission_risk", "high", "high"),     # permissions
            _finding("control_flow", "critical", "high"),    # code
            _finding("api_usage", "high", "medium"),         # api
            _finding("c2", "critical", "very_high"),         # network
            _finding("ioc_match", "high", "high"),           # threat_intel
        ])
        domain_names = {ds.domain for ds in result.domain_scores if ds.finding_count > 0}
        assert {"manifest", "permissions", "code", "api", "network", "threat_intel"}.issubset(domain_names)

    def test_max_scoring_within_domain(self) -> None:
        """Domain score uses max finding, not average."""
        engine = RiskScoringEngine()
        # Two api findings: info and critical
        result = engine.score([
            _finding("api_usage", "info", "low"),       # 10 × 0.30 = 3.0
            _finding("api_usage", "critical", "high"),  # 100 × 0.85 = 85.0
        ])
        api_domain = next(ds for ds in result.domain_scores if ds.domain == "api")
        assert api_domain.raw_score == 85.0  # max, not average

    def test_empty_domain_gets_zero(self) -> None:
        """Domains with no findings get raw_score=0."""
        engine = RiskScoringEngine()
        result = engine.score([_finding("api_usage", "medium", "high")])
        manifest_domain = next(ds for ds in result.domain_scores if ds.domain == "manifest")
        assert manifest_domain.raw_score == 0.0
        assert manifest_domain.finding_count == 0


class TestTierClassification:
    """Test risk tier thresholds."""

    def test_benign_tier(self) -> None:
        engine = RiskScoringEngine()
        result = engine.score([_finding("api_usage", "info", "low")])
        assert result.tier == RiskTierEnum.benign

    def test_suspicious_tier(self) -> None:
        """Score ≥ 40 but < 70 → suspicious."""
        engine = RiskScoringEngine()
        # Build up enough findings across domains to hit ~50
        findings = [
            _finding("control_flow", "critical", "very_high"),  # code: 100 × 0.20 = 20
            _finding("api_usage", "critical", "very_high"),     # api: 100 × 0.15 = 15
            _finding("c2", "high", "high"),                      # network: 63.75 × 0.15 = 9.56
        ]
        result = engine.score(findings)
        assert 40.0 <= result.final_score < 70.0
        assert result.tier == RiskTierEnum.suspicious

    def test_critical_tier(self) -> None:
        """Score ≥ 90 → critical."""
        engine = RiskScoringEngine()
        # Max out all domains
        findings = [
            _finding("debuggable", "critical", "very_high"),
            _finding("permission_risk", "critical", "very_high"),
            _finding("control_flow", "critical", "very_high"),
            _finding("api_usage", "critical", "very_high"),
            _finding("c2", "critical", "very_high"),
            _finding("ioc_match", "critical", "very_high"),
        ]
        result = engine.score(findings)
        assert result.final_score >= 90.0
        assert result.tier == RiskTierEnum.critical


class TestConfidence:
    """Test confidence computation."""

    def test_no_findings_moderate_confidence(self) -> None:
        engine = RiskScoringEngine()
        result = engine.score([])
        assert result.confidence == 0.5

    def test_high_severity_boosts_confidence(self) -> None:
        engine = RiskScoringEngine()
        result = engine.score([
            _finding("api_usage", "critical", "very_high"),
            _finding("c2", "high", "high"),
        ])
        assert result.confidence > 0.5

    def test_multi_domain_boosts_confidence(self) -> None:
        """Findings across many domains increase confidence."""
        engine = RiskScoringEngine()
        result = engine.score([
            _finding("debuggable", "medium", "high"),
            _finding("permission_risk", "medium", "high"),
            _finding("api_usage", "medium", "high"),
            _finding("c2", "medium", "high"),
        ])
        single = engine.score([_finding("api_usage", "medium", "high")])
        assert result.confidence > single.confidence


class TestKeyFindings:
    """Test key findings extraction."""

    def test_key_findings_ordered_by_severity(self) -> None:
        engine = RiskScoringEngine()
        result = engine.score([
            _finding("api_usage", "info", "low", title="Low prio"),
            _finding("c2", "critical", "very_high", title="Critical C2"),
            _finding("debuggable", "medium", "high", title="Medium debuggable"),
        ])
        assert result.key_findings[0].startswith("[CRITICAL]")
        assert result.key_findings[-1].startswith("[INFO]")

    def test_key_findings_capped_at_ten(self) -> None:
        engine = RiskScoringEngine()
        findings = [_finding("api_usage", "medium", "high", title=f"Finding {i}") for i in range(20)]
        result = engine.score(findings)
        assert len(result.key_findings) <= 10
