"""Synthetic profile integration tests — validate scoring calibration.

These tests run fully constructed APK analysis profiles through the scoring
engine and assert they land in the correct score/tier/category ranges. The
profiles are informed by CICMalDroid-2020 and CCCS-CIC-AndMal2020 category
behaviours (banking malware, adware, SMS malware, riskware, benign).

Each profile simulates the findings that the upstream agents would produce
for a particular type of APK, exercising the full pipeline: domain scoring,
synergy rules, category classification, and tier assignment.
"""

from __future__ import annotations

import pytest

from ai.scoring.engine import RiskScoringEngine
from ai.scoring.models import RiskTierEnum


def _f(
    ftype: str,
    severity: str,
    confidence: str,
    mitre: list[str] | None = None,
    owasp: list[str] | None = None,
    title: str = "",
) -> dict:
    """Shorthand finding builder."""
    return {
        "id": f"profile-{ftype}-{severity}",
        "type": ftype,
        "severity": severity,
        "confidence": confidence,
        "title": title or f"{ftype} ({severity})",
        "description": f"Synthetic {ftype}",
        "mitre_techniques": mitre or [],
        "owasp_mobile": owasp or [],
    }


# =====================================================================
# Profile 1: Completely benign app
# =====================================================================
BENIGN_PROFILE = {
    "name": "Benign Calculator App",
    "findings": [
        _f("manifest_config", "info", "high", title="Standard manifest"),
        _f("permission", "info", "high", title="INTERNET permission"),
    ],
    "permissions": [
        "android.permission.INTERNET",
    ],
    "agent_outputs": {},
}


# =====================================================================
# Profile 2: Adware — aggressive ads, tracking, but not malware
# =====================================================================
ADWARE_PROFILE = {
    "name": "Adware Flashlight App",
    "findings": [
        _f("permission_risk", "medium", "high", title="READ_PHONE_STATE", owasp=["M1"]),
        _f("permission_risk", "medium", "high", title="ACCESS_FINE_LOCATION", owasp=["M1"]),
        _f("api_usage", "medium", "medium", title="Location API usage", owasp=["M1"]),
        _f("api_usage", "low", "medium", title="Advertising ID access"),
        _f("network", "medium", "high",
           title="Connects to ad networks",
           mitre=["T1071"], owasp=["M3"]),
        _f("cleartext", "low", "high", title="Some cleartext ad traffic"),
        _f("exported_component", "low", "medium", title="Exported ad receiver"),
    ],
    "permissions": [
        "android.permission.INTERNET",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.READ_PHONE_STATE",
    ],
    "agent_outputs": {},
}


# =====================================================================
# Profile 3: Riskware — poorly written app with security issues
# =====================================================================
RISKWARE_PROFILE = {
    "name": "Riskware File Manager",
    "findings": [
        _f("debuggable", "high", "very_high", title="App is debuggable", mitre=["T1562.001"]),
        _f("backup_allowed", "medium", "very_high", title="Backup allowed", mitre=["T1005"]),
        _f("cleartext", "medium", "high", title="Cleartext traffic allowed", owasp=["M3"]),
        _f("exported_component", "medium", "high", title="3 exported activities"),
        _f("permission_risk", "medium", "high", title="READ_EXTERNAL_STORAGE"),
        _f("api_usage", "low", "medium", title="File I/O operations"),
        _f("certificate", "medium", "high", title="Debug certificate"),
    ],
    "permissions": [
        "android.permission.INTERNET",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
    ],
    "agent_outputs": {},
}


# =====================================================================
# Profile 4: Spyware — data exfiltration focused
# =====================================================================
SPYWARE_PROFILE = {
    "name": "Spyware Stalkerware",
    "findings": [
        _f("permission_risk", "high", "very_high", title="CAMERA access"),
        _f("permission_risk", "high", "very_high", title="RECORD_AUDIO access"),
        _f("permission_risk", "high", "very_high", title="ACCESS_FINE_LOCATION"),
        _f("permission_risk", "high", "high", title="READ_CONTACTS"),
        _f("permission_risk", "high", "high", title="READ_SMS"),
        _f("api_usage", "high", "high",
           title="Location tracking API",
           mitre=["T1430"], owasp=["M1"]),
        _f("api_usage", "high", "high",
           title="Audio recording API",
           mitre=["T1429"]),
        _f("api_usage", "critical", "very_high",
           title="SMS collection and exfiltration",
           mitre=["T1636.004", "T1041"]),
        _f("data_exfil", "critical", "very_high",
           title="Exfiltrates contacts over network",
           mitre=["T1636.003", "T1041"], owasp=["M2"]),
        _f("c2", "high", "high",
           title="C2 communication channel",
           mitre=["T1071", "T1573"]),
        _f("obfuscation", "high", "very_high",
           title="Code obfuscation detected",
           mitre=["T1027"]),
        _f("anti_analysis", "medium", "high",
           title="Anti-emulator checks"),
    ],
    "permissions": [
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.READ_CONTACTS",
        "android.permission.READ_SMS",
        "android.permission.INTERNET",
    ],
    "agent_outputs": {},
}


# =====================================================================
# Profile 5: Banking Trojan — full capabilities
# =====================================================================
BANKING_TROJAN_PROFILE = {
    "name": "Banking Trojan (Anubis-like)",
    "findings": [
        # Overlay attack
        _f("api_usage", "critical", "very_high",
           title="SYSTEM_ALERT_WINDOW overlay",
           mitre=["T1417.002"], owasp=["M1"]),
        # Accessibility abuse
        _f("api_usage", "critical", "very_high",
           title="AccessibilityService abuse",
           mitre=["T1417.001"], owasp=["M1"]),
        # SMS interception
        _f("api_usage", "critical", "very_high",
           title="SMS interception via SmsManager",
           mitre=["T1636.004"], owasp=["M1"]),
        # Device admin
        _f("api_usage", "critical", "very_high",
           title="DeviceAdminReceiver registered",
           mitre=["T1626"]),
        # Reflection + dynamic loading
        _f("reflection", "high", "high",
           title="Reflection-based dynamic dispatch",
           mitre=["T1620"]),
        _f("api_usage", "high", "high",
           title="DexClassLoader dynamic loading",
           mitre=["T1407"]),
        # Network / C2
        _f("c2", "critical", "very_high",
           title="C2 communication to suspicious domain",
           mitre=["T1071", "T1573"]),
        _f("data_exfil", "high", "high",
           title="Exfiltrates SMS + contacts",
           mitre=["T1636.003", "T1041"]),
        # Code evasion
        _f("obfuscation", "high", "very_high",
           title="Heavy code obfuscation",
           mitre=["T1027"]),
        _f("anti_analysis", "high", "high",
           title="Root/emulator detection"),
        _f("control_flow", "high", "high",
           title="Reflection chain: forName→getMethod→invoke"),
        _f("native_code", "medium", "high",
           title="Native library with encrypted strings"),
        # Permissions
        _f("permission_risk", "critical", "very_high",
           title="Critical permission profile"),
        # Manifest
        _f("exported_component", "high", "high",
           title="Multiple exported components"),
        # Threat intel
        _f("ioc_match", "critical", "very_high",
           title="Hash matches known Anubis sample"),
        _f("family_attribution", "critical", "very_high",
           title="Attributed to Anubis family"),
    ],
    "permissions": [
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_SMS",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.BIND_DEVICE_ADMIN",
        "android.permission.INTERNET",
        "android.permission.READ_CONTACTS",
    ],
    "agent_outputs": {
        "threat_intel_agent": {
            "malware_families": [{"family_name": "Anubis"}],
        }
    },
}


# =====================================================================
# Profile 6: Dropper — loads payload at runtime
# =====================================================================
DROPPER_PROFILE = {
    "name": "Dropper (Stage 1 Loader)",
    "findings": [
        _f("api_usage", "critical", "very_high",
           title="DexClassLoader usage",
           mitre=["T1407"]),
        _f("reflection", "high", "high",
           title="Reflective code loading",
           mitre=["T1620"]),
        _f("network", "high", "high",
           title="Downloads payload from CDN",
           mitre=["T1071"]),
        _f("obfuscation", "high", "very_high",
           title="Heavy obfuscation to hide loader",
           mitre=["T1027"]),
        _f("anti_analysis", "high", "high",
           title="Sandbox evasion checks"),
        _f("native_code", "medium", "high",
           title="Native unpacking routine"),
        _f("control_flow", "high", "high",
           title="Encrypted string decryption chain"),
        _f("permission_risk", "medium", "high",
           title="Broad permissions for loader"),
    ],
    "permissions": [
        "android.permission.INTERNET",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.REQUEST_INSTALL_PACKAGES",
    ],
    "agent_outputs": {},
}


# =====================================================================
# Profile 7: Edge case — single devastating finding
# =====================================================================
SINGLE_IOC_PROFILE = {
    "name": "Edge Case — Single IOC Match Only",
    "findings": [
        _f("ioc_match", "critical", "very_high",
           title="SHA-256 matches known Cerberus hash"),
    ],
    "permissions": [],
    "agent_outputs": {
        "threat_intel_agent": {
            "malware_families": [{"family_name": "Cerberus"}],
        }
    },
}


# =====================================================================
# Profile 8: Edge case — many low-severity findings
# =====================================================================
MANY_LOW_FINDINGS_PROFILE = {
    "name": "Edge Case — 50 Info Findings",
    "findings": [
        _f("api_usage", "info", "low", title=f"Info finding {i}")
        for i in range(50)
    ],
    "permissions": [],
    "agent_outputs": {},
}


# =====================================================================
# Tests
# =====================================================================

class TestBenignProfile:
    def test_score_below_20(self) -> None:
        engine = RiskScoringEngine()
        result = engine.score(
            BENIGN_PROFILE["findings"],
            permissions=BENIGN_PROFILE["permissions"],
        )
        assert result.final_score < 20.0, f"Benign app scored {result.final_score}"
        assert result.tier == RiskTierEnum.benign

    def test_no_synergy_rules_fire(self) -> None:
        engine = RiskScoringEngine()
        result = engine.score(BENIGN_PROFILE["findings"])
        assert len(result.synergy_bonuses) == 0


class TestAdwareProfile:
    def test_score_in_range(self) -> None:
        engine = RiskScoringEngine()
        result = engine.score(
            ADWARE_PROFILE["findings"],
            permissions=ADWARE_PROFILE["permissions"],
        )
        assert 15.0 <= result.final_score <= 55.0, (
            f"Adware scored {result.final_score}, expected 15-55"
        )

    def test_tier_is_benign_or_suspicious(self) -> None:
        engine = RiskScoringEngine()
        result = engine.score(ADWARE_PROFILE["findings"])
        assert result.tier in (RiskTierEnum.benign, RiskTierEnum.suspicious)


class TestRiskwareProfile:
    def test_score_in_range(self) -> None:
        engine = RiskScoringEngine()
        result = engine.score(
            RISKWARE_PROFILE["findings"],
            permissions=RISKWARE_PROFILE["permissions"],
        )
        assert 20.0 <= result.final_score <= 55.0, (
            f"Riskware scored {result.final_score}, expected 20-55"
        )

    def test_cleartext_debuggable_synergy(self) -> None:
        """SYN-007 should fire for cleartext + debuggable."""
        engine = RiskScoringEngine()
        result = engine.score(RISKWARE_PROFILE["findings"])
        fired_ids = {sb.rule_id for sb in result.synergy_bonuses}
        assert "SYN-007" in fired_ids


class TestSpywareProfile:
    def test_score_above_60(self) -> None:
        engine = RiskScoringEngine()
        result = engine.score(
            SPYWARE_PROFILE["findings"],
            permissions=SPYWARE_PROFILE["permissions"],
        )
        assert result.final_score >= 60.0, f"Spyware scored {result.final_score}"

    def test_tier_is_malicious_or_higher(self) -> None:
        engine = RiskScoringEngine()
        result = engine.score(
            SPYWARE_PROFILE["findings"],
            permissions=SPYWARE_PROFILE["permissions"],
        )
        assert result.tier in (RiskTierEnum.malicious, RiskTierEnum.critical)

    def test_category_is_spyware(self) -> None:
        engine = RiskScoringEngine()
        result = engine.score(
            SPYWARE_PROFILE["findings"],
            permissions=SPYWARE_PROFILE["permissions"],
        )
        assert result.primary_category == "spyware" or "spyware" in result.secondary_categories


class TestBankingTrojanProfile:
    def test_score_above_90(self) -> None:
        """Full banking trojan should score ≥ 90 (critical tier)."""
        engine = RiskScoringEngine()
        result = engine.score(
            BANKING_TROJAN_PROFILE["findings"],
            BANKING_TROJAN_PROFILE["agent_outputs"],
            BANKING_TROJAN_PROFILE["permissions"],
        )
        assert result.final_score >= 90.0, f"Banking trojan scored {result.final_score}"
        assert result.tier == RiskTierEnum.critical

    def test_category_is_banking_trojan(self) -> None:
        engine = RiskScoringEngine()
        result = engine.score(
            BANKING_TROJAN_PROFILE["findings"],
            BANKING_TROJAN_PROFILE["agent_outputs"],
            BANKING_TROJAN_PROFILE["permissions"],
        )
        assert result.primary_category == "banking_trojan"

    def test_multiple_synergies_fire(self) -> None:
        """A full banking trojan should trigger several synergy rules."""
        engine = RiskScoringEngine()
        result = engine.score(
            BANKING_TROJAN_PROFILE["findings"],
            BANKING_TROJAN_PROFILE["agent_outputs"],
        )
        assert len(result.synergy_bonuses) >= 3, (
            f"Expected ≥3 synergy rules, got {len(result.synergy_bonuses)}: "
            f"{[sb.rule_id for sb in result.synergy_bonuses]}"
        )

    def test_high_confidence(self) -> None:
        engine = RiskScoringEngine()
        result = engine.score(
            BANKING_TROJAN_PROFILE["findings"],
            BANKING_TROJAN_PROFILE["agent_outputs"],
        )
        assert result.confidence >= 0.80

    def test_mitre_techniques_populated(self) -> None:
        engine = RiskScoringEngine()
        result = engine.score(BANKING_TROJAN_PROFILE["findings"])
        assert len(result.mitre_techniques) >= 5


class TestDropperProfile:
    def test_score_in_range(self) -> None:
        engine = RiskScoringEngine()
        result = engine.score(
            DROPPER_PROFILE["findings"],
            permissions=DROPPER_PROFILE["permissions"],
        )
        assert result.final_score >= 55.0, f"Dropper scored {result.final_score}"

    def test_dropper_synergy_fires(self) -> None:
        """SYN-003 should fire: dynamic loading + reflection + network."""
        engine = RiskScoringEngine()
        result = engine.score(DROPPER_PROFILE["findings"])
        fired_ids = {sb.rule_id for sb in result.synergy_bonuses}
        assert "SYN-003" in fired_ids

    def test_category_includes_dropper(self) -> None:
        engine = RiskScoringEngine()
        result = engine.score(DROPPER_PROFILE["findings"])
        all_cats = [result.primary_category] + result.secondary_categories
        assert "dropper" in all_cats


class TestEdgeCases:
    def test_single_ioc_match(self) -> None:
        """One devastating IOC match should still produce a meaningful score."""
        engine = RiskScoringEngine()
        result = engine.score(
            SINGLE_IOC_PROFILE["findings"],
            SINGLE_IOC_PROFILE["agent_outputs"],
        )
        # Single critical in threat_intel (weight 0.15): 100 × 1.0 × 0.15 = 15
        # Plus SYN-008 won't fire (no permissions domain findings)
        assert result.final_score >= 15.0
        assert result.primary_category == "banking_trojan"  # from TI agent output

    def test_many_low_findings_stay_low(self) -> None:
        """50 info findings shouldn't inflate the score to malicious."""
        engine = RiskScoringEngine()
        result = engine.score(MANY_LOW_FINDINGS_PROFILE["findings"])
        # Max in api domain: info(10) × low(0.30) = 3.0
        # 3.0 × 0.15 = 0.45
        assert result.final_score < 10.0
        assert result.tier == RiskTierEnum.benign

    def test_determinism(self) -> None:
        """Running the same input twice produces identical scores."""
        engine = RiskScoringEngine()
        r1 = engine.score(
            BANKING_TROJAN_PROFILE["findings"],
            BANKING_TROJAN_PROFILE["agent_outputs"],
            BANKING_TROJAN_PROFILE["permissions"],
        )
        r2 = engine.score(
            BANKING_TROJAN_PROFILE["findings"],
            BANKING_TROJAN_PROFILE["agent_outputs"],
            BANKING_TROJAN_PROFILE["permissions"],
        )
        assert r1.final_score == r2.final_score
        assert r1.tier == r2.tier
        assert r1.primary_category == r2.primary_category
        assert r1.confidence == r2.confidence

    def test_empty_findings_determinism(self) -> None:
        engine = RiskScoringEngine()
        r1 = engine.score([])
        r2 = engine.score([])
        assert r1.final_score == r2.final_score == 0.0

    def test_scoring_version_propagated(self) -> None:
        engine = RiskScoringEngine(scoring_version="2.0.0")
        result = engine.score(BENIGN_PROFILE["findings"])
        assert result.scoring_version == "2.0.0"
