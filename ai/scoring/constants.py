"""Scoring engine constants — weights, severity maps, and framework mappings.

These are the knobs that control the deterministic scoring model.
All values are calibrated against CICMalDroid-2020 category behaviours
(banking malware, adware, SMS malware, riskware, benign) and CCCS-CIC
trojan-banker sub-families. Adjustments should be accompanied by
re-running the profile tests in ``test_profiles.py``.

Architecture note (02-services.md §8): "No LLM call in the scoring math
itself — reproducible." Everything here is pure arithmetic.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Domain weights — how much each analysis domain contributes to the final
# score. Must sum to 1.0.
# ---------------------------------------------------------------------------
DOMAIN_WEIGHTS: dict[str, float] = {
    "manifest":     0.10,
    "permissions":  0.15,
    "code":         0.20,
    "api":          0.15,
    "network":      0.15,
    "threat_intel": 0.15,
    "dynamic":      0.10,  # Phase 10 — unused until dynamic analysis ships
}

# ---------------------------------------------------------------------------
# Severity → numeric score mapping
# Aligned with CVSS qualitative ratings:
#   info ≈ 0-3.9, low ≈ 4.0-5.9, medium ≈ 6.0-7.4, high ≈ 7.5-8.9, critical ≈ 9.0-10.0
# Mapped to a 0-100 engine scale.
# ---------------------------------------------------------------------------
SEVERITY_SCORES: dict[str, float] = {
    "info":     10.0,
    "low":      25.0,
    "medium":   50.0,
    "high":     75.0,
    "critical": 100.0,
}

# ---------------------------------------------------------------------------
# Confidence → multiplier mapping
# Confidence attenuates the raw severity: a critical finding with low
# confidence contributes less than a high finding with very_high confidence.
# ---------------------------------------------------------------------------
CONFIDENCE_MULTIPLIERS: dict[str, float] = {
    "low":       0.30,
    "medium":    0.60,
    "high":      0.85,
    "very_high": 1.00,
}

# ---------------------------------------------------------------------------
# Risk tier thresholds
# ---------------------------------------------------------------------------
TIER_THRESHOLDS: list[tuple[float, str]] = [
    (90.0, "critical"),
    (70.0, "malicious"),
    (40.0, "suspicious"),
    (0.0,  "benign"),
]

# ---------------------------------------------------------------------------
# Finding type → domain mapping
# When a Finding arrives we need to assign it to a scoring domain.
# ---------------------------------------------------------------------------
FINDING_TYPE_TO_DOMAIN: dict[str, str] = {
    # Manifest domain
    "exported_component": "manifest",
    "debuggable":         "manifest",
    "backup_allowed":     "manifest",
    "cleartext":          "manifest",
    "certificate":        "manifest",
    "manifest_config":    "manifest",

    # Permissions domain
    "permission":      "permissions",
    "permission_risk": "permissions",

    # Code domain
    "control_flow":  "code",
    "obfuscation":   "code",
    "anti_analysis": "code",
    "behavior":      "code",

    # API domain
    "dangerous_api": "api",
    "api_usage":     "api",
    "api":           "api",
    "reflection":    "api",
    "native_code":   "api",

    # Network domain
    "network":         "network",
    "c2":              "network",
    "data_exfil":      "network",
    "suspicious_domain": "network",
    "pinning_bypass":  "network",
    "url":             "network",
    "ip":              "network",

    # Threat intel domain
    "threat_intel":        "threat_intel",
    "ioc_match":           "threat_intel",
    "family_attribution":  "threat_intel",
    "actor_attribution":   "threat_intel",
    "signature":           "threat_intel",

    # Dynamic domain (Phase 10)
    "runtime_behavior": "dynamic",
    "dynamic":          "dynamic",
}

# ---------------------------------------------------------------------------
# MITRE ATT&CK technique → category hints
# Used by the categorizer to weight malware family scores.
# ---------------------------------------------------------------------------
MITRE_CATEGORY_HINTS: dict[str, list[str]] = {
    # Banking trojan indicators
    "T1417.001": ["banking_trojan"],  # Input Capture: Keylogging
    "T1417.002": ["banking_trojan"],  # Input Capture: GUI Input Capture (overlay)
    "T1636.004": ["banking_trojan", "spyware"],  # SMS/MMS Collection
    "T1626":     ["banking_trojan"],  # Abuse Elevation Control Mechanism
    "T1204":     ["banking_trojan"],  # User Execution
    "T1623":     ["banking_trojan", "rootkit"],  # Command & Scripting Interpreter

    # Spyware indicators
    "T1636.003": ["spyware"],  # Contact List
    "T1636.001": ["spyware"],  # Calendar Entries
    "T1429":     ["spyware"],  # Audio Capture
    "T1512":     ["spyware"],  # Video Capture
    "T1430":     ["spyware"],  # Location Tracking

    # Dropper / loader indicators
    "T1407": ["dropper"],  # Download New Code at Runtime
    "T1620": ["dropper"],  # Reflective Code Loading

    # Ransomware indicators
    "T1486": ["ransomware"],  # Data Encrypted for Impact
    "T1489": ["ransomware"],  # Service Stop

    # Obfuscation / evasion (amplifies other categories)
    "T1027":     ["evasion"],
    "T1406":     ["evasion"],

    # Network / C2
    "T1071":     ["c2"],  # Application Layer Protocol
    "T1573":     ["c2"],  # Encrypted Channel
    "T1041":     ["exfiltration"],  # Exfiltration Over C2 Channel
    "T1005":     ["exfiltration"],  # Data from Local System
}

# ---------------------------------------------------------------------------
# OWASP Mobile Top 10 categories for compliance mapping
# ---------------------------------------------------------------------------
OWASP_DESCRIPTIONS: dict[str, str] = {
    "M1":  "Improper Platform Usage",
    "M2":  "Insecure Data Storage",
    "M3":  "Insecure Communication",
    "M4":  "Insecure Authentication",
    "M5":  "Insufficient Cryptography",
    "M6":  "Insecure Authorization",
    "M7":  "Client Code Quality",
    "M8":  "Code Tampering",
    "M9":  "Reverse Engineering",
    "M10": "Extraneous Functionality",
}
