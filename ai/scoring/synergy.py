"""Synergy rules — multi-signal amplification for compound threats.

A single finding (e.g. "uses reflection") is interesting but ambiguous.
When *multiple* indicators co-occur (reflection + dynamic DEX loading +
network exfiltration), the probability of malicious intent skyrockets.
Synergy rules capture these compound patterns with additive score bonuses.

Each rule defines:
- ``required_signals``: a set of conditions that must all be true.
  Conditions reference domains (e.g. ``domain:api``), finding types
  (e.g. ``type:reflection``), or MITRE techniques (e.g. ``mitre:T1417.002``).
- ``bonus``: additive points to the final score (capped at 100 total).
- ``confidence``: how reliable this synergy pattern is as a malware indicator.

Rules are evaluated after base domain scoring, using the same findings.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class SynergyRule:
    """A compound threat pattern that amplifies the risk score."""
    rule_id: str
    name: str
    description: str
    required_signals: frozenset[str]  # conditions that must all match
    bonus: float                      # additive points
    confidence: float = 0.80          # how reliable this pattern is


# ---------------------------------------------------------------------------
# Synergy rule registry
# ---------------------------------------------------------------------------
# Rules are ordered by descending bonus so the most impactful fire first.
# The engine applies ALL matching rules (they stack additively).

SYNERGY_RULES: list[SynergyRule] = [
    # ── Banking trojan compound patterns ─────────────────────────────────
    SynergyRule(
        rule_id="SYN-001",
        name="Overlay + SMS Intercept",
        description=(
            "Classic banking trojan pattern: draw overlay to steal credentials "
            "while intercepting SMS for OTP bypass."
        ),
        required_signals=frozenset({
            "mitre:T1417.002",   # GUI Input Capture (overlay)
            "mitre:T1636.004",   # SMS/MMS Collection
        }),
        bonus=15.0,
        confidence=0.95,
    ),
    SynergyRule(
        rule_id="SYN-002",
        name="Accessibility + Overlay + Device Admin",
        description=(
            "Full takeover pattern: accessibility service for keylogging, "
            "overlay for credential theft, device admin for persistence."
        ),
        required_signals=frozenset({
            "mitre:T1417.001",   # Keylogging (accessibility)
            "mitre:T1417.002",   # Overlay
            "mitre:T1626",       # Device admin abuse
        }),
        bonus=20.0,
        confidence=0.95,
    ),
    SynergyRule(
        rule_id="SYN-003",
        name="Dynamic Loading + Reflection + Network",
        description=(
            "Payload dropper pattern: downloads new code at runtime via "
            "reflective loading over a network channel."
        ),
        required_signals=frozenset({
            "mitre:T1407",       # Download New Code at Runtime
            "mitre:T1620",       # Reflective Code Loading
            "domain:network",    # has network findings
        }),
        bonus=15.0,
        confidence=0.90,
    ),
    SynergyRule(
        rule_id="SYN-004",
        name="SMS + Contacts + Network Exfil",
        description=(
            "Spyware pattern: exfiltrates PII (SMS + contacts) over the network."
        ),
        required_signals=frozenset({
            "mitre:T1636.004",   # SMS Collection
            "mitre:T1636.003",   # Contact List
            "domain:network",
        }),
        bonus=12.0,
        confidence=0.90,
    ),
    SynergyRule(
        rule_id="SYN-005",
        name="Obfuscation + Anti-Analysis + Native Code",
        description=(
            "Heavy evasion: obfuscated code with anti-analysis tricks and "
            "native components to hide malicious logic."
        ),
        required_signals=frozenset({
            "type:obfuscation",
            "type:anti_analysis",
            "type:native_code",
        }),
        bonus=10.0,
        confidence=0.85,
    ),

    # ── Medium-severity compound patterns ────────────────────────────────
    SynergyRule(
        rule_id="SYN-006",
        name="Reflection + Runtime Exec",
        description=(
            "Reflective code execution combined with runtime command execution "
            "suggests payload unpacking or privilege escalation."
        ),
        required_signals=frozenset({
            "type:reflection",
            "mitre:T1623",  # Command & Scripting Interpreter
        }),
        bonus=8.0,
        confidence=0.80,
    ),
    SynergyRule(
        rule_id="SYN-007",
        name="Cleartext Traffic + Debuggable",
        description=(
            "App allows cleartext traffic AND is debuggable — trivially "
            "interceptable; may be intentional for testing or for MitM."
        ),
        required_signals=frozenset({
            "type:cleartext",
            "type:debuggable",
        }),
        bonus=5.0,
        confidence=0.70,
    ),
    SynergyRule(
        rule_id="SYN-008",
        name="Threat Intel Match + High Permissions",
        description=(
            "Known malware signature match combined with dangerous permission "
            "profile — very high confidence of active threat."
        ),
        required_signals=frozenset({
            "domain:threat_intel",
            "domain:permissions",
        }),
        bonus=12.0,
        confidence=0.95,
    ),
    SynergyRule(
        rule_id="SYN-009",
        name="Crypto Misuse + Network Exfil",
        description=(
            "Custom cryptography combined with network communication — "
            "likely encrypting exfiltrated data to evade DLP."
        ),
        required_signals=frozenset({
            "mitre:T1573",   # Encrypted Channel
            "mitre:T1041",   # Exfil over C2
        }),
        bonus=8.0,
        confidence=0.80,
    ),
    SynergyRule(
        rule_id="SYN-010",
        name="Accessibility + SMS Access",
        description=(
            "Accessibility service abuse with SMS access — can silently "
            "read and forward OTPs without user awareness."
        ),
        required_signals=frozenset({
            "mitre:T1417.001",  # Keylogging
            "mitre:T1636.004",  # SMS Collection
        }),
        bonus=12.0,
        confidence=0.90,
    ),
]


def evaluate_synergy(
    active_domains: set[str],
    active_types: set[str],
    active_mitre: set[str],
) -> list[tuple[SynergyRule, bool]]:
    """Evaluate all synergy rules against the active signal sets.

    Args:
        active_domains: set of domain names that have at least one finding
        active_types: set of finding types present across all findings
        active_mitre: set of MITRE technique IDs across all findings

    Returns:
        List of (rule, matched) tuples for every rule.
    """
    # Build a unified signal set for fast lookup
    signals: set[str] = set()
    for d in active_domains:
        signals.add(f"domain:{d}")
    for t in active_types:
        signals.add(f"type:{t}")
    for m in active_mitre:
        signals.add(f"mitre:{m}")

    results: list[tuple[SynergyRule, bool]] = []
    for rule in SYNERGY_RULES:
        matched = rule.required_signals.issubset(signals)
        results.append((rule, matched))
    return results
