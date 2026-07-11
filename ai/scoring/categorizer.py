"""Malware category classifier — determines the most likely malware family.

Uses a weighted voting system across multiple signals:
1. MITRE technique → category hints (from constants)
2. Finding type heuristics (e.g. overlay findings ⇒ banking trojan)
3. Threat intelligence family matches (if present)
4. Permission profile analysis (dangerous permission combos)

The classifier is deterministic and reproducible — no LLM involvement.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from ai.scoring.constants import MITRE_CATEGORY_HINTS


# Known banking trojan family names for threat-intel matching
_BANKING_FAMILIES: frozenset[str] = frozenset({
    "anubis", "cerberus", "eventbot", "brata", "teabot", "flubot",
    "xenomorph", "hook", "medusa", "sharkbot", "hydra", "ermac",
    "octo", "godfather", "nexus", "vultur", "brokewell", "anatsa",
    "copybara", "sova", "ginp", "gustuff",
})

# Finding types that strongly indicate specific categories
_TYPE_CATEGORY_HINTS: dict[str, list[tuple[str, int]]] = {
    # (category, weight)
    "exported_component": [("banking_trojan", 1)],
    "debuggable":         [("riskware", 2)],
    "backup_allowed":     [("riskware", 1)],
    "cleartext":          [("riskware", 1)],

    "permission":      [("spyware", 1)],
    "permission_risk": [("spyware", 1)],

    "control_flow":  [("banking_trojan", 2), ("dropper", 1)],
    "obfuscation":   [("banking_trojan", 1), ("dropper", 1)],
    "anti_analysis": [("banking_trojan", 2), ("rootkit", 1)],
    "behavior":      [("banking_trojan", 1)],

    "reflection":    [("dropper", 2), ("banking_trojan", 1)],
    "native_code":   [("rootkit", 2)],

    "c2":              [("banking_trojan", 3), ("spyware", 2)],
    "data_exfil":      [("spyware", 3), ("banking_trojan", 1)],
    "suspicious_domain": [("banking_trojan", 1), ("spyware", 1)],
    "pinning_bypass":  [("banking_trojan", 2)],

    "ioc_match":          [("banking_trojan", 5)],
    "family_attribution": [("banking_trojan", 5)],
    "signature":          [("banking_trojan", 3)],
}

# Dangerous permission combos that hint at specific categories
_PERMISSION_COMBOS: list[tuple[frozenset[str], str, int]] = [
    # (required_perms, category, weight)
    (
        frozenset({"android.permission.RECEIVE_SMS", "android.permission.SYSTEM_ALERT_WINDOW"}),
        "banking_trojan", 4,
    ),
    (
        frozenset({"android.permission.RECEIVE_SMS", "android.permission.READ_SMS"}),
        "banking_trojan", 3,
    ),
    (
        frozenset({"android.permission.READ_CONTACTS", "android.permission.RECORD_AUDIO"}),
        "spyware", 3,
    ),
    (
        frozenset({"android.permission.CAMERA", "android.permission.RECORD_AUDIO",
                    "android.permission.ACCESS_FINE_LOCATION"}),
        "spyware", 4,
    ),
    (
        frozenset({"android.permission.BIND_DEVICE_ADMIN",
                    "android.permission.BIND_ACCESSIBILITY_SERVICE"}),
        "banking_trojan", 5,
    ),
]


def classify(
    finding_types: list[str],
    mitre_techniques: list[str],
    agent_outputs: dict[str, Any] | None = None,
    permissions: list[str] | None = None,
) -> tuple[str, list[str]]:
    """Classify the APK into malware categories.

    Returns:
        A tuple of (primary_category, secondary_categories).
        If no category has enough signal, returns ``("unknown", [])``.
    """
    votes: dict[str, int] = defaultdict(int)

    # 1. MITRE technique → category hints
    for technique in mitre_techniques:
        categories = MITRE_CATEGORY_HINTS.get(technique, [])
        for cat in categories:
            votes[cat] += 2

    # 2. Finding type heuristics
    for ftype in finding_types:
        hints = _TYPE_CATEGORY_HINTS.get(ftype, [])
        for cat, weight in hints:
            votes[cat] += weight

    # 3. Threat intelligence family matching
    if agent_outputs:
        ti_output = agent_outputs.get("threat_intel_agent", {})
        if not isinstance(ti_output, dict):
            ti_output = {}
        families = ti_output.get("malware_families", [])
        if isinstance(families, list):
            for fam in families:
                fam_name = ""
                if isinstance(fam, dict):
                    fam_name = fam.get("family_name", "").lower()
                elif isinstance(fam, str):
                    fam_name = fam.lower()
                if fam_name and any(known in fam_name for known in _BANKING_FAMILIES):
                    votes["banking_trojan"] += 10

    # 4. Permission profile analysis
    if permissions:
        perm_set = frozenset(permissions)
        for required, category, weight in _PERMISSION_COMBOS:
            if required.issubset(perm_set):
                votes[category] += weight

    # Remove meta-categories that just amplify others
    for meta in ("evasion", "c2", "exfiltration"):
        votes.pop(meta, None)

    if not votes or max(votes.values()) == 0:
        return "unknown", []

    # Sort by vote count descending
    sorted_cats = sorted(votes.items(), key=lambda x: x[1], reverse=True)
    primary = sorted_cats[0][0]
    # Secondary = any other category with at least 30% of primary's votes
    primary_votes = sorted_cats[0][1]
    threshold = max(1, int(primary_votes * 0.30))
    secondaries = [cat for cat, v in sorted_cats[1:] if v >= threshold]

    return primary, secondaries
