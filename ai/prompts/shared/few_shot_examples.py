"""Few-shot examples for agent prompts."""

from __future__ import annotations

from typing import Dict, List


FEW_SHOT_EXAMPLES: Dict[str, List[Dict[str, str]]] = {
    "manifest_agent": [
        {
            "input": """Package: com.example.malware
Permissions: android.permission.BIND_ACCESSIBILITY_SERVICE, android.permission.SYSTEM_ALERT_WINDOW, android.permission.RECEIVE_SMS
Components: Exported activity MainActivity, Exported service AccessibilityService
debuggable: true""",
            "output": """{
  "package_name": "com.example.malware",
  "permissions": [
    {"id": "perm:accessibility", "type": "permission", "severity": "critical", "confidence": "very_high", "title": "Dangerous permission: android.permission.BIND_ACCESSIBILITY_SERVICE", "description": "Enables keylogging, screen reading, and UI interaction injection", "permission_name": "android.permission.BIND_ACCESSIBILITY_SERVICE", "protection_level": "dangerous", "risk_rationale": "Enables keylogging, screen reading, and UI interaction injection", "mitre_techniques": ["T1417.001"], "owasp_mobile": ["M1"]},
    {"id": "perm:overlay", "type": "permission", "severity": "high", "confidence": "high", "title": "Dangerous permission: android.permission.SYSTEM_ALERT_WINDOW", "description": "Allows overlay attacks for credential phishing", "permission_name": "android.permission.SYSTEM_ALERT_WINDOW", "protection_level": "dangerous", "risk_rationale": "Allows overlay attacks for credential phishing", "mitre_techniques": ["T1417.002"], "owasp_mobile": ["M1"]},
    {"id": "perm:sms", "type": "permission", "severity": "high", "confidence": "high", "title": "Dangerous permission: android.permission.RECEIVE_SMS", "description": "Intercepts SMS-based 2FA codes", "permission_name": "android.permission.RECEIVE_SMS", "protection_level": "dangerous", "risk_rationale": "Intercepts SMS-based 2FA codes", "mitre_techniques": ["T1636.004"], "owasp_mobile": ["M1"]}
  ],
  "components": [
    {"name": "MainActivity", "component_type": "activity", "exported": true, "permission": null, "intent_filters": [{"action": "android.intent.action.MAIN"}], "enabled": true},
    {"name": "AccessibilityService", "component_type": "service", "exported": true, "permission": "android.permission.BIND_ACCESSIBILITY_SERVICE", "intent_filters": [], "enabled": true}
  ],
  "debuggable": true,
  "allow_backup": true,
  "exported_component_count": 2,
  "dangerous_permission_count": 3,
  "critical_findings": 1,
  "high_findings": 2,
  "medium_findings": 0,
  "low_findings": 0,
  "info_findings": 0
}"""
        }
    ],
    "permission_agent": [
        {
            "input": """Declared permissions: BIND_ACCESSIBILITY_SERVICE, SYSTEM_ALERT_WINDOW, RECEIVE_SMS, READ_SMS, SEND_SMS, REQUEST_INSTALL_PACKAGES, BIND_DEVICE_ADMIN
Code-used permissions: BIND_ACCESSIBILITY_SERVICE, SYSTEM_ALERT_WINDOW, RECEIVE_SMS""",
            "output": """{
  "total_permissions": 7,
  "dangerous_permissions": [
    {"permission": "android.permission.BIND_ACCESSIBILITY_SERVICE", "protection_level": "dangerous", "risk_score": 1.0, "severity": "critical", "confidence": "very_high", "rationale": "High-risk banking malware permission. Actively used in code.", "mitre_techniques": ["T1417.001"], "owasp_categories": ["M1"], "is_runtime_requested": true, "is_used_by_component": true},
    {"permission": "android.permission.SYSTEM_ALERT_WINDOW", "protection_level": "dangerous", "risk_score": 0.95, "severity": "high", "confidence": "high", "rationale": "High-risk banking malware permission. Actively used in code.", "mitre_techniques": ["T1417.002"], "owasp_categories": ["M1"], "is_runtime_requested": true, "is_used_by_component": true}
  ],
  "permission_groups": [
    {"group_name": "ACCESSIBILITY", "permissions": [{"permission": "android.permission.BIND_ACCESSIBILITY_SERVICE", "protection_level": "dangerous", "risk_score": 1.0, "severity": "critical", "confidence": "very_high", "rationale": "High-risk banking malware permission. Actively used in code.", "mitre_techniques": ["T1417.001"], "owasp_categories": ["M1"], "is_runtime_requested": true, "is_used_by_component": true}], "aggregate_risk": 1.0, "severity": "critical", "capabilities_enabled": ["keylogging", "screen_reading", "ui_injection", "auto_click"]}
  ],
  "banking_relevant_permissions": [{"permission": "android.permission.BIND_ACCESSIBILITY_SERVICE", "protection_level": "dangerous", "risk_score": 1.0, "severity": "critical", "confidence": "very_high", "rationale": "High-risk banking malware permission. Actively used in code.", "mitre_techniques": ["T1417.001"], "owasp_categories": ["M1"], "is_runtime_requested": true, "is_used_by_component": true}],
  "financial_risk_score": 0.95,
  "findings": [],
  "critical_count": 1,
  "high_count": 2,
  "medium_count": 0,
  "low_count": 0
}"""
        }
    ],
    "risk_agent": [
        {
            "input": """Findings: 1 critical (overlay), 2 high (accessibility, SMS), 3 medium (network, crypto), 2 low
Agent outputs: manifest, permissions, code, api, network, threat_intel
Deterministic baseline: score=78, tier=malicious, confidence=0.8""",
            "output": """{
  "score": 82.5,
  "tier": "malicious",
  "confidence": 0.85,
  "breakdown": {
    "factors": [
      {"factor_id": "static_api", "name": "Static Api", "category": "static_api", "weight": 0.15, "raw_score": 100.0, "weighted_contribution": 15.0, "evidence_refs": ["api_overlay", "api_accessibility"], "description": "Category score: 100.0, Weight: 0.15", "mitre_techniques": ["T1417.002", "T1417.001"], "owasp_categories": ["M1"]},
      {"factor_id": "static_permissions", "name": "Static Permissions", "category": "static_permissions", "weight": 0.15, "raw_score": 95.0, "weighted_contribution": 14.25, "evidence_refs": ["perm_accessibility", "perm_overlay"], "description": "Category score: 95.0, Weight: 0.15", "mitre_techniques": ["T1417.001", "T1417.002"], "owasp_categories": ["M1"]}
    ],
    "total_weight": 1.0,
    "base_score": 78.0,
    "adjustments": [{"type": "threat_intel_boost", "value": 4.5, "reason": "Banking malware family attribution"}],
    "final_score": 82.5,
    "scoring_version": "1.0",
    "computed_at": "2024-01-15T10:30:00Z",
    "confidence": 0.85
  },
  "static_score": 85.0,
  "dynamic_score": 0.0,
  "code_score": 75.0,
  "network_score": 60.0,
  "threat_intel_score": 90.0,
  "permission_score": 95.0,
  "manifest_score": 70.0,
  "primary_category": "banking_trojan",
  "categories": ["banking_trojan", "spyware"],
  "mitre_techniques": ["T1417.001", "T1417.002", "T1636.004"],
  "owasp_mobile_categories": ["M1", "M3", "M5"],
  "key_findings": ["Overlay attack capability", "Accessibility service abuse", "SMS interception", "Banking malware family attributed"],
  "risk_narrative": "This sample exhibits strong indicators of a banking trojan with overlay attack capabilities, accessibility service abuse for keylogging and UI injection, and SMS interception for 2FA bypass. Threat intelligence attributes it to a known banking malware family.",
  "recommended_actions": ["Block indicators at network perimeter", "Update mobile threat detection rules", "Notify fraud monitoring teams", "Initiate incident response if found in environment"]
}"""
        }
    ],
}


def get_few_shot(agent_name: str) -> List[Dict[str, str]]:
    """Get few-shot examples for an agent."""
    return FEW_SHOT_EXAMPLES.get(agent_name, [])