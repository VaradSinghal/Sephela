"""Permission Agent - Deep permission risk analysis and capability mapping."""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel

from ai.schemas.base import Finding, Severity, Confidence, EvidenceRef
from ai.schemas.permission import PermissionAnalysis, PermissionRisk, PermissionGroupRisk
from ai.agents.base import BaseAgent, AgentConfig, AgentResult


# Permission groups for capability analysis
PERMISSION_GROUPS = {
    "SMS": [
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_WAP_PUSH",
        "android.permission.RECEIVE_MMS",
    ],
    "CALL_LOG": [
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.PROCESS_OUTGOING_CALLS",
    ],
    "CONTACTS": [
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.GET_ACCOUNTS",
    ],
    "LOCATION": [
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
    ],
    "MICROPHONE": [
        "android.permission.RECORD_AUDIO",
    ],
    "CAMERA": [
        "android.permission.CAMERA",
    ],
    "STORAGE": [
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.MANAGE_EXTERNAL_STORAGE",
    ],
    "PHONE": [
        "android.permission.CALL_PHONE",
        "android.permission.READ_PHONE_STATE",
        "android.permission.READ_PHONE_NUMBERS",
        "android.permission.ANSWER_PHONE_CALLS",
    ],
    "DEVICE_ADMIN": [
        "android.permission.BIND_DEVICE_ADMIN",
        "android.permission.BIND_WALLPAPER",
    ],
    "ACCESSIBILITY": [
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
    ],
    "OVERLAY": [
        "android.permission.SYSTEM_ALERT_WINDOW",
    ],
    "INSTALL_PACKAGES": [
        "android.permission.REQUEST_INSTALL_PACKAGES",
    ],
    "NETWORK": [
        "android.permission.INTERNET",
        "android.permission.ACCESS_NETWORK_STATE",
        "android.permission.ACCESS_WIFI_STATE",
        "android.permission.CHANGE_WIFI_STATE",
        "android.permission.CHANGE_NETWORK_STATE",
    ],
    "BLUETOOTH": [
        "android.permission.BLUETOOTH",
        "android.permission.BLUETOOTH_ADMIN",
        "android.permission.BLUETOOTH_CONNECT",
        "android.permission.BLUETOOTH_SCAN",
    ],
    "NFC": [
        "android.permission.NFC",
    ],
}


# Banking-specific high-risk permissions
BANKING_HIGH_RISK = {
    "android.permission.BIND_ACCESSIBILITY_SERVICE": 1.0,
    "android.permission.SYSTEM_ALERT_WINDOW": 0.95,
    "android.permission.RECEIVE_SMS": 0.9,
    "android.permission.READ_SMS": 0.9,
    "android.permission.REQUEST_INSTALL_PACKAGES": 0.85,
    "android.permission.BIND_DEVICE_ADMIN": 0.8,
    "android.permission.READ_CONTACTS": 0.6,
    "android.permission.RECORD_AUDIO": 0.5,
    "android.permission.ACCESS_FINE_LOCATION": 0.4,
}


class PermissionAgent(BaseAgent[PermissionAnalysis]):
    """Performs deep permission risk analysis and capability mapping."""

    def __init__(self, llm_client: Any = None):
        config = AgentConfig(
            name="permission_agent",
            model="claude-3-5-sonnet-20241022",
            temperature=0.1,
            max_tokens=4096,
            output_schema=PermissionAnalysis,
            system_prompt=self._get_system_prompt(),
        )
        super().__init__(config, llm_client)

    def _get_system_prompt(self) -> str:
        return """You are a senior Android security analyst specializing in permission risk analysis.
Your task is to analyze the permissions declared in an Android APK and assess their risk,
particularly in the context of banking malware and financial fraud.

For each permission, evaluate:
1. Protection level (normal, dangerous, signature, signatureOrSystem)
2. Risk score (0.0-1.0) based on abuse potential
3. Whether it's actually used by the code (cross-reference with code analysis if available)
4. Permission groups and combined capabilities enabled
5. Banking-specific relevance

Output a complete PermissionAnalysis object with:
- Individual permission risk assessments
- Grouped capability analysis
- Banking-relevant risk scoring
- Findings with MITRE/OWASP mappings"""

    def build_prompt(self, evidence: dict[str, Any], context: dict[str, Any]) -> str:
        manifest_evidence = evidence.get("manifest", {})
        permission_evidence = evidence.get("permissions", {})
        code_evidence = context.get("code_agent_output", {})

        permissions = permission_evidence.get("permissions", [])
        code_permissions = code_evidence.get("summary", {}).get("permissions_used", []) if code_evidence else []

        return f"""Analyze these Android permissions for security risk:

DECLARED PERMISSIONS ({len(permissions)} total):
{json.dumps(permissions, indent=2)}

PERMISSIONS USED IN CODE (from Code Agent):
{json.dumps(code_permissions, indent=2)}

PERMISSION GROUPS REFERENCE:
{json.dumps(PERMISSION_GROUPS, indent=2)}

BANKING HIGH-RISK WEIGHTS:
{json.dumps(BANKING_HIGH_RISK, indent=2)}

For each permission, determine:
1. Protection level
2. Risk score (0.0-1.0)
3. Whether it's actually used in code
4. MITRE ATT&CK techniques enabled
5. OWASP Mobile categories

Group permissions by capability (SMS, Location, etc.) and assess combined risk.
Calculate banking-specific financial risk score.
Output complete PermissionAnalysis object."""

    def parse_output(self, raw_output: str) -> PermissionAnalysis:
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            import re
            match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', raw_output, re.DOTALL)
            if match:
                data = json.loads(match.group(1))
            else:
                raise ValueError("Could not parse agent output as JSON")
        return PermissionAnalysis(**data)


def analyze_permissions_deterministic(evidence: dict[str, Any], code_context: dict[str, Any] = None) -> PermissionAnalysis:
    """Deterministic permission analysis without LLM."""
    permission_evidence = evidence.get("permissions", {})
    permissions = permission_evidence.get("permissions", [])
    
    code_permissions = set()
    if code_context:
        code_permissions = set(code_context.get("summary", {}).get("permissions_used", []))

    dangerous_risks = []
    signature_risks = []
    custom_risks = []
    normal_risks = []

    for perm in permissions:
        in_code = perm in code_permissions
        risk = _assess_permission_risk(perm, in_code)
        
        if "dangerous" in perm.lower() or perm in BANKING_HIGH_RISK:
            dangerous_risks.append(risk)
        elif "signature" in perm.lower():
            signature_risks.append(risk)
        elif perm.startswith("com.") or perm.startswith("org."):
            custom_risks.append(risk)
        else:
            normal_risks.append(risk)

    # Group by capability
    groups = []
    for group_name, group_perms in PERMISSION_GROUPS.items():
        group_risks = [r for r in dangerous_risks + signature_risks + custom_risks if r.permission in group_perms]
        if group_risks:
            aggregate = sum(r.risk_score for r in group_risks) / len(group_risks)
            severity = _score_to_severity(aggregate)
            capabilities = _get_capabilities(group_name, group_risks)
            groups.append(PermissionGroupRisk(
                group_name=group_name,
                permissions=group_risks,
                aggregate_risk=aggregate,
                severity=severity,
                capabilities_enabled=capabilities,
            ))

    # Banking relevant
    banking_risks = [r for r in dangerous_risks + signature_risks + custom_risks if r.permission in BANKING_HIGH_RISK]
    financial_score = sum(BANKING_HIGH_RISK.get(r.permission, 0) * r.risk_score for r in banking_risks) / max(len(banking_risks), 1)

    # Findings
    findings = []
    for risk in dangerous_risks + signature_risks + custom_risks:
        findings.append(Finding(
            id=f"perm_risk:{risk.permission}",
            type="permission_risk",
            severity=risk.severity,
            confidence=risk.confidence,
            title=f"Permission risk: {risk.permission}",
            description=risk.rationale,
            evidence_refs=risk.evidence_refs,
            mitre_techniques=risk.mitre_techniques,
            owasp_mobile=risk.owasp_categories,
        ))

    return PermissionAnalysis(
        total_permissions=len(permissions),
        dangerous_permissions=dangerous_risks,
        signature_permissions=signature_risks,
        custom_permissions=custom_risks,
        normal_permissions=normal_risks,
        permission_groups=groups,
        banking_relevant_permissions=banking_risks,
        financial_risk_score=financial_score,
        findings=findings,
    )


def _assess_permission_risk(permission: str, used_in_code: bool) -> PermissionRisk:
    """Assess risk for a single permission."""
    if permission in BANKING_HIGH_RISK:
        base_score = BANKING_HIGH_RISK[permission]
        severity = _score_to_severity(base_score)
        confidence = Confidence.very_high if used_in_code else Confidence.high
        rationale = f"High-risk banking malware permission. {'Actively used in code.' if used_in_code else 'Declared but code usage unconfirmed.'}"
        mitre = _get_mitre_for_permission(permission)
        owasp = _get_owasp_for_permission(permission)
    else:
        base_score = 0.1
        severity = Severity.low
        confidence = Confidence.medium
        rationale = "Standard permission with limited abuse potential."
        mitre = []
        owasp = []

    if used_in_code:
        base_score = min(1.0, base_score * 1.2)
        severity = _score_to_severity(base_score)

    return PermissionRisk(
        permission=permission,
        protection_level="dangerous" if permission in BANKING_HIGH_RISK else "normal",
        risk_score=base_score,
        severity=severity,
        confidence=confidence,
        rationale=rationale,
        mitre_techniques=mitre,
        owasp_categories=owasp,
        evidence_refs=[EvidenceRef(extractor="permissions", path="permissions")],
        is_runtime_requested=True,
        is_used_by_component=used_in_code,
    )


def _score_to_severity(score: float) -> Severity:
    if score >= 0.8:
        return Severity.critical
    elif score >= 0.6:
        return Severity.high
    elif score >= 0.4:
        return Severity.medium
    elif score >= 0.2:
        return Severity.low
    return Severity.info


def _get_mitre_for_permission(permission: str) -> list[str]:
    mapping = {
        "android.permission.BIND_ACCESSIBILITY_SERVICE": ["T1417.001"],
        "android.permission.SYSTEM_ALERT_WINDOW": ["T1417.002"],
        "android.permission.RECEIVE_SMS": ["T1636.004"],
        "android.permission.READ_SMS": ["T1636.004"],
        "android.permission.SEND_SMS": ["T1582"],
        "android.permission.REQUEST_INSTALL_PACKAGES": ["T1476"],
        "android.permission.BIND_DEVICE_ADMIN": ["T1626"],
        "android.permission.READ_CONTACTS": ["T1636.003"],
        "android.permission.RECORD_AUDIO": ["T1429"],
        "android.permission.ACCESS_FINE_LOCATION": ["T1430"],
    }
    return mapping.get(permission, [])


def _get_owasp_for_permission(permission: str) -> list[str]:
    mapping = {
        "android.permission.BIND_ACCESSIBILITY_SERVICE": ["M1"],
        "android.permission.SYSTEM_ALERT_WINDOW": ["M1"],
        "android.permission.RECEIVE_SMS": ["M1"],
        "android.permission.READ_SMS": ["M1"],
        "android.permission.SEND_SMS": ["M1"],
        "android.permission.REQUEST_INSTALL_PACKAGES": ["M1"],
        "android.permission.BIND_DEVICE_ADMIN": ["M1"],
        "android.permission.READ_CONTACTS": ["M2"],
        "android.permission.RECORD_AUDIO": ["M2"],
        "android.permission.ACCESS_FINE_LOCATION": ["M2"],
    }
    return mapping.get(permission, [])


def _get_capabilities(group: str, risks: list[PermissionRisk]) -> list[str]:
    caps = {
        "SMS": ["intercept_2fa", "send_premium_sms", "spread_via_sms"],
        "CALL_LOG": ["call_metadata_harvest", "call_fraud"],
        "CONTACTS": ["contact_harvest", "social_engineering"],
        "LOCATION": ["location_tracking", "geofencing"],
        "MICROPHONE": ["audio_surveillance", "call_recording"],
        "CAMERA": ["photo_capture", "video_surveillance"],
        "STORAGE": ["file_exfiltration", "data_theft"],
        "PHONE": ["call_fraud", "call_interception"],
        "DEVICE_ADMIN": ["persistence", "factory_reset_block", "screen_lock"],
        "ACCESSIBILITY": ["keylogging", "screen_reading", "ui_injection", "auto_click"],
        "OVERLAY": ["phishing_overlay", "clickjacking"],
        "INSTALL_PACKAGES": ["dropper", "payload_delivery"],
        "NETWORK": ["c2_communication", "data_exfil"],
        "BLUETOOTH": ["proximity_attack", "bluetooth_exploit"],
        "NFC": ["nfc_relay", "payment_theft"],
    }
    return caps.get(group, [])
```