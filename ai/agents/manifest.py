"""Manifest Agent - Analyzes AndroidManifest.xml for security issues."""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel

from ai.schemas.base import Finding, Severity, Confidence, EvidenceRef
from ai.schemas.manifest import ManifestAnalysis, ComponentInfo, PermissionFinding
from ai.agents.base import BaseAgent, AgentConfig, AgentResult


# Dangerous permissions with MITRE/OWASP mapping
DANGEROUS_PERMISSIONS = {
    "android.permission.BIND_ACCESSIBILITY_SERVICE": (
        Severity.critical, Confidence.very_high,
        ["T1417.001"], ["M1"],
        "Enables keylogging, screen reading, and UI interaction injection"
    ),
    "android.permission.SYSTEM_ALERT_WINDOW": (
        Severity.high, Confidence.high,
        ["T1417.002"], ["M1"],
        "Allows overlay attacks for credential phishing"
    ),
    "android.permission.RECEIVE_SMS": (
        Severity.high, Confidence.high,
        ["T1636.004"], ["M1"],
        "Intercepts SMS-based 2FA codes"
    ),
    "android.permission.READ_SMS": (
        Severity.high, Confidence.high,
        ["T1636.004"], ["M1"],
        "Reads SMS messages including 2FA"
    ),
    "android.permission.SEND_SMS": (
        Severity.high, Confidence.medium,
        ["T1582"], ["M1"],
        "Sends premium SMS or spreads malware"
    ),
    "android.permission.REQUEST_INSTALL_PACKAGES": (
        Severity.high, Confidence.high,
        ["T1476"], ["M1"],
        "Installs additional payloads without user consent"
    ),
    "android.permission.BIND_DEVICE_ADMIN": (
        Severity.high, Confidence.high,
        ["T1626"], ["M1"],
        "Gains device admin privileges for persistence"
    ),
    "android.permission.READ_CONTACTS": (
        Severity.medium, Confidence.high,
        ["T1636.003"], ["M2"],
        "Harvests contact list for social engineering"
    ),
    "android.permission.RECORD_AUDIO": (
        Severity.medium, Confidence.medium,
        ["T1429"], ["M2"],
        "Records ambient audio and calls"
    ),
    "android.permission.ACCESS_FINE_LOCATION": (
        Severity.medium, Confidence.medium,
        ["T1430"], ["M2"],
        "Tracks precise device location"
    ),
    "android.permission.CAMERA": (
        Severity.medium, Confidence.medium,
        ["T1429"], ["M2"],
        "Captures photos/video without indication"
    ),
    "android.permission.CALL_PHONE": (
        Severity.medium, Confidence.medium,
        ["T1582"], ["M1"],
        "Initiates phone calls (premium numbers)"
    ),
    "android.permission.READ_CALL_LOG": (
        Severity.medium, Confidence.medium,
        ["T1636.003"], ["M2"],
        "Accesses call history"
    ),
    "android.permission.WRITE_EXTERNAL_STORAGE": (
        Severity.low, Confidence.low,
        ["T1005"], ["M2"],
        "Broad file system access (legacy)"
    ),
}


class ManifestAgent(BaseAgent[ManifestAnalysis]):
    """Analyzes Android manifest for security-relevant declarations."""
    
    def __init__(self, llm_client: Any = None):
        config = AgentConfig(
            name="manifest_agent",
            model="claude-3-5-sonnet-20241022",
            temperature=0.1,
            max_tokens=4096,
            output_schema=ManifestAnalysis,
            system_prompt=self._get_system_prompt(),
        )
        super().__init__(config, llm_client)
    
    def _get_system_prompt(self) -> str:
        return """You are a senior Android security analyst specializing in manifest analysis.
Your task is to analyze AndroidManifest.xml data extracted from an APK and identify
security-relevant declarations, permissions, and configuration issues.

Focus on:
1. Dangerous permissions and their abuse potential
2. Exported components (activities, services, receivers, providers) that could be attacked
3. Debuggable/allowBackup flags
4. Network security configuration
5. Certificate details
6. Custom permissions that could be abused

For each finding, provide:
- Clear severity (critical/high/medium/low/info)
- Confidence level
- MITRE ATT&CK technique mappings
- OWASP Mobile Top 10 mappings
- Evidence reference to the manifest extractor output

Output must conform to the ManifestAnalysis schema."""
    
    def build_prompt(self, evidence: dict[str, Any], context: dict[str, Any]) -> str:
        manifest_evidence = evidence.get("manifest", {})
        permission_evidence = evidence.get("permissions", {})
        component_evidence = evidence.get("components", {})
        cert_evidence = evidence.get("certificate", {})
        
        prompt = f"""Analyze the following Android manifest data:

PACKAGE INFO:
- Package: {manifest_evidence.get('package_name', 'unknown')}
- Version: {manifest_evidence.get('version_name', 'unknown')} ({manifest_evidence.get('version_code', 'unknown')})
- Min SDK: {manifest_evidence.get('min_sdk', 'unknown')}
- Target SDK: {manifest_evidence.get('target_sdk', 'unknown')}
- Main Activity: {manifest_evidence.get('main_activity', 'unknown')}

PERMISSIONS ({permission_evidence.get('count', 0)} total):
{json.dumps(permission_evidence.get('permissions', []), indent=2)}

COMPONENTS:
- Activities: {component_evidence.get('counts', {}).get('activities', 0)}
- Services: {component_evidence.get('counts', {}).get('services', 0)}
- Receivers: {component_evidence.get('counts', {}).get('receivers', 0)}
- Providers: {component_evidence.get('counts', {}).get('providers', 0)}

Activities:
{json.dumps(component_evidence.get('activities', []), indent=2)}

Services:
{json.dumps(component_evidence.get('services', []), indent=2)}

Receivers:
{json.dumps(component_evidence.get('receivers', []), indent=2)}

Providers:
{json.dumps(component_evidence.get('providers', []), indent=2)}

Intent Filters:
{json.dumps(component_evidence.get('intent_filters', {}), indent=2)}

CERTIFICATES:
{json.dumps(cert_evidence.get('certificates', []), indent=2)}

KNOWN DANGEROUS PERMISSIONS REFERENCE:
{json.dumps({k: {"severity": v[0].value, "confidence": v[1].value, "mitre": v[2], "owasp": v[3], "rationale": v[4]} for k, v in DANGEROUS_PERMISSIONS.items()}, indent=2)}

Analyze and output a complete ManifestAnalysis object."""
        return prompt
    
    def parse_output(self, raw_output: str) -> ManifestAnalysis:
        # Try to parse as JSON first
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            # Try to extract JSON from markdown code block
            import re
            match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', raw_output, re.DOTALL)
            if match:
                data = json.loads(match.group(1))
            else:
                raise ValueError("Could not parse agent output as JSON")
        
        # Validate and construct
        return ManifestAnalysis(**data)
    
    def extract_findings(self, output: ManifestAnalysis) -> list[Finding]::
        findings = []
        findings.extend(output.permissions)  # PermissionFinding extends Finding
        
        # Add component findings
        for comp in output.components:
            if comp.exported and comp.component_type in ("activity", "service", "receiver", "provider"):
                findings.append(Finding(
                    id=f"exported_{comp.component_type}_{comp.name}",
                    type="exported_component",
                    severity=Severity.medium,
                    confidence=Confidence.high,
                    title=f"Exported {comp.component_type}: {comp.name}",
                    description=f"Component {comp.name} is exported and accessible by other apps",
                    evidence_refs=[EvidenceRef(extractor="components", path=f"{comp.component_type}s")],
                    mitre_techniques=["T1417"],
                    owasp_mobile=["M1"],
                ))
        
        # Debuggable finding
        if output.debuggable:
            findings.append(Finding(
                id="debuggable_true",
                type="debuggable",
                severity=Severity.medium,
                confidence=Confidence.very_high,
                title="Application is debuggable",
                description="android:debuggable=true allows runtime attachment and debugging",
                evidence_refs=[EvidenceRef(extractor="manifest", path="debuggable")],
                mitre_techniques=["T1562.001"],
                owasp_mobile=["M7"],
            ))
        
        # Allow backup finding
        if output.allow_backup:
            findings.append(Finding(
                id="allow_backup_true",
                type="backup_allowed",
                severity=Severity.low,
                confidence=Confidence.high,
                title="Backup allowed",
                description="android:allowBackup=true permits data extraction via adb backup",
                evidence_refs=[EvidenceRef(extractor="manifest", path="allow_backup")],
                mitre_techniques=["T1005"],
                owasp_mobile=["M2"],
            ))
        
        return findings


# Standalone analysis function for non-LLM path
def analyze_manifest_deterministic(evidence: dict[str, Any]) -> ManifestAnalysis:
    """Deterministic manifest analysis without LLM."""
    manifest_evidence = evidence.get("manifest", {})
    permission_evidence = evidence.get("permissions", {})
    component_evidence = evidence.get("components", {})
    cert_evidence = evidence.get("certificate", {})
    
    permissions = permission_evidence.get("permissions", [])
    permission_findings = []
    
    for perm in permissions:
        if perm in DANGEROUS_PERMISSIONS:
            sev, conf, mitre, owasp, rationale = DANGEROUS_PERMISSIONS[perm]
            permission_findings.append(PermissionFinding(
                id=f"perm:{perm}",
                type="permission",
                severity=sev,
                confidence=conf,
                title=f"Dangerous permission: {perm}",
                description=rationale,
                permission_name=perm,
                protection_level="dangerous",
                risk_rationale=rationale,
                evidence_refs=[EvidenceRef(extractor="permissions", path="permissions")],
                mitre_techniques=mitre,
                owasp_mobile=owasp,
            ))
    
    components = []
    for comp_type in ("activities", "services", "receivers", "providers"):
        for name in component_evidence.get(comp_type, []):
            # Check if exported via intent filters
            exported = False
            intent_filters = {}
            if name in component_evidence.get("intent_filters", {}):
                exported = True
                intent_filters = component_evidence["intent_filters"][name]
            components.append(ComponentInfo(
                name=name,
                component_type=comp_type.rstrip("s"),
                exported=exported,
                intent_filters=intent_filters,
            ))
    
    # Certificates
    certs = cert_evidence.get("certificates", [])
    debug_cert = any("Android Debug" in c.get("subject", "") for c in certs)
    
    return ManifestAnalysis(
        package_name=manifest_evidence.get("package_name", "unknown"),
        version_name=manifest_evidence.get("version_name"),
        version_code=manifest_evidence.get("version_code"),
        min_sdk=manifest_evidence.get("min_sdk"),
        target_sdk=manifest_evidence.get("target_sdk"),
        max_sdk=manifest_evidence.get("max_sdk"),
        permissions=permission_findings,
        components=components,
        debuggable=manifest_evidence.get("debuggable", False),
        allow_backup=manifest_evidence.get("allow_backup", True),
        uses_cleartext_traffic=manifest_evidence.get("uses_cleartext_traffic", False),
        network_security_config=manifest_evidence.get("network_security_config"),
        certificates=certs,
    )