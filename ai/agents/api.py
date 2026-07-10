"""API Agent - Analyzes dangerous API usage patterns in decompiled code."""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel

from ai.schemas.base import Finding, Severity, Confidence, EvidenceRef
from ai.schemas.api import APIAnalysis, APICall, DangerousAPI
from ai.agents.base import BaseAgent, AgentConfig, AgentResult


DANGEROUS_API_SIGNATURES = {
    "crypto_misuse": {
        "patterns": [
            "Cipher.getInstance.*ECB",
            "MessageDigest.getInstance.*MD5",
            "MessageDigest.getInstance.*SHA1",
            "SecretKeySpec.*",
            "IvParameterSpec.*0{16}",
            "SecureRandom.*setSeed",
        ],
        "severity": Severity.high,
        "mitre": ["T1573.001"],
        "owasp": ["M5"],
        "description": "Weak cryptographic implementation",
    },
    "reflection_abuse": {
        "patterns": [
            "Class.forName.*",
            "Method.invoke.*",
            "Field.setAccessible.*true",
            "Constructor.newInstance.*",
            "DexClassLoader",
            "PathClassLoader",
            "InMemoryDexClassLoader",
        ],
        "severity": Severity.high,
        "mitre": ["T1027.004", "T1127.001"],
        "owasp": ["M7", "M8"],
        "description": "Dynamic code loading and reflection abuse",
    },
    "native_code": {
        "patterns": [
            "System.loadLibrary.*",
            "System.load.*",
            "Runtime.loadLibrary.*",
            "Runtime.load.*",
            "JNI_OnLoad",
        ],
        "severity": Severity.medium,
        "mitre": ["T1127.001"],
        "owasp": ["M7"],
        "description": "Native library loading - potential rootkit or anti-analysis",
    },
    "sms_intercept": {
        "patterns": [
            "SmsManager.sendTextMessage",
            "SmsManager.sendMultipartTextMessage",
            "Telephony.Sms.Intents.SMS_RECEIVED_ACTION",
            "abortBroadcast.*SMS",
        ],
        "severity": Severity.critical,
        "mitre": ["T1636.004"],
        "owasp": ["M1"],
        "description": "SMS interception and sending - 2FA bypass",
    },
    "overlay_attack": {
        "patterns": [
            "TYPE_APPLICATION_OVERLAY",
            "SYSTEM_ALERT_WINDOW",
            "WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE",
            "WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL",
            "WindowManager.LayoutParams.FLAG_WATCH_OUTSIDE_TOUCH",
        ],
        "severity": Severity.critical,
        "mitre": ["T1417.002"],
        "owasp": ["M1"],
        "description": "Overlay attack for credential phishing",
    },
    "accessibility_abuse": {
        "patterns": [
            "AccessibilityService",
            "onAccessibilityEvent",
            "performGlobalAction",
            "dispatchGesture",
            "AccessibilityNodeInfo.ACTION_CLICK",
            "AccessibilityNodeInfo.ACTION_SCROLL_FORWARD",
            "setOnClickListener.*Accessibility",
        ],
        "severity": Severity.critical,
        "mitre": ["T1417.001"],
        "owasp": ["M1"],
        "description": "Accessibility service abuse for keylogging and UI injection",
    },
    "device_admin": {
        "patterns": [
            "DevicePolicyManager",
            "DeviceAdminReceiver",
            "setPasswordMinimumLength",
            "lockNow",
            "wipeData",
            "resetPassword",
            "setMaximumFailedPasswordsForWipe",
        ],
        "severity": Severity.high,
        "mitre": ["T1626"],
        "owasp": ["M1"],
        "description": "Device admin abuse for persistence and lockout",
    },
    "network_exfil": {
        "patterns": [
            "OkHttpClient.*",
            "Retrofit.*",
            "HttpURLConnection.*",
            "HttpsURLConnection.*",
            "Socket.*",
            "SSLSocketFactory.*",
            "TrustManager.*",
            "X509TrustManager.*",
            "HostnameVerifier.*",
            "allowAllHostnameVerifier",
        ],
        "severity": Severity.medium,
        "mitre": ["T1041", "T1573.001"],
        "owasp": ["M3", "M5"],
        "description": "Network communication - potential C2 or data exfiltration",
    },
    "certificate_pinning_bypass": {
        "patterns": [
            "TrustManager.*checkServerTrusted.*",
            "X509TrustManager.*",
            "SSLContext.init.*null",
            "OkHttpClient.Builder.*certificatePinner",
            "CertificatePinner.*",
        ],
        "severity": Severity.high,
        "mitre": ["T1573.001"],
        "owasp": ["M3", "M5"],
        "description": "Certificate pinning implementation or bypass",
    },
    "file_exfiltration": {
        "patterns": [
            "FileOutputStream.*",
            "FileInputStream.*",
            "openFileOutput.*",
            "openFileInput.*",
            "getExternalFilesDir.*",
            "getExternalCacheDir.*",
            "MediaStore.*",
            "DocumentsContract.*",
        ],
        "severity": Severity.medium,
        "mitre": ["T1005", "T1041"],
        "owasp": ["M2"],
        "description": "File system access - potential data collection/exfiltration",
    },
    "ipc_abuse": {
        "patterns": [
            "sendBroadcast.*",
            "sendOrderedBroadcast.*",
            "registerReceiver.*",
            "ContentResolver.query.*",
            "ContentResolver.insert.*",
            "ContentResolver.delete.*",
            "ContentResolver.update.*",
            "Binder.*",
            "Messenger.*",
            "AIDL.*",
        ],
        "severity": Severity.medium,
        "mitre": ["T1417"],
        "owasp": ["M1"],
        "description": "IPC mechanism abuse for component hijacking",
    },
    "runtime_execution": {
        "patterns": [
            "Runtime.getRuntime().exec",
            "ProcessBuilder.*",
            "Runtime.exec.*",
            "su ",
            "/system/bin/sh",
            "/system/xbin/su",
        ],
        "severity": Severity.high,
        "mitre": ["T1059.004"],
        "owasp": ["M7"],
        "description": "Shell command execution - root exploit or system modification",
    },
    "keystore_access": {
        "patterns": [
            "KeyStore.getInstance.*",
            "KeyPairGenerator.*",
            "KeyGenerator.*",
            "Cipher.*init.*",
            "KeyStore.LoadStoreParameter",
            "AndroidKeyStore",
        ],
        "severity": Severity.low,
        "mitre": [],
        "owasp": ["M5"],
        "description": "Keystore operations - legitimate or key extraction",
    },
    "logging_sensitive": {
        "patterns": [
            "Log.d.*password",
            "Log.i.*token",
            "Log.v.*secret",
            "Log.w.*key",
            "System.out.println.*password",
            "System.err.println.*token",
        ],
        "severity": Severity.low,
        "mitre": [],
        "owasp": ["M2"],
        "description": "Sensitive data in logs",
    },
}


class APIAgent(BaseAgent[APIAnalysis]):
    """Analyzes dangerous API usage patterns with context and data flow."""

    def __init__(self, llm_client: Any = None):
        config = AgentConfig(
            name="api_agent",
            model="claude-3-5-sonnet-20241022",
            temperature=0.1,
            max_tokens=8192,
            output_schema=APIAnalysis,
            system_prompt=self._get_system_prompt(),
        )
        super().__init__(config, llm_client)

    def _get_system_prompt(self) -> str:
        return """You are a senior Android security analyst specializing in API usage analysis.
Your task is to analyze dangerous API call patterns extracted from decompiled code and determine:

1. Which dangerous APIs are actually called (not just referenced)
2. Call sites - which methods call these APIs
3. Data flow - what data flows into/out of these APIs
4. Reflection vs direct calls
5. Dynamic loading patterns
6. Native library usage

For each dangerous API finding, provide:
- API class, method, package
- Call sites (method signatures that call this API)
- Data flow traces (tainted variables)
- Whether called via reflection or dynamic loading
- Severity based on context (not just API type)
- MITRE ATT&CK and OWASP Mobile mappings
- Evidence reference to code_intel extractor output

Output must conform to the APIAnalysis schema."""

    def build_prompt(self, evidence: dict[str, Any], context: dict[str, Any]) -> str:
        code_intel = evidence.get("code_intel", {})
        api_usage = code_intel.get("api_usage", {})
        call_graph = code_intel.get("call_graph", {})
        summarizer = code_intel.get("summarizer", {})

        prompt = f"""Analyze the following API usage intelligence:

=== CODE SUMMARY ===
{json.dumps(summarizer.get("code_summary", {}), indent=2)}

=== DANGEROUS APIS DETECTED ===
{json.dumps(api_usage.get("dangerous_apis", []), indent=2)}

=== CALL SITES ===
{json.dumps(api_usage.get("call_sites", []), indent=2)}

=== REFLECTION USAGE ===
{json.dumps(api_usage.get("reflection_usage", []), indent=2)}

=== DYNAMIC LOADING ===
{json.dumps(api_usage.get("dynamic_loading", []), indent=2)}

=== NATIVE LIBRARIES ===
{json.dumps(api_usage.get("native_libraries", []), indent=2)}

=== CALL GRAPH ===
Nodes: {len(call_graph.get("nodes", []))}
Edges: {len(call_graph.get("edges", []))}
Entry Points: {call_graph.get("entry_points", [])}
Sinks: {call_graph.get("sinks", [])}

=== DANGEROUS API SIGNATURES REFERENCE ===
{json.dumps({k: {**v, "severity": v["severity"].value} for k, v in DANGEROUS_API_SIGNATURES.items()}, indent=2)}

Analyze and output a complete APIAnalysis object with:
1. APICall for each dangerous API with call sites and data flow
2. DangerousAPI for each category with severity assessment
3. Findings with evidence references
4. Context-aware severity (e.g., SMS API in a banking app = critical)"""
        return prompt

    def parse_output(self, raw_output: str) -> APIAnalysis:
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            import re
            match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', raw_output, re.DOTALL)
            if match:
                data = json.loads(match.group(1))
            else:
                raise ValueError("Could not parse agent output as JSON")

        return APIAnalysis(**data)

    def extract_findings(self, output: APIAnalysis) -> list[Finding]:
        findings = []
        for api_call in output.api_calls:
            findings.append(Finding(
                id=f"api_{api_call.api_class}_{api_call.api_method}",
                type="dangerous_api",
                severity=api_call.severity,
                confidence=api_call.confidence,
                title=f"Dangerous API: {api_call.api_class}.{api_call.api_method}",
                description=f"API called from {len(api_call.call_sites)} site(s). Data flow: {len(api_call.data_flow)} trace(s). Reflection: {api_call.is_reflection}, Dynamic: {api_call.is_dynamic_loading}",
                evidence_refs=[EvidenceRef(extractor="api_usage", path="call_sites")],
                mitre_techniques=api_call.mitre_techniques,
                owasp_mobile=api_call.owasp_categories,
                metadata={
                    "api_class": api_call.api_class,
                    "api_method": api_call.api_method,
                    "call_sites": api_call.call_sites,
                    "is_reflection": api_call.is_reflection,
                    "is_dynamic_loading": api_call.is_dynamic_loading,
                }
            ))
        return findings
