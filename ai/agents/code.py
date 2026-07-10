"""Code Agent - Analyzes decompiled Java/Smali code for malicious patterns."""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel

from ai.schemas.base import Finding, Severity, Confidence, EvidenceRef
from ai.schemas.code import CodeAnalysis, CodeSummary, ClassInfo, MethodInfo, CallGraph, CallGraphEdge, ControlFlowFinding, APIUsageFinding
from ai.agents.base import BaseAgent, AgentConfig, AgentResult


DANGEROUS_API_PACKAGES = {
    "crypto": [
        "javax.crypto",
        "java.security",
        "android.security.keystore",
    ],
    "reflection": [
        "java.lang.reflect",
        "dalvik.system.DexClassLoader",
        "dalvik.system.PathClassLoader",
    ],
    "native": [
        "java.lang.System.load",
        "java.lang.System.loadLibrary",
        "java.lang.Runtime.load",
        "java.lang.Runtime.loadLibrary",
    ],
    "sms": [
        "android.telephony.SmsManager",
        "android.provider.Telephony.Sms",
    ],
    "overlay": [
        "android.view.WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY",
        "android.permission.SYSTEM_ALERT_WINDOW",
    ],
    "accessibility": [
        "android.accessibilityservice.AccessibilityService",
        "android.view.accessibility.AccessibilityEvent",
    ],
    "device_admin": [
        "android.app.admin.DevicePolicyManager",
        "android.app.admin.DeviceAdminReceiver",
    ],
    "network": [
        "java.net.Socket",
        "java.net.URL",
        "javax.net.ssl.HttpsURLConnection",
        "okhttp3.OkHttpClient",
        "retrofit2.Retrofit",
    ],
    "file_io": [
        "java.io.FileOutputStream",
        "java.io.FileInputStream",
        "android.content.Context.openFileOutput",
        "android.content.Context.openFileInput",
    ],
    "ipc": [
        "android.content.Intent",
        "android.content.BroadcastReceiver",
        "android.app.Service",
        "android.content.ContentProvider",
        "android.os.Binder",
        "android.os.Messenger",
    ],
    "logging": [
        "android.util.Log",
        "java.lang.System.out",
        "java.lang.System.err",
    ],
    "runtime_exec": [
        "java.lang.Runtime.exec",
        "java.lang.ProcessBuilder",
    ],
    "dex_manipulation": [
        "dalvik.system.DexFile",
        "dalvik.system.DexClassLoader",
        "dalvik.system.InMemoryDexClassLoader",
    ],
}


class CodeAgent(BaseAgent[CodeAnalysis]):
    """Analyzes decompiled code for malicious patterns and suspicious behaviors."""

    def __init__(self, llm_client: Any = None):
        config = AgentConfig(
            name="code_agent",
            model="claude-3-5-sonnet-20241022",
            temperature=0.1,
            max_tokens=8192,
            output_schema=CodeAnalysis,
            system_prompt=self._get_system_prompt(),
        )
        super().__init__(config, llm_client)

    def _get_system_prompt(self) -> str:
        return """You are a senior Android malware analyst specializing in static code analysis.
Your task is to analyze decompiled Java/Smali code extracted from an APK and identify:

1. Dangerous API usage (crypto, reflection, native loading, SMS, overlay, accessibility, device admin, network, file I/O, IPC, runtime exec, dex manipulation)
2. Control flow anomalies (unreachable code, infinite loops, exception swallowing, dead code, obfuscation indicators)
3. Suspicious patterns (string encryption, class encryption, anti-analysis, anti-debugging, emulator detection)
4. Banking-specific patterns (overlay attacks, accessibility abuse, SMS interception, keylogging, screen recording)
5. Call graph analysis - entry points, sinks, data flow

For each finding, provide:
- Clear severity (critical/high/medium/low/info)
- Confidence level
- MITRE ATT&CK technique mappings
- OWASP Mobile Top 10 mappings
- Evidence reference to the code_intel extractor output
- Call sites and data flow traces where applicable

Output must conform to the CodeAnalysis schema with CodeSummary optimized for LLM consumption."""

    def build_prompt(self, evidence: dict[str, Any], context: dict[str, Any]) -> str:
        static_evidence = evidence.get("static_evidence", {})
        code_intel_evidence = evidence.get("code_intel", {})

        smali_evidence = static_evidence.get("smali", {})
        decompiled_evidence = static_evidence.get("decompiled_java", {})
        strings_evidence = static_evidence.get("strings", {})
        hashes_evidence = static_evidence.get("hashes", {})

        api_usage = code_intel_evidence.get("api_usage", {})
        call_graph = code_intel_evidence.get("call_graph", {})
        control_flow = code_intel_evidence.get("control_flow", {})
        class_filter = code_intel_evidence.get("class_filter", {})
        summarizer = code_intel_evidence.get("summarizer", {})

        prompt = f"""Analyze the following decompiled code intelligence:

=== CODE INTELLIGENCE SUMMARY ===
{json.dumps(summarizer.get("code_summary", {}), indent=2)}

=== CLASS FILTER RESULTS ===
App classes (non-framework): {class_filter.get("app_class_count", 0)}
Framework classes filtered: {class_filter.get("framework_class_count", 0)}
Third-party libraries filtered: {class_filter.get("library_class_count", 0)}

=== DANGEROUS API USAGE ===
{json.dumps(api_usage.get("dangerous_apis", []), indent=2)}

API Call Sites:
{json.dumps(api_usage.get("call_sites", []), indent=2)}

Reflection Usage:
{json.dumps(api_usage.get("reflection_usage", []), indent=2)}

Dynamic Loading:
{json.dumps(api_usage.get("dynamic_loading", []), indent=2)}

Native Libraries:
{json.dumps(api_usage.get("native_libraries", []), indent=2)}

=== CALL GRAPH ===
Nodes: {len(call_graph.get("nodes", []))}
Edges: {len(call_graph.get("edges", []))}
Entry Points: {call_graph.get("entry_points", [])}
Sinks: {call_graph.get("sinks", [])}

=== CONTROL FLOW ANOMALIES ===
{json.dumps(control_flow.get("anomalies", []), indent=2)}

=== EXTRACTED STRINGS (sample) ===
Total strings: {strings_evidence.get("count", 0)}
High entropy strings: {strings_evidence.get("high_entropy_count", 0)}
Suspicious strings: {json.dumps(strings_evidence.get("suspicious", [])[:50], indent=2)}

=== HASHES ===
SSDEEP: {hashes_evidence.get("ssdeep", "N/A")}
TLSH: {hashes_evidence.get("tlsh", "N/A")}

=== DANGEROUS API REFERENCE ===
{json.dumps({k: v for k, v in DANGEROUS_API_PACKAGES.items()}, indent=2)}

Analyze and output a complete CodeAnalysis object with:
1. ControlFlowFinding for each control flow anomaly
2. APIUsageFinding for each dangerous API usage with call sites and data flow
3. CodeSummary with token-optimized summary for downstream agents
4. ClassInfo for key app classes (entry points, suspicious classes)
5. CallGraph with nodes, edges, entry points, sinks"""
        return prompt

    def parse_output(self, raw_output: str) -> CodeAnalysis:
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            import re
            match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', raw_output, re.DOTALL)
            if match:
                data = json.loads(match.group(1))
            else:
                raise ValueError("Could not parse agent output as JSON")

        return CodeAnalysis(**data)

    def extract_findings(self, output: CodeAnalysis) -> list[Finding]:
        findings = []
        findings.extend(output.control_flow_findings)
        findings.extend(output.api_usage_findings)
        return findings
```