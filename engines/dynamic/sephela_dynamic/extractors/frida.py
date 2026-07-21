"""Frida trace extractor — parses runtime API hook logs.

Reads ``frida_trace.json`` (a structured log of intercepted Java API calls)
produced by the Frida instrumentation script (``infra/sandbox/frida_hooks.js``).

Detection capabilities:
- **Cryptographic operations**: Cipher.init, SecretKeySpec, MessageDigest
- **Dynamic class loading**: DexClassLoader, PathClassLoader, loadClass
- **Reflection chains**: Class.forName → getMethod → invoke
- **SMS interception**: SmsManager.sendTextMessage, SMS broadcast receivers
- **Accessibility abuse**: AccessibilityService API calls
- **Device fingerprinting**: TelephonyManager, Build.*, IMEI/IMSI reads

Security note: All log content is treated as hostile data (an APK could
craft strings to poison logs). We validate structure via Pydantic and never
``eval`` or render content as code.
"""

from __future__ import annotations

import json
from collections import Counter
from typing import Any

from sephela_dynamic.base import ArtifactsContext, DynamicExtractor, ExtractorResult
from sephela_dynamic.envelope import (
    Finding,
    FindingType,
    Mappings,
    Provenance,
    Severity,
)
from sephela_dynamic.schemas import FridaHookEntry, FridaHookType, FridaTrace

# Maps hook types to finding metadata
_HOOK_SEVERITY: dict[FridaHookType, tuple[Severity, FindingType, str, list[str]]] = {
    FridaHookType.crypto: (
        Severity.medium,
        FindingType.crypto,
        "Runtime cryptographic operation detected",
        ["T1573"],  # Encrypted Channel
    ),
    FridaHookType.reflection: (
        Severity.high,
        FindingType.evasion,
        "Runtime reflection chain detected",
        ["T1620"],  # Reflective Code Loading
    ),
    FridaHookType.dex_loading: (
        Severity.critical,
        FindingType.dynamic_load,
        "Dynamic DEX/class loading at runtime",
        ["T1620"],  # Reflective Code Loading
    ),
    FridaHookType.sms: (
        Severity.critical,
        FindingType.sms,
        "Runtime SMS operation (send/intercept)",
        ["T1636.004"],  # SMS Control
    ),
    FridaHookType.network: (
        Severity.medium,
        FindingType.network,
        "Runtime network connection",
        ["T1071"],  # Application Layer Protocol
    ),
    FridaHookType.accessibility: (
        Severity.critical,
        FindingType.behavior,
        "Accessibility service abuse detected",
        ["T1453"],  # Abuse Accessibility Features
    ),
    FridaHookType.device_info: (
        Severity.low,
        FindingType.behavior,
        "Device fingerprinting (IMEI/IMSI/Build info)",
        ["T1426"],  # System Information Discovery
    ),
    FridaHookType.file_io: (
        Severity.low,
        FindingType.file_access,
        "File system access at runtime",
        ["T1533"],  # Data from Local System
    ),
    FridaHookType.process: (
        Severity.high,
        FindingType.evasion,
        "Process manipulation at runtime",
        ["T1407"],  # Download New Code at Runtime
    ),
}

# Suspicious crypto patterns (key sizes, algorithms)
_SUSPICIOUS_CRYPTO: set[str] = {
    "AES", "DES", "RSA", "Blowfish", "RC4",
}


class FridaExtractor(DynamicExtractor):
    """Parse Frida hook traces into structured findings."""

    name = "frida"
    required_artifacts = ["frida_trace.json"]

    def extract(self, ctx: ArtifactsContext) -> ExtractorResult:
        """Parse frida_trace.json and emit findings per hook category.

        Args:
            ctx: Artifacts context with the sandbox output directory.

        Returns:
            Structured evidence with hook statistics and categorised findings.
        """
        raw = ctx.read_artifact("frida_trace.json")
        if raw is None:
            return ExtractorResult(
                evidence={"error": "frida_trace.json not found"},
            )

        data = json.loads(raw)
        trace = FridaTrace.model_validate(data)

        # Aggregate hooks by type
        type_counts: Counter[str] = Counter()
        findings: list[Finding] = []
        hook_details: list[dict[str, Any]] = []

        for entry in trace.entries:
            type_counts[entry.hook_type.value] += 1
            hook_details.append({
                "timestamp_ms": entry.timestamp_ms,
                "hook_type": entry.hook_type.value,
                "class": entry.class_name,
                "method": entry.method_name,
                "args_preview": entry.args[:3],  # truncate for safety
            })

        # Emit one finding per observed hook category
        for hook_type, count in type_counts.items():
            ht = FridaHookType(hook_type)
            meta = _HOOK_SEVERITY.get(ht)
            if meta is None:
                continue

            severity, finding_type, description, mitre = meta
            findings.append(Finding(
                id=f"dyn_frida_{hook_type}_{count}",
                type=finding_type,
                severity=severity,
                confidence=min(0.5 + (count * 0.05), 0.95),
                detail=f"{description}: {count} call(s) observed at runtime.",
                provenance=Provenance(extractor=self.name),
                mappings=Mappings(mitre=mitre),
            ))

        # Detect specific high-value patterns
        findings.extend(self._detect_patterns(trace.entries))

        evidence: dict[str, object] = {
            "total_hooks": trace.total_hooks,
            "hook_type_counts": dict(type_counts),
            "unique_classes": len({e.class_name for e in trace.entries}),
            "unique_methods": len({f"{e.class_name}.{e.method_name}" for e in trace.entries}),
            "apk_package": trace.apk_package,
            "timeline_sample": hook_details[:50],  # first 50 for LLM context
        }

        return ExtractorResult(evidence=evidence, findings=findings)

    def _detect_patterns(self, entries: list[FridaHookEntry]) -> list[Finding]:
        """Detect composite attack patterns across multiple hooks.

        Args:
            entries: List of Frida hook entries.

        Returns:
            Additional findings for detected compound patterns.
        """
        findings: list[Finding] = []
        hook_types_seen = {e.hook_type for e in entries}

        # Pattern: reflection + dex_loading = packed/staged malware
        if FridaHookType.reflection in hook_types_seen and FridaHookType.dex_loading in hook_types_seen:
            findings.append(Finding(
                id="dyn_frida_staged_payload",
                type=FindingType.dynamic_load,
                severity=Severity.critical,
                confidence=0.90,
                detail=(
                    "Compound pattern: reflection + dynamic DEX loading observed "
                    "at runtime. Strongly indicates staged/packed malware payload."
                ),
                provenance=Provenance(extractor=self.name),
                mappings=Mappings(mitre=["T1620", "T1027.002"]),
            ))

        # Pattern: sms + crypto = encrypted C2 via SMS
        if FridaHookType.sms in hook_types_seen and FridaHookType.crypto in hook_types_seen:
            findings.append(Finding(
                id="dyn_frida_encrypted_sms",
                type=FindingType.sms,
                severity=Severity.critical,
                confidence=0.85,
                detail=(
                    "Compound pattern: SMS operations + cryptographic operations "
                    "at runtime. May indicate encrypted SMS C2 channel."
                ),
                provenance=Provenance(extractor=self.name),
                mappings=Mappings(mitre=["T1636.004", "T1573"]),
            ))

        # Pattern: accessibility + device_info = overlay attack preparation
        if FridaHookType.accessibility in hook_types_seen and FridaHookType.device_info in hook_types_seen:
            findings.append(Finding(
                id="dyn_frida_overlay_prep",
                type=FindingType.behavior,
                severity=Severity.critical,
                confidence=0.88,
                detail=(
                    "Compound pattern: accessibility service + device fingerprinting "
                    "at runtime. Indicates credential harvesting via overlay attack."
                ),
                provenance=Provenance(extractor=self.name),
                mappings=Mappings(mitre=["T1453", "T1426"]),
            ))

        return findings
