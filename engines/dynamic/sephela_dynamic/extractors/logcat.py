"""Logcat extractor — parses Android system logs for suspicious behaviour.

Reads ``logcat.txt`` (standard Android log output captured during sandbox
execution) and flags:
- Suspicious intent broadcasts (SMS_RECEIVED, BOOT_COMPLETED)
- Crash traces / ANR (potential anti-analysis or deliberate instability)
- WebView URL loads (phishing overlays)
- Root/SU detection attempts
- Notable framework errors

The logcat parser works on structured JSON lines if available
(``logcat.json``) or falls back to plain-text parsing of standard
``logcat -v threadtime`` format.
"""

from __future__ import annotations

import json
import re
from typing import Any

from sephela_dynamic.base import ArtifactsContext, DynamicExtractor, ExtractorResult
from sephela_dynamic.envelope import (
    Finding,
    FindingType,
    Mappings,
    Provenance,
    Severity,
)
from sephela_dynamic.schemas import LogcatEntry, LogcatLevel, LogcatTrace

# Regex patterns for suspicious logcat content
_SUSPICIOUS_PATTERNS: list[tuple[str, re.Pattern[str], Severity, FindingType, str, list[str]]] = [
    (
        "sms_broadcast",
        re.compile(r"android\.provider\.Telephony\.SMS_RECEIVED", re.IGNORECASE),
        Severity.critical,
        FindingType.sms,
        "SMS_RECEIVED broadcast detected — app is intercepting SMS messages",
        ["T1636.004"],
    ),
    (
        "boot_receiver",
        re.compile(r"android\.intent\.action\.BOOT_COMPLETED", re.IGNORECASE),
        Severity.medium,
        FindingType.behavior,
        "BOOT_COMPLETED receiver — app starts automatically on device boot",
        ["T1398"],  # Boot or Logon Autostart
    ),
    (
        "webview_load",
        re.compile(r"WebView\.loadUrl\(|shouldOverrideUrlLoading|CookieManager", re.IGNORECASE),
        Severity.medium,
        FindingType.behavior,
        "WebView URL loading detected — potential phishing overlay",
        ["T1411"],  # Input Prompt
    ),
    (
        "su_root",
        re.compile(r"\bsu\b|/system/xbin/su|/system/bin/su|SuperSU|Magisk|root.*check", re.IGNORECASE),
        Severity.high,
        FindingType.evasion,
        "Root/SU detection or escalation attempt",
        ["T1404"],  # Exploitation for Privilege Escalation
    ),
    (
        "process_exec",
        re.compile(r"Runtime\.exec|ProcessBuilder|/bin/sh|/system/bin/sh", re.IGNORECASE),
        Severity.high,
        FindingType.evasion,
        "Shell command execution at runtime",
        ["T1623"],  # Command and Scripting Interpreter
    ),
    (
        "dex_load_log",
        re.compile(r"DexClassLoader|InMemoryDexClassLoader|PathClassLoader.*\.dex", re.IGNORECASE),
        Severity.critical,
        FindingType.dynamic_load,
        "Dynamic DEX loading observed in system log",
        ["T1620"],
    ),
    (
        "accessibility_event",
        re.compile(r"AccessibilityService|onAccessibilityEvent|performAction", re.IGNORECASE),
        Severity.critical,
        FindingType.behavior,
        "Accessibility service activity in system log",
        ["T1453"],
    ),
]


class LogcatExtractor(DynamicExtractor):
    """Parse Android logcat output for suspicious runtime behaviour."""

    name = "logcat"
    required_artifacts = ["logcat.json"]

    def can_run(self, ctx: ArtifactsContext) -> bool:
        """Check for either JSON or plain-text logcat."""
        return (
            ctx.artifact_path("logcat.json").is_file()
            or ctx.artifact_path("logcat.txt").is_file()
        )

    def extract(self, ctx: ArtifactsContext) -> ExtractorResult:
        """Parse logcat and emit findings for suspicious patterns.

        Args:
            ctx: Artifacts context with the sandbox output directory.

        Returns:
            Structured evidence with log statistics and pattern matches.
        """
        trace = self._load_trace(ctx)
        if trace is None:
            return ExtractorResult(evidence={"error": "No logcat artifact found"})

        findings: list[Finding] = []
        pattern_hits: dict[str, int] = {}

        for entry in trace.entries:
            for pattern_id, regex, severity, ftype, description, mitre in _SUSPICIOUS_PATTERNS:
                if regex.search(entry.message):
                    pattern_hits[pattern_id] = pattern_hits.get(pattern_id, 0) + 1

        # Emit one finding per matched pattern
        for pattern_id, count in pattern_hits.items():
            for pid, regex, severity, ftype, description, mitre in _SUSPICIOUS_PATTERNS:
                if pid == pattern_id:
                    findings.append(Finding(
                        id=f"dyn_logcat_{pattern_id}_{count}",
                        type=ftype,
                        severity=severity,
                        confidence=min(0.5 + (count * 0.1), 0.95),
                        detail=f"{description} ({count} occurrence(s) in logcat).",
                        provenance=Provenance(extractor=self.name),
                        mappings=Mappings(mitre=mitre),
                    ))
                    break

        # Detect crashes / ANR
        crash_count = sum(
            1 for e in trace.entries
            if e.level in (LogcatLevel.error, LogcatLevel.fatal)
            and ("FATAL" in e.message or "ANR" in e.message or "Crash" in e.message)
        )
        if crash_count > 0:
            findings.append(Finding(
                id=f"dyn_logcat_crashes_{crash_count}",
                type=FindingType.behavior,
                severity=Severity.low,
                confidence=0.60,
                detail=f"{crash_count} crash/ANR event(s) in logcat — may indicate anti-analysis.",
                provenance=Provenance(extractor=self.name),
                mappings=Mappings(mitre=["T1581"]),  # Geofencing
            ))

        # Level distribution
        level_counts: dict[str, int] = {}
        for entry in trace.entries:
            level_counts[entry.level.value] = level_counts.get(entry.level.value, 0) + 1

        evidence: dict[str, object] = {
            "total_lines": trace.total_lines,
            "level_distribution": level_counts,
            "pattern_matches": pattern_hits,
            "crash_count": crash_count,
            "unique_tags": len({e.tag for e in trace.entries}),
        }

        return ExtractorResult(evidence=evidence, findings=findings)

    def _load_trace(self, ctx: ArtifactsContext) -> LogcatTrace | None:
        """Load logcat from JSON (preferred) or fallback to text.

        Args:
            ctx: Artifacts context.

        Returns:
            Parsed LogcatTrace or None if no artifact exists.
        """
        # Try structured JSON first
        raw_json = ctx.read_artifact("logcat.json")
        if raw_json is not None:
            data = json.loads(raw_json)
            return LogcatTrace.model_validate(data)

        # Fallback to plain text
        raw_text = ctx.read_artifact("logcat.txt")
        if raw_text is not None:
            return self._parse_text_logcat(raw_text)

        return None

    def _parse_text_logcat(self, text: str) -> LogcatTrace:
        """Best-effort parse of ``logcat -v threadtime`` format.

        Args:
            text: Raw logcat text content.

        Returns:
            A LogcatTrace with entries parsed from text lines.
        """
        entries: list[LogcatEntry] = []
        line_count = 0

        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            line_count += 1

            # logcat -v threadtime format:
            # MM-DD HH:MM:SS.mmm  PID  TID LEVEL TAG: MESSAGE
            match = re.match(
                r"\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+\s+(\d+)\s+\d+\s+([VDIWEF])\s+(\S+)\s*:\s*(.*)",
                line,
            )
            if match:
                pid_str, level_str, tag, message = match.groups()
                try:
                    level = LogcatLevel(level_str)
                except ValueError:
                    level = LogcatLevel.info

                entries.append(LogcatEntry(
                    timestamp_ms=line_count,  # use line number as pseudo-timestamp
                    level=level,
                    tag=tag,
                    pid=int(pid_str),
                    message=message,
                ))
            else:
                # Non-matching line — still capture it
                entries.append(LogcatEntry(
                    timestamp_ms=line_count,
                    level=LogcatLevel.info,
                    tag="unknown",
                    message=line,
                ))

        return LogcatTrace(
            version="1.0",
            entries=entries,
            total_lines=line_count,
        )
