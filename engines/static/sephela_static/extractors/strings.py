"""String extractor — printable ASCII/UTF-8 strings from DEX + resources.

Tool-free: reads classes*.dex and resources.arsc directly from the archive and
extracts printable runs. This feeds the URL/IP extractors and the Code
Intelligence engine (Phase 6).

Beyond the raw list it computes two derived views, because the raw list is far too
large to be read by anything downstream that reasons rather than greps:

- ``high_entropy`` — long runs whose Shannon entropy is near the ceiling for their
  alphabet. In an APK that means an encrypted C2 configuration, a packed payload, or
  a key, none of which appear in a benign app's string table.
- ``suspicious`` — strings matching capability keywords a banking trojan needs. Not a
  verdict on its own; a declared capability is what makes the rest of the evidence
  worth correlating.

Both are consumed by the code and network agents' prompts, which read
``high_entropy_count`` and ``suspicious``.
"""

from __future__ import annotations

import math
import re
from collections import Counter

from sephela_static.base import ExtractionContext, Extractor, ExtractorResult

_PRINTABLE = re.compile(rb"[\x20-\x7e]{5,}")  # runs of >=5 printable chars
_MAX_STRINGS = 50_000  # bound memory on huge/hostile APKs

#: Entropy is only meaningful over enough symbols. Below this a coincidence of
#: distinct characters reads as randomness — "Xq7#mB" is not an encrypted blob.
_MIN_ENTROPY_LENGTH = 24

#: Shannon bits per character. Base64 tops out near 6.0 and hex near 4.0; encrypted
#: or compressed data encoded either way sits close to its ceiling, while identifiers
#: and English sit well below. 4.2 admits high-entropy hex without admitting prose.
_ENTROPY_THRESHOLD = 4.2

#: Keep the derived lists bounded — they go into an LLM prompt, and a thousand
#: base64 blobs crowd out the evidence that carries signal.
_MAX_DERIVED = 200

#: Capability keywords, grouped by what an analyst would call the behaviour. Matched
#: case-insensitively against the string. Deliberately narrow: a keyword that fires on
#: half the Android framework tells a reader nothing.
_SUSPICIOUS_PATTERNS: dict[str, tuple[str, ...]] = {
    # Screen reading and synthetic input — the overlay-trojan core.
    "accessibility": (
        "accessibilityservice",
        "accessibilityevent",
        "performGlobalAction",
        "dispatchGesture",
        "TYPE_APPLICATION_OVERLAY",
        "addView",
    ),
    # SMS interception, used to defeat one-time passcodes.
    "sms": (
        "SmsManager",
        "sendTextMessage",
        "SMS_RECEIVED",
        "abortBroadcast",
        "content://sms",
    ),
    # Loading code that was not in the APK at install time.
    "dynamic_code": (
        "DexClassLoader",
        "PathClassLoader",
        "InMemoryDexClassLoader",
        "Class.forName",
        "loadLibrary",
        "setAccessible",
    ),
    # Root and shell access.
    "shell": ("/system/bin/", "/system/xbin/", "su -c", "chmod 777", "Runtime.getRuntime().exec"),
    # Emulator and analysis detection.
    "anti_analysis": (
        "ro.build.tags",
        "test-keys",
        "goldfish",
        "isDebuggerConnected",
        "ro.kernel.qemu",
        "Superuser.apk",
    ),
    # Weak or misused cryptography. Matched at the call site rather than by algorithm
    # name: a bare "MD5" appears throughout legitimate library code, so it would flood
    # the field instead of narrowing it.
    "crypto": (
        "AES/ECB",
        "DESede",
        "SecretKeySpec",
        "IvParameterSpec",
        'getInstance("MD5',
        'getInstance("SHA-1',
        'getInstance("AES',
    ),
    # Device administration — lock, wipe, and uninstall protection.
    "device_admin": ("DevicePolicyManager", "DeviceAdminReceiver", "lockNow", "resetPassword"),
    # Credential and account access.
    "credentials": ("AccountManager", "getPassword", "keystore", "credential"),
}


def shannon_entropy(value: str) -> float:
    """Shannon entropy of ``value`` in bits per character."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def _is_high_entropy(value: str) -> bool:
    return len(value) >= _MIN_ENTROPY_LENGTH and shannon_entropy(value) >= _ENTROPY_THRESHOLD


def _suspicion_categories(value: str) -> list[str]:
    """Which capability groups ``value`` matches, if any."""
    lowered = value.lower()
    return [
        category
        for category, keywords in _SUSPICIOUS_PATTERNS.items()
        if any(keyword.lower() in lowered for keyword in keywords)
    ]


class StringExtractor(Extractor):
    name = "strings"

    def extract(self, ctx: ExtractionContext) -> ExtractorResult:
        strings: list[str] = []
        seen: set[str] = set()
        for entry in ctx.zip.namelist():
            if not (entry.endswith(".dex") or entry.endswith(".arsc")):
                continue
            try:
                blob = ctx.zip.read(entry)
            except Exception:  # noqa: BLE001 — skip unreadable entries
                continue
            for match in _PRINTABLE.finditer(blob):
                s = match.group().decode("ascii", "ignore")
                if s not in seen:
                    seen.add(s)
                    strings.append(s)
                    if len(strings) >= _MAX_STRINGS:
                        break
            if len(strings) >= _MAX_STRINGS:
                break

        high_entropy = [s for s in strings if _is_high_entropy(s)]
        suspicious: list[str] = []
        categories: Counter[str] = Counter()
        for s in strings:
            matched = _suspicion_categories(s)
            if matched:
                categories.update(matched)
                if len(suspicious) < _MAX_DERIVED:
                    suspicious.append(s)

        return ExtractorResult(
            evidence={
                "count": len(strings),
                "strings": strings,
                "truncated": len(strings) >= _MAX_STRINGS,
                # Counts are of everything found; the lists are capped, so a reader can
                # tell "none" from "too many to show".
                "high_entropy_count": len(high_entropy),
                "high_entropy": high_entropy[:_MAX_DERIVED],
                "suspicious_count": sum(categories.values()),
                "suspicious": suspicious,
                "suspicious_categories": dict(categories),
            }
        )
