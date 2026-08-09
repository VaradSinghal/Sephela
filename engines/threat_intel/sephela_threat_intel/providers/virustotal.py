"""VirusTotal (API v3) — multi-engine AV consensus for hashes, domains, IPs, URLs.

The most broadly useful feed and the one with the tightest free quota (4 lookups
per minute), so the token bucket matters here more than anywhere else.

Verdict derivation uses the *ratio* of malicious to responding engines rather
than a raw count: a single detection out of 70 engines is routinely a false
positive on obfuscated-but-legitimate APKs (packers, DRM), while 15 of 70 is
conclusive. Banking-fraud analysts act on the ratio, so scoring gets the ratio.
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING, Any

from sephela_threat_intel.base import Provider, ProviderResult, Verdict
from sephela_threat_intel.iocs import Ioc, IocType
from sephela_threat_intel.providers.http import clamp, request_json, str_list

if TYPE_CHECKING:  # pragma: no cover
    import httpx

API_ROOT = "https://www.virustotal.com/api/v3"

#: >= this fraction of responding engines flagging it ⇒ malicious
MALICIOUS_RATIO = 0.10
#: at least one detection but below the malicious ratio ⇒ suspicious
SUSPICIOUS_MIN_DETECTIONS = 1


def _url_id(url: str) -> str:
    """VT identifies URLs by unpadded base64url of the URL itself."""
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


class VirusTotalProvider(Provider):
    name = "virustotal"
    supports = frozenset({IocType.hash, IocType.domain, IocType.ip, IocType.url})
    # Public API tier: 4 requests/minute.
    requests_per_minute = 4

    def _endpoint(self, ioc: Ioc) -> str:
        match ioc.type:
            case IocType.hash:
                return f"{API_ROOT}/files/{ioc.value}"
            case IocType.domain:
                return f"{API_ROOT}/domains/{ioc.value}"
            case IocType.ip:
                return f"{API_ROOT}/ip_addresses/{ioc.value}"
            case IocType.url:
                return f"{API_ROOT}/urls/{_url_id(ioc.value)}"
            case _:  # pragma: no cover — guarded by `supports`
                raise ValueError(f"virustotal cannot enrich {ioc.type}")

    async def lookup(self, ioc: Ioc, client: httpx.AsyncClient) -> ProviderResult:
        payload = await request_json(
            client,
            "GET",
            self._endpoint(ioc),
            provider=self.name,
            headers={"x-apikey": self.api_key or "", "Accept": "application/json"},
        )
        if payload is None:
            # Not in VT at all. For a hash that is itself notable: known malware
            # families are indexed within hours, so an unindexed APK is either
            # brand new (targeted fraud campaigns often are) or bespoke.
            return ProviderResult(
                ioc=ioc,
                provider=self.name,
                verdict=Verdict.unknown,
                summary="Not present in VirusTotal",
                raw={"found": False},
            )

        attributes = payload.get("data", {})
        attributes = attributes.get("attributes", {}) if isinstance(attributes, dict) else {}
        if not isinstance(attributes, dict):
            attributes = {}

        stats = attributes.get("last_analysis_stats")
        stats = stats if isinstance(stats, dict) else {}
        malicious = _int(stats.get("malicious"))
        suspicious = _int(stats.get("suspicious"))
        harmless = _int(stats.get("harmless"))
        undetected = _int(stats.get("undetected"))
        responded = malicious + suspicious + harmless + undetected

        flagged = malicious + suspicious
        ratio = (flagged / responded) if responded else 0.0

        if responded == 0:
            verdict = Verdict.unknown
        elif ratio >= MALICIOUS_RATIO:
            verdict = Verdict.malicious
        elif flagged >= SUSPICIOUS_MIN_DETECTIONS:
            verdict = Verdict.suspicious
        else:
            verdict = Verdict.benign

        families = _families(attributes)
        signatures = _signatures(attributes)

        return ProviderResult(
            ioc=ioc,
            provider=self.name,
            verdict=verdict,
            # Saturate at a 50% detection ratio — beyond that the certainty is
            # already total and the extra engines add no information.
            score=clamp(ratio * 2.0),
            families=families,
            signatures=signatures,
            summary=(
                f"{flagged}/{responded} engines flagged this {ioc.type.value}"
                if responded
                else "No VirusTotal engine results"
            ),
            raw={
                "found": True,
                "stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected,
                },
                "reputation": _int(attributes.get("reputation")),
                "threat_label": attributes.get("popular_threat_classification", {}).get(
                    "suggested_threat_label"
                )
                if isinstance(attributes.get("popular_threat_classification"), dict)
                else None,
                "families": families,
                "signatures": signatures,
            },
        )


def _int(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _families(attributes: dict[str, Any]) -> list[str]:
    """Pull family labels out of VT's threat classification block."""
    classification = attributes.get("popular_threat_classification")
    if not isinstance(classification, dict):
        return []

    families: list[str] = []
    label = classification.get("suggested_threat_label")
    if isinstance(label, str) and label.strip():
        families.append(label.strip()[:128])

    for entry in classification.get("popular_threat_name", []) or []:
        if isinstance(entry, dict):
            value = entry.get("value")
            if isinstance(value, str) and value.strip() and value.strip() not in families:
                families.append(value.strip()[:128])
        if len(families) >= 10:
            break
    return families


def _signatures(attributes: dict[str, Any]) -> list[str]:
    """Collect the distinct AV signature names from per-engine results.

    Capped hard: ``last_analysis_results`` carries ~70 engines, and the useful
    signal is which *names* recur, not the full per-vendor matrix.
    """
    results = attributes.get("last_analysis_results")
    if not isinstance(results, dict):
        return str_list(attributes.get("tags"), limit=10)

    names: list[str] = []
    for engine_result in results.values():
        if not isinstance(engine_result, dict):
            continue
        if engine_result.get("category") not in ("malicious", "suspicious"):
            continue
        result = engine_result.get("result")
        if isinstance(result, str) and result.strip() and result.strip() not in names:
            names.append(result.strip()[:128])
        if len(names) >= 15:
            break
    return names
