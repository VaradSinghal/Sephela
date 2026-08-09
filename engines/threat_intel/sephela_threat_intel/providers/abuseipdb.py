"""AbuseIPDB — crowd-sourced abuse reports for IPv4/IPv6 addresses only.

Narrow but high-signal for this domain: fraudulent banking APKs exfiltrate to
cheap VPS and residential-proxy infrastructure that accumulates abuse reports
quickly. The provider's own ``abuseConfidenceScore`` (0-100) is already a
calibrated confidence, so it maps almost directly onto our 0..1 score.

``usageType`` is kept in the raw payload because it changes the interpretation:
abuse reports against a hosting/VPS ASN implicate the sample's operator, while
reports against a shared mobile carrier NAT gateway usually do not.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sephela_threat_intel.base import Provider, ProviderResult, Verdict
from sephela_threat_intel.iocs import Ioc, IocType
from sephela_threat_intel.providers.http import clamp, request_json

if TYPE_CHECKING:  # pragma: no cover
    import httpx

API_URL = "https://api.abuseipdb.com/api/v2/check"

#: Confidence (0-100) at or above which the IP is treated as malicious
MALICIOUS_CONFIDENCE = 50
#: ...and above which it is at least suspicious
SUSPICIOUS_CONFIDENCE = 15
#: Report window. 90 days keeps rotated infrastructure from looking clean while
#: not resurrecting abuse from a previous tenant of the address.
MAX_AGE_DAYS = "90"


class AbuseIpDbProvider(Provider):
    name = "abuseipdb"
    supports = frozenset({IocType.ip})
    # Free tier: 1000 checks/day. Paced well under that per minute.
    requests_per_minute = 30

    async def lookup(self, ioc: Ioc, client: httpx.AsyncClient) -> ProviderResult:
        payload = await request_json(
            client,
            "GET",
            API_URL,
            provider=self.name,
            headers={"Key": self.api_key or "", "Accept": "application/json"},
            params={"ipAddress": ioc.value, "maxAgeInDays": MAX_AGE_DAYS},
        )
        if payload is None:
            return ProviderResult(
                ioc=ioc,
                provider=self.name,
                verdict=Verdict.unknown,
                summary="No AbuseIPDB record",
                raw={"found": False},
            )

        data = payload.get("data")
        data = data if isinstance(data, dict) else {}
        confidence = _int(data.get("abuseConfidenceScore"))
        reports = _int(data.get("totalReports"))

        if confidence >= MALICIOUS_CONFIDENCE:
            verdict = Verdict.malicious
        elif confidence >= SUSPICIOUS_CONFIDENCE or reports > 0:
            verdict = Verdict.suspicious
        else:
            verdict = Verdict.benign

        usage_type = data.get("usageType")
        country = data.get("countryCode")

        return ProviderResult(
            ioc=ioc,
            provider=self.name,
            verdict=verdict,
            score=clamp(confidence / 100.0),
            summary=(
                f"Abuse confidence {confidence}% from {reports} report(s)"
                f"{f' — {usage_type}' if isinstance(usage_type, str) else ''}"
            ),
            raw={
                "found": True,
                "abuse_confidence": confidence,
                "total_reports": reports,
                "distinct_reporters": _int(data.get("numDistinctUsers")),
                "usage_type": usage_type if isinstance(usage_type, str) else None,
                "isp": data.get("isp") if isinstance(data.get("isp"), str) else None,
                "domain": data.get("domain") if isinstance(data.get("domain"), str) else None,
                "country": country if isinstance(country, str) else None,
                "is_tor": bool(data.get("isTor")),
                "last_reported_at": data.get("lastReportedAt")
                if isinstance(data.get("lastReportedAt"), str)
                else None,
            },
        )


def _int(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0
