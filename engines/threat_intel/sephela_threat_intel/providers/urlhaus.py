"""URLhaus (abuse.ch) — malware *distribution* URLs and hosts. No API key needed.

Keyless, generous, and precisely on-topic: URLhaus tracks URLs used to deliver
payloads, which is exactly what a dropper APK's embedded download endpoints are.
Because it is an explicit blocklist rather than a reputation score, a hit is
treated as high-confidence malicious with no ratio arithmetic — the indicator was
manually or automatically confirmed to serve malware.

Being keyless also makes it the engine's smoke test: a deployment with no API
keys configured at all still produces real threat-intel evidence.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sephela_threat_intel.base import Provider, ProviderResult, Verdict
from sephela_threat_intel.iocs import Ioc, IocType
from sephela_threat_intel.providers.http import request_json, str_list

if TYPE_CHECKING:  # pragma: no cover
    import httpx

URL_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"
HOST_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/host/"


class UrlHausProvider(Provider):
    name = "urlhaus"
    supports = frozenset({IocType.url, IocType.domain, IocType.ip})
    requests_per_minute = 60

    @property
    def configured(self) -> bool:
        # Keyless feed — always available.
        return True

    async def lookup(self, ioc: Ioc, client: httpx.AsyncClient) -> ProviderResult:
        if ioc.type is IocType.url:
            endpoint, form = URL_ENDPOINT, {"url": ioc.value}
        else:
            endpoint, form = HOST_ENDPOINT, {"host": ioc.value}

        payload = await request_json(
            client, "POST", endpoint, provider=self.name, data=form
        )
        # URLhaus signals "not found" in the body, not the status code.
        if payload is None or payload.get("query_status") != "ok":
            return ProviderResult(
                ioc=ioc,
                provider=self.name,
                verdict=Verdict.unknown,
                summary="Not listed on URLhaus",
                raw={"found": False, "query_status": _status(payload)},
            )

        threat = payload.get("threat")
        tags = str_list(payload.get("tags"), limit=15)
        url_status = payload.get("url_status")

        if ioc.type is IocType.url:
            # A dead distribution URL is still evidence the sample intended to
            # fetch a payload — the verdict stands, only confidence drops.
            offline = url_status == "offline"
            verdict = Verdict.malicious
            score = 0.7 if offline else 1.0
            summary = f"Listed on URLhaus as {threat or 'malware_download'} ({url_status or '?'})"
            raw: dict[str, Any] = {
                "found": True,
                "threat": threat if isinstance(threat, str) else None,
                "url_status": url_status if isinstance(url_status, str) else None,
                "date_added": payload.get("date_added")
                if isinstance(payload.get("date_added"), str)
                else None,
                "tags": tags,
                "reporter": payload.get("reporter")
                if isinstance(payload.get("reporter"), str)
                else None,
            }
        else:
            # Host lookups return the count of URLs seen on that host.
            urls = payload.get("urls")
            url_count = len(urls) if isinstance(urls, list) else 0
            blacklists = payload.get("blacklists")
            blacklists = blacklists if isinstance(blacklists, dict) else {}
            verdict = Verdict.malicious if url_count else Verdict.suspicious
            score = 1.0 if url_count >= 3 else (0.8 if url_count else 0.4)
            summary = f"URLhaus has {url_count} malware URL(s) on this host"
            raw = {
                "found": True,
                "url_count": url_count,
                "first_seen": payload.get("firstseen")
                if isinstance(payload.get("firstseen"), str)
                else None,
                "blacklists": {k: v for k, v in blacklists.items() if isinstance(v, str)},
                "tags": tags,
            }

        return ProviderResult(
            ioc=ioc,
            provider=self.name,
            verdict=verdict,
            score=score,
            families=[threat] if isinstance(threat, str) and threat.strip() else [],
            signatures=tags,
            summary=summary,
            raw=raw,
        )


def _status(payload: dict[str, Any] | None) -> str:
    if payload is None:
        return "http_404"
    status = payload.get("query_status")
    return status if isinstance(status, str) else "unknown"
