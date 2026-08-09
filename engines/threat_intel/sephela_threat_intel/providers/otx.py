"""AlienVault OTX — community "pulses" (campaign reports) for any indicator type.

OTX is the engine's main source of *attribution* rather than detection: pulses
carry campaign names, adversary names, and malware families contributed by
researchers. For banking-fraud triage that context ("this C2 appears in a
Cerberus pulse") is often more actionable than an AV verdict, so pulse metadata
is promoted into ``families``/``actors`` and becomes attribution findings.

Verdict derivation is pulse-count based. One pulse can be a researcher's noisy
bulk import; several independent pulses referencing the same indicator is a real
signal.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sephela_threat_intel.base import Provider, ProviderResult, Verdict
from sephela_threat_intel.iocs import Ioc, IocType
from sephela_threat_intel.providers.http import clamp, request_json

if TYPE_CHECKING:  # pragma: no cover
    import httpx

API_ROOT = "https://otx.alienvault.com/api/v1/indicators"

#: >= this many pulses ⇒ malicious; 1 or more ⇒ suspicious
MALICIOUS_PULSE_COUNT = 3

_SECTIONS = {
    IocType.hash: "file",
    IocType.domain: "domain",
    IocType.ip: "IPv4",
    IocType.url: "url",
}


class OtxProvider(Provider):
    name = "otx"
    supports = frozenset({IocType.hash, IocType.domain, IocType.ip, IocType.url})
    requests_per_minute = 60

    def _endpoint(self, ioc: Ioc) -> str:
        section = _SECTIONS.get(ioc.type)
        if section is None:  # pragma: no cover — guarded by `supports`
            raise ValueError(f"otx cannot enrich {ioc.type}")
        # OTX accepts the indicator in the path; httpx handles the encoding.
        return f"{API_ROOT}/{section}/{ioc.value}/general"

    async def lookup(self, ioc: Ioc, client: httpx.AsyncClient) -> ProviderResult:
        payload = await request_json(
            client,
            "GET",
            self._endpoint(ioc),
            provider=self.name,
            headers={"X-OTX-API-KEY": self.api_key or "", "Accept": "application/json"},
        )
        if payload is None:
            return ProviderResult(
                ioc=ioc,
                provider=self.name,
                verdict=Verdict.unknown,
                summary="No OTX record",
                raw={"found": False},
            )

        pulse_info = payload.get("pulse_info")
        pulse_info = pulse_info if isinstance(pulse_info, dict) else {}
        pulses = pulse_info.get("pulses")
        pulses = pulses if isinstance(pulses, list) else []
        count = _int(pulse_info.get("count")) or len(pulses)

        names, families, actors = _pulse_metadata(pulses)

        if count >= MALICIOUS_PULSE_COUNT:
            verdict = Verdict.malicious
        elif count >= 1:
            verdict = Verdict.suspicious
        else:
            # OTX knows the indicator but nobody has reported it — closer to
            # "no information" than to a clean bill of health.
            verdict = Verdict.unknown

        return ProviderResult(
            ioc=ioc,
            provider=self.name,
            verdict=verdict,
            # Saturates at 10 pulses; beyond that it is a well-known indicator.
            score=clamp(count / 10.0),
            families=families,
            actors=actors,
            summary=(
                f"Referenced by {count} OTX pulse(s)" if count else "Known to OTX, no pulses"
            ),
            raw={
                "found": True,
                "pulse_count": count,
                "pulses": names[:10],
                "families": families,
                "actors": actors,
                "validation": [
                    v.get("source")
                    for v in (payload.get("validation") or [])
                    if isinstance(v, dict)
                ][:5],
            },
        )


def _pulse_metadata(pulses: list[Any]) -> tuple[list[str], list[str], list[str]]:
    """Extract pulse names, malware families, and adversaries from pulse records."""
    names: list[str] = []
    families: list[str] = []
    actors: list[str] = []

    for pulse in pulses:
        if not isinstance(pulse, dict):
            continue
        name = pulse.get("name")
        if isinstance(name, str) and name.strip():
            names.append(name.strip()[:200])

        for family in pulse.get("malware_families") or []:
            label = family.get("display_name") if isinstance(family, dict) else family
            if isinstance(label, str) and label.strip() and label.strip() not in families:
                families.append(label.strip()[:128])

        adversary = pulse.get("adversary")
        if isinstance(adversary, str) and adversary.strip() and adversary.strip() not in actors:
            actors.append(adversary.strip()[:128])

    return names, families[:10], actors[:10]


def _int(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0
