"""Threat-intel providers — registry of the feeds the engine can query.

Each provider is an independent module wrapping one external API. Import them
here so the pipeline and the backend's provider factory can discover them by
name, mirroring ``sephela_dynamic.extractors``.

Construction order is the order results appear in the envelope's evidence block;
it is chosen so the highest-signal, cheapest feeds come first (keyless abuse.ch
services before the metered ones), which also means a run that exhausts its
budget mid-way keeps the most useful answers.
"""

from __future__ import annotations

from sephela_threat_intel.base import Provider
from sephela_threat_intel.providers.abuseipdb import AbuseIpDbProvider
from sephela_threat_intel.providers.bazaar import MalwareBazaarProvider
from sephela_threat_intel.providers.otx import OtxProvider
from sephela_threat_intel.providers.urlhaus import UrlHausProvider
from sephela_threat_intel.providers.virustotal import VirusTotalProvider

#: name → class, for config-driven construction by the backend
PROVIDER_REGISTRY: dict[str, type[Provider]] = {
    MalwareBazaarProvider.name: MalwareBazaarProvider,
    UrlHausProvider.name: UrlHausProvider,
    VirusTotalProvider.name: VirusTotalProvider,
    OtxProvider.name: OtxProvider,
    AbuseIpDbProvider.name: AbuseIpDbProvider,
}


def build_providers(api_keys: dict[str, str | None] | None = None) -> list[Provider]:
    """Instantiate every registered provider, keyed by name, dropping unconfigured ones.

    A provider without its API key is *omitted* rather than constructed and
    skipped later, so the envelope's evidence block reflects only feeds that were
    genuinely consulted.
    """
    keys = api_keys or {}
    providers = [cls(api_key=keys.get(name)) for name, cls in PROVIDER_REGISTRY.items()]
    return [p for p in providers if p.configured]


__all__ = [
    "AbuseIpDbProvider",
    "MalwareBazaarProvider",
    "OtxProvider",
    "PROVIDER_REGISTRY",
    "UrlHausProvider",
    "VirusTotalProvider",
    "build_providers",
]
