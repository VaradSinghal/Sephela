"""Sephela Threat Intelligence Engine (Phase 11).

Enriches the indicators surfaced by static and dynamic analysis against external
threat feeds (VirusTotal, OTX, AbuseIPDB, URLhaus, MalwareBazaar), correlates the
answers across providers, and emits a standardized Evidence Envelope for the
scoring and AI layers.

The engine is a pure function of its inputs — indicators in, envelope out. It
owns no database and no configuration: the caller supplies the providers (with
their API keys) and a cache implementation, which is what lets the backend back
the cache with the ``enrichments`` table while tests use an in-memory one.

Public API::

    from sephela_threat_intel import analyze, build_providers, iocs_from_findings

    iocs = sample_iocs(sha256=sample.sha256) + iocs_from_findings(rows)
    envelope = await analyze(iocs, providers=build_providers(keys), cache=cache)
"""

from sephela_threat_intel.base import Provider, ProviderResult, Verdict
from sephela_threat_intel.cache import EnrichmentCache, InMemoryCache, ttl_for
from sephela_threat_intel.envelope import EvidenceEnvelope
from sephela_threat_intel.iocs import Ioc, IocType, make_ioc
from sephela_threat_intel.pipeline import ENGINE_NAME, ENGINE_VERSION, analyze
from sephela_threat_intel.providers import PROVIDER_REGISTRY, build_providers
from sephela_threat_intel.sources import iocs_from_findings, sample_iocs

__all__ = [
    "ENGINE_NAME",
    "ENGINE_VERSION",
    "EnrichmentCache",
    "EvidenceEnvelope",
    "InMemoryCache",
    "Ioc",
    "IocType",
    "PROVIDER_REGISTRY",
    "Provider",
    "ProviderResult",
    "Verdict",
    "analyze",
    "build_providers",
    "iocs_from_findings",
    "make_ioc",
    "sample_iocs",
    "ttl_for",
]
__version__ = "0.1.0"
