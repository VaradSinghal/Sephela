"""Provider framework — the contract every threat-intel feed implements.

Mirrors the extractor contract of the static/dynamic engines: one module per
source, isolated failures, structured output. The differences are inherent to
talking to somebody else's API:

- lookups are **async** (the engine is network-bound, not CPU-bound);
- a provider may not be **configured** (no API key) — that is a skip, not an error;
- a provider answers only for some **IoC types** (AbuseIPDB has no opinion on a
  file hash), so the pipeline routes indicators rather than broadcasting them;
- every provider normalizes its own vendor-specific response into one
  ``ProviderResult`` so correlation and scoring stay vendor-agnostic.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

from sephela_threat_intel.iocs import Ioc, IocType

if TYPE_CHECKING:  # pragma: no cover
    import httpx


class Verdict(str, Enum):
    """Normalized cross-provider verdict. Matches ``enrichments.verdict``."""

    malicious = "malicious"
    suspicious = "suspicious"
    benign = "benign"
    #: the feed answered, but has no record of this indicator (a real signal —
    #: distinct from "we never asked")
    unknown = "unknown"


@dataclass
class ProviderResult:
    """One provider's normalized answer about one indicator."""

    ioc: Ioc
    provider: str
    verdict: Verdict = Verdict.unknown
    #: 0.0 (clean) .. 1.0 (certainly malicious) — provider-normalized
    score: float = 0.0
    #: malware family / campaign labels, e.g. ["Cerberus"]
    families: list[str] = field(default_factory=list)
    #: AV or YARA signature names
    signatures: list[str] = field(default_factory=list)
    #: threat-actor or campaign attributions
    actors: list[str] = field(default_factory=list)
    #: short human-readable summary for the finding detail line
    summary: str = ""
    #: trimmed provider payload, persisted to ``enrichments.raw``
    raw: dict[str, Any] = field(default_factory=dict)
    #: served from the enrichment cache rather than a live call
    cached: bool = False

    @property
    def is_hit(self) -> bool:
        """True when the feed had an actual adverse record for this indicator."""
        return self.verdict in (Verdict.malicious, Verdict.suspicious)


class ProviderError(RuntimeError):
    """A provider could not answer. Recorded as a partial failure, never fatal."""


class RateLimitedError(ProviderError):
    """The provider refused the call due to quota (HTTP 429 or local budget)."""


class ProviderUnavailableError(ProviderError):
    """The provider is unreachable, erroring, or its circuit breaker is open."""


class Provider(ABC):
    """Base class for all threat-intel providers."""

    #: stable identifier — used as the evidence key, provenance name, and the
    #: ``enrichments.provider`` value, so it must match the values documented in
    #: docs/architecture/04-data-model.md
    name: str = "provider"
    #: indicator classes this provider can answer for
    supports: frozenset[IocType] = frozenset()
    #: sustained request budget, used to size the token bucket
    requests_per_minute: int = 60

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key or None

    @property
    def configured(self) -> bool:
        """Whether this provider can be called at all.

        Keyless feeds (URLHaus, MalwareBazaar) override this to always be true.
        """
        return self.api_key is not None

    def handles(self, ioc: Ioc) -> bool:
        return ioc.type in self.supports

    @abstractmethod
    async def lookup(self, ioc: Ioc, client: httpx.AsyncClient) -> ProviderResult:
        """Query the feed for one indicator.

        Must either return a ``ProviderResult`` (including a ``Verdict.unknown``
        one for "no record") or raise a ``ProviderError``. The pipeline isolates
        the raise into ``envelope.errors``.
        """
