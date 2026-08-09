"""IoC model + normalization.

The engine enriches *indicators*, not APKs, so this module owns the boundary
between "what the upstream engines found" and "what is worth asking a paid,
rate-limited external API about".

Two rules drive everything here:

1. **Normalize before caching.** ``HTTP://Evil.Example./path`` and
   ``http://evil.example/path`` are one indicator; treating them as two doubles
   the API spend and splits the cache.
2. **Never send noise off-box.** Private/loopback IPs, localhost, and ubiquitous
   platform domains (``schemas.android.com``, ``play.google.com``) appear in
   virtually every APK. Querying them burns quota, pollutes findings, and —
   because IoCs are extracted from a malware sample — leaks nothing useful.
   Filtering is also a privacy control (docs/architecture/09-security.md).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlsplit


class IocType(str, Enum):
    """Matches ``enrichments.ioc_type`` in docs/architecture/04-data-model.md."""

    hash = "hash"
    domain = "domain"
    ip = "ip"
    url = "url"
    cert = "cert"


@dataclass(frozen=True)
class Ioc:
    """One normalized indicator, hashable so de-duplication is free.

    ``source`` records which engine surfaced it (static/dynamic/…) purely for
    provenance — it deliberately does not participate in equality, so the same
    domain seen by two engines is enriched once.
    """

    type: IocType
    value: str
    source: str = "unknown"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Ioc):
            return NotImplemented
        return (self.type, self.value) == (other.type, other.value)

    def __hash__(self) -> int:
        return hash((self.type, self.value))

    @property
    def key(self) -> str:
        """Stable cache/finding key, e.g. ``domain:evil.example``."""
        return f"{self.type.value}:{self.value}"


# Domains that appear in nearly every Android app. Matched on the domain itself
# or any subdomain of it.
BENIGN_DOMAIN_SUFFIXES: frozenset[str] = frozenset(
    {
        "android.com",
        "google.com",
        "googleapis.com",
        "gstatic.com",
        "googleusercontent.com",
        "google-analytics.com",
        "googlesyndication.com",
        "googletagmanager.com",
        "doubleclick.net",
        "firebaseio.com",
        "crashlytics.com",
        "w3.org",
        "apache.org",
        "xml.org",
        "schema.org",
        "json-schema.org",
        "github.com",
        "githubusercontent.com",
        "kotlinlang.org",
        "oracle.com",
        "sun.com",
        "bouncycastle.org",
        "facebook.com",
        "fbcdn.net",
        "example.com",
        "localhost",
    }
)

_HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}
_HEX_RE = re.compile(r"^[0-9a-f]+$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$"
)
# The IoC extracted from strings is often surrounded by junk; also accept the
# common "defanged" forms analysts paste around.
_DEFANG = str.maketrans({"[": "", "]": ""})

MAX_IOC_LENGTH = 2048


def normalize_hash(value: str) -> str | None:
    """Lowercase a hex digest, or return None if it is not md5/sha1/sha256."""
    candidate = value.strip().lower()
    if len(candidate) not in _HASH_LENGTHS or not _HEX_RE.match(candidate):
        return None
    return candidate


def normalize_domain(value: str) -> str | None:
    """Lowercase, strip the trailing root dot, and validate the shape."""
    candidate = value.strip().translate(_DEFANG).lower().rstrip(".")
    candidate = candidate.replace("[.]", ".").replace("(.)", ".")
    if not candidate or len(candidate) > 253:
        return None
    # An IP is not a domain — callers should classify it as one.
    if _is_ip(candidate):
        return None
    if not _DOMAIN_RE.match(candidate):
        return None
    return candidate


def normalize_ip(value: str) -> str | None:
    """Validate a public, routable IP address (v4 or v6)."""
    candidate = value.strip().translate(_DEFANG).replace("[.]", ".")
    try:
        ip = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    if ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return None
    return str(ip)


def normalize_url(value: str) -> str | None:
    """Canonicalize a URL: lowercase scheme+host, drop the default port.

    Query strings and fragments are preserved — a malicious C2 path is often the
    whole indicator — but the URL is length-capped so a giant embedded data: blob
    never reaches a provider.
    """
    candidate = value.strip().translate(_DEFANG)
    candidate = candidate.replace("hxxp", "http").replace("[.]", ".")
    if len(candidate) > MAX_IOC_LENGTH:
        return None
    try:
        parts = urlsplit(candidate)
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https", "ftp") or not parts.hostname:
        return None

    # Strip the DNS root dot: "evil.example." and "evil.example" are one host,
    # and leaving it in would split the cache key and double the API spend.
    host = parts.hostname.lower().rstrip(".")
    if not host:
        return None
    port = parts.port
    default_port = {"http": 80, "https": 443, "ftp": 21}[parts.scheme.lower()]
    netloc = host if port in (None, default_port) else f"{host}:{port}"
    path = parts.path or "/"
    rebuilt = f"{parts.scheme.lower()}://{netloc}{path}"
    if parts.query:
        rebuilt += f"?{parts.query}"
    return rebuilt


def host_of(url: str) -> str | None:
    """Extract the hostname from a URL, for deriving domain/IP IoCs."""
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None


def is_benign_domain(domain: str) -> bool:
    """True for platform/SDK domains present in almost every APK."""
    if domain in BENIGN_DOMAIN_SUFFIXES:
        return True
    return any(domain.endswith(f".{suffix}") for suffix in BENIGN_DOMAIN_SUFFIXES)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def make_ioc(type_: IocType, value: str, *, source: str = "unknown") -> Ioc | None:
    """Normalize + validate one raw indicator, or None if it is not enrichable."""
    normalizer = {
        IocType.hash: normalize_hash,
        IocType.domain: normalize_domain,
        IocType.ip: normalize_ip,
        IocType.url: normalize_url,
    }.get(type_)

    if normalizer is None:  # cert — an opaque fingerprint, used verbatim
        candidate = value.strip().lower()
        return Ioc(type_, candidate, source) if candidate else None

    normalized = normalizer(value)
    if normalized is None:
        return None
    if type_ is IocType.domain and is_benign_domain(normalized):
        return None
    if type_ is IocType.url:
        host = host_of(normalized)
        if host and not _is_ip(host) and is_benign_domain(host):
            return None
    return Ioc(type_, normalized, source)


def expand_urls(iocs: list[Ioc]) -> list[Ioc]:
    """Derive domain/IP IoCs from URL IoCs.

    URLHaus knows the URL; AbuseIPDB only knows the IP; VirusTotal knows both.
    Deriving the host indicator up front means each provider gets the indicator
    class it can actually answer for.
    """
    derived: list[Ioc] = []
    for ioc in iocs:
        if ioc.type is not IocType.url:
            continue
        host = host_of(ioc.value)
        if not host:
            continue
        as_ip = normalize_ip(host)
        if as_ip is not None:
            derived.append(Ioc(IocType.ip, as_ip, ioc.source))
            continue
        domain = normalize_domain(host)
        if domain is not None and not is_benign_domain(domain):
            derived.append(Ioc(IocType.domain, domain, ioc.source))
    return derived


def dedupe(iocs: list[Ioc]) -> list[Ioc]:
    """De-duplicate while preserving discovery order (stable finding ids)."""
    seen: set[Ioc] = set()
    out: list[Ioc] = []
    for ioc in iocs:
        if ioc in seen:
            continue
        seen.add(ioc)
        out.append(ioc)
    return out
