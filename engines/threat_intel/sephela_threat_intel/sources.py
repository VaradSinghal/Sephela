"""IoC harvesting from upstream evidence.

The threat-intel engine sits downstream of static and dynamic analysis, so its
input is whatever those engines already found. Rather than parse each engine's
bespoke ``evidence`` block — which would couple this engine to every other
engine's internal shape and break whenever one of them evolves — indicators are
harvested from the **normalized findings**, the one cross-engine structure whose
schema is fixed (``docs/architecture/04-data-model.md``, ``findings`` table).

That choice is what makes this engine work unchanged when a new engine lands: any
engine emitting ``url``/``ip``/``cert``/``network`` findings is automatically a
source of indicators.

Findings are treated as untrusted input: they were derived from strings inside a
malware sample, so every value is re-normalized and re-validated here even though
the upstream engine already did so.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from sephela_threat_intel.iocs import Ioc, IocType, dedupe, make_ioc

#: Finding ``type`` → indicator class, for findings whose ``detail`` *is* the
#: indicator (the static engine's url/ip extractors work this way).
DIRECT_TYPES: dict[str, IocType] = {
    "url": IocType.url,
    "ip": IocType.ip,
    "domain": IocType.domain,
    "cert": IocType.cert,
}

#: Finding types whose ``detail`` is prose that *contains* indicators — the
#: dynamic engine's network findings read like "POST http://c2.example/reg".
SCANNED_TYPES: frozenset[str] = frozenset({"network", "behavior", "runtime_api"})

_URL_RE = re.compile(r"(?:https?|ftp)://[^\s\"'<>)\\]+", re.IGNORECASE)
_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_DOMAIN_RE = re.compile(
    r"(?<![\w.-])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|info|biz|top|xyz|online|site|club|shop|app|dev|io|co|ru|cn|in|br|ir|tk|ml|ga|cf|gq|pw|cc|me|su|icu|vip|link|live|store|fun|space|website|tech|pro)"
    r"(?![\w-])"
)

#: Per-class caps. Extracted strings are a firehose: a packed APK can yield
#: thousands of URL-shaped fragments, most of them SDK boilerplate. Capping here
#: (in addition to the pipeline's lookup budget) keeps the *indicator set* itself
#: bounded, so the evidence block stays readable.
DEFAULT_CAPS: dict[IocType, int] = {
    IocType.url: 60,
    IocType.domain: 60,
    IocType.ip: 40,
    IocType.cert: 10,
    IocType.hash: 4,
}


def sample_iocs(
    *, sha256: str | None = None, sha1: str | None = None, md5: str | None = None
) -> list[Ioc]:
    """Indicators for the sample file itself — the highest-value lookups.

    All available digests are included because feeds are indexed inconsistently:
    MalwareBazaar keys on SHA-256, while older AV intel is often only reachable
    by MD5.
    """
    out: list[Ioc] = []
    for digest in (sha256, sha1, md5):
        if not digest:
            continue
        ioc = make_ioc(IocType.hash, digest, source="sample")
        if ioc is not None:
            out.append(ioc)
    return dedupe(out)


def iocs_from_findings(
    findings: Iterable[dict[str, Any]],
    *,
    caps: dict[IocType, int] | None = None,
) -> list[Ioc]:
    """Harvest indicators from normalized finding rows.

    Each row needs only ``type`` and ``detail``; ``source_engine`` (or
    ``source``) is used for provenance when present. Rows are processed in the
    order given, so callers control which engine's indicators survive the caps —
    dynamic-analysis indicators are observed at runtime and therefore stronger
    than strings scraped from a binary, so the backend passes those first.
    """
    limits = {**DEFAULT_CAPS, **(caps or {})}
    counts: dict[IocType, int] = dict.fromkeys(IocType, 0)
    harvested: list[Ioc] = []

    def add(candidate: Ioc | None) -> None:
        if candidate is None:
            return
        if counts[candidate.type] >= limits.get(candidate.type, 0):
            return
        counts[candidate.type] += 1
        harvested.append(candidate)

    for row in findings:
        if not isinstance(row, dict):
            continue
        type_ = row.get("type")
        detail = row.get("detail")
        if not isinstance(type_, str) or not isinstance(detail, str) or not detail.strip():
            continue
        source = str(row.get("source_engine") or row.get("source") or "unknown")[:32]

        direct = DIRECT_TYPES.get(type_)
        if direct is not None:
            add(make_ioc(direct, detail, source=source))
            continue
        if type_ in SCANNED_TYPES:
            for candidate in _scan(detail, source=source):
                add(candidate)

    return dedupe(harvested)


def _scan(text: str, *, source: str) -> list[Ioc]:
    """Pull URL/IP/domain indicators out of a free-text finding detail."""
    candidates: list[Ioc | None] = []

    urls = [m.group(0) for m in _URL_RE.finditer(text)]
    candidates += [make_ioc(IocType.url, raw, source=source) for raw in urls]

    # Blank out host-shaped substrings already covered by a matched URL, so one
    # observed request does not become three indicators.
    remainder = text
    for raw in urls:
        remainder = remainder.replace(raw, " ")

    candidates += [
        make_ioc(IocType.ip, m.group(0), source=source) for m in _IPV4_RE.finditer(remainder)
    ]
    candidates += [
        make_ioc(IocType.domain, m.group(0), source=source)
        for m in _DOMAIN_RE.finditer(remainder)
    ]

    return [ioc for ioc in candidates if ioc is not None]
