"""Correlation — many provider answers about many indicators into findings.

This is the engine's actual analysis, and it exists because a raw pile of feed
responses is not evidence. Three things happen here:

1. **Consensus.** Per indicator, provider answers are reconciled into one
   verdict. Agreement between independent feeds is the strongest signal
   available, so confidence rises with corroboration rather than taking any
   single provider's word — this is what stops one noisy VT engine or one stale
   OTX pulse from driving the risk score on its own.

2. **Severity by indicator class.** A hash hit means *this APK is known
   malware*; a domain hit means *it talks to something known bad*. The first is
   conclusive, the second is strong circumstantial evidence, and the report has
   to say which is which.

3. **Attribution promotion.** Family and actor labels are lifted out of
   individual responses into their own findings, deduplicated across providers,
   because ``ai/scoring`` weights ``family_attribution`` separately from
   ``ioc_match`` (see ``ai/scoring/constants.py``) and an analyst reads the
   family name first.

Findings ids are stable across re-runs (derived from the indicator, not from
iteration order), which is what makes the stage idempotent when the backend
upserts on ``(job_id, source_engine, finding_id)``.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass, field

from sephela_threat_intel.base import ProviderResult, Verdict
from sephela_threat_intel.envelope import (
    Finding,
    FindingType,
    Mappings,
    Provenance,
    Severity,
)
from sephela_threat_intel.iocs import Ioc, IocType

# Verdict precedence when providers disagree — the worst confirmed answer wins.
# A feed saying "clean" never overrides another saying "malicious": blocklists
# are authoritative about what they list and silent about what they don't.
_VERDICT_RANK = {
    Verdict.malicious: 3,
    Verdict.suspicious: 2,
    Verdict.benign: 1,
    Verdict.unknown: 0,
}

# Base severity for a confirmed-malicious indicator, by indicator class.
_MALICIOUS_SEVERITY = {
    IocType.hash: Severity.critical,  # the sample itself is known malware
    IocType.cert: Severity.high,  # signed by a key seen on known malware
    IocType.url: Severity.high,
    IocType.domain: Severity.high,
    IocType.ip: Severity.medium,  # IPs are shared/rotated more than names
}

# MITRE ATT&CK mappings, per indicator class.
_MITRE = {
    IocType.url: ["T1071.001", "T1105"],  # web protocols, ingress tool transfer
    IocType.domain: ["T1071.001", "T1583.001"],  # web protocols, acquire domains
    IocType.ip: ["T1071", "T1583.003"],  # app-layer protocol, acquire VPS
    IocType.hash: ["T1406"],  # obfuscated/known malicious payload
    IocType.cert: ["T1587.002"],  # develop capabilities: code signing certs
}
_OWASP_NETWORK = ["M5"]  # Insecure Communication
_OWASP_CODE = ["M8"]  # Code Tampering / malicious code


@dataclass
class IocConsensus:
    """The reconciled view of one indicator across every provider that answered."""

    ioc: Ioc
    verdict: Verdict = Verdict.unknown
    confidence: float = 0.0
    hits: list[ProviderResult] = field(default_factory=list)
    results: list[ProviderResult] = field(default_factory=list)

    @property
    def providers(self) -> list[str]:
        return [r.provider for r in self.results]

    @property
    def hit_providers(self) -> list[str]:
        return [r.provider for r in self.hits]

    @property
    def all_cached(self) -> bool:
        return bool(self.results) and all(r.cached for r in self.results)


def _short(value: str, limit: int = 48) -> str:
    """Bound a finding-id component, keeping it deterministic for long URLs."""
    if len(value) <= limit:
        return value
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
    return f"{value[:limit - 17]}~{digest}"


def _slug(value: str) -> str:
    """Lowercase, punctuation-free token for use inside a finding id."""
    return "".join(c if c.isalnum() else "-" for c in value.lower()).strip("-")[:48]


def consensus(results: list[ProviderResult]) -> list[IocConsensus]:
    """Group results by indicator and reconcile them into one verdict each.

    Confidence combines the strongest single provider score with a corroboration
    bonus: each *additional* feed that independently flags the indicator adds
    15%, capped at 1.0. Two feeds agreeing is worth more than one feed being
    slightly more certain.
    """
    grouped: dict[Ioc, list[ProviderResult]] = defaultdict(list)
    order: list[Ioc] = []
    for result in results:
        if result.ioc not in grouped:
            order.append(result.ioc)
        grouped[result.ioc].append(result)

    out: list[IocConsensus] = []
    for ioc in order:
        group = grouped[ioc]
        hits = [r for r in group if r.is_hit]
        verdict = max((r.verdict for r in group), key=lambda v: _VERDICT_RANK[v])

        if hits:
            best = max(r.score for r in hits)
            corroboration = 0.15 * (len(hits) - 1)
            confidence = min(1.0, best + corroboration)
        else:
            # No adverse record anywhere. Confidence in *that* grows with how
            # many feeds were consulted.
            confidence = min(0.9, 0.4 + 0.1 * len(group)) if group else 0.0

        out.append(
            IocConsensus(
                ioc=ioc,
                verdict=verdict,
                confidence=round(confidence, 3),
                hits=hits,
                results=group,
            )
        )
    return out


def _severity(item: IocConsensus) -> Severity:
    if item.verdict is Verdict.malicious:
        return _MALICIOUS_SEVERITY.get(item.ioc.type, Severity.high)
    if item.verdict is Verdict.suspicious:
        return Severity.medium if item.ioc.type is not IocType.hash else Severity.high
    return Severity.info


def _mappings(ioc_type: IocType) -> Mappings:
    owasp = _OWASP_CODE if ioc_type in (IocType.hash, IocType.cert) else _OWASP_NETWORK
    return Mappings(mitre=list(_MITRE.get(ioc_type, [])), owasp_mobile=list(owasp))


def build_findings(results: list[ProviderResult]) -> tuple[list[Finding], list[IocConsensus]]:
    """Turn provider results into envelope findings.

    Returns the findings plus the consensus records, which the pipeline also
    writes into the evidence block so a report can show the full per-indicator
    picture — including the indicators that came back clean.
    """
    reconciled = consensus(results)
    findings: list[Finding] = []

    # --- 1. IoC matches -------------------------------------------------------
    for item in reconciled:
        if not item.hits:
            continue
        detail_parts = [r.summary for r in item.hits if r.summary]
        findings.append(
            Finding(
                id=f"ti-ioc-{item.ioc.type.value}-{_short(item.ioc.value)}",
                type=FindingType.ioc_match,
                severity=_severity(item),
                confidence=item.confidence,
                detail=(
                    f"{item.ioc.type.value} {item.ioc.value} flagged {item.verdict.value} "
                    f"by {', '.join(item.hit_providers)}"
                    + (f" — {'; '.join(detail_parts)}" if detail_parts else "")
                ),
                provenance=Provenance(
                    extractor=item.hit_providers[0],
                    locator=item.ioc.key,
                    cached=item.all_cached,
                ),
                mappings=_mappings(item.ioc.type),
            )
        )

    # --- 2. Family attribution -----------------------------------------------
    # Deduplicated across indicators and providers: "Cerberus" reported by both
    # Bazaar (on the hash) and OTX (on the C2) is one attribution corroborated
    # twice, not two findings.
    families: dict[str, tuple[set[str], set[str]]] = {}
    actors: dict[str, tuple[set[str], set[str]]] = {}
    for result in results:
        for family in result.families:
            provs, iocs = families.setdefault(family, (set(), set()))
            provs.add(result.provider)
            iocs.add(result.ioc.key)
        for actor in result.actors:
            provs, iocs = actors.setdefault(actor, (set(), set()))
            provs.add(result.provider)
            iocs.add(result.ioc.key)

    for family, (provs, iocs) in families.items():
        findings.append(
            Finding(
                id=f"ti-family-{_slug(family)}",
                type=FindingType.family_attribution,
                # Corroborated attribution is what upgrades a "suspicious app"
                # into a named campaign in the SOC report.
                severity=Severity.critical if len(provs) > 1 else Severity.high,
                confidence=min(1.0, 0.6 + 0.2 * (len(provs) - 1)),
                detail=(
                    f"Attributed to malware family '{family}' by {', '.join(sorted(provs))} "
                    f"via {', '.join(sorted(iocs)[:5])}"
                ),
                provenance=Provenance(extractor=sorted(provs)[0], locator=sorted(iocs)[0]),
                mappings=Mappings(mitre=["T1406"], owasp_mobile=list(_OWASP_CODE)),
            )
        )

    for actor, (provs, iocs) in actors.items():
        findings.append(
            Finding(
                id=f"ti-actor-{_slug(actor)}",
                type=FindingType.actor_attribution,
                severity=Severity.high,
                confidence=min(1.0, 0.5 + 0.2 * (len(provs) - 1)),
                detail=(
                    f"Associated with threat actor '{actor}' by {', '.join(sorted(provs))} "
                    f"via {', '.join(sorted(iocs)[:5])}"
                ),
                provenance=Provenance(extractor=sorted(provs)[0], locator=sorted(iocs)[0]),
                mappings=Mappings(mitre=["T1583"]),
            )
        )

    # --- 3. Signatures --------------------------------------------------------
    # One finding per indicator that carried AV/YARA names, not one per name —
    # 15 vendor spellings of the same trojan is one piece of evidence.
    for item in reconciled:
        names: list[str] = []
        for result in item.results:
            for signature in result.signatures:
                if signature not in names:
                    names.append(signature)
        if not names:
            continue
        findings.append(
            Finding(
                id=f"ti-sig-{item.ioc.type.value}-{_short(item.ioc.value)}",
                type=FindingType.signature,
                severity=Severity.medium,
                confidence=item.confidence,
                detail=(
                    f"Signatures reported for {item.ioc.key}: {', '.join(names[:10])}"
                    + (f" (+{len(names) - 10} more)" if len(names) > 10 else "")
                ),
                provenance=Provenance(
                    extractor=item.results[0].provider,
                    locator=item.ioc.key,
                    cached=item.all_cached,
                ),
                mappings=Mappings(mitre=["T1406"], owasp_mobile=list(_OWASP_CODE)),
            )
        )

    return findings, reconciled
