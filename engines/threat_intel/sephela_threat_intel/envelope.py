"""Evidence Envelope — the universal engine contract for threat intelligence.

Mirrors the static and dynamic engines' envelopes
(``engines/static/sephela_static/envelope.py``) so the orchestration pipeline and
AI layer treat all evidence uniformly. This is the threat-intel engine's own
copy; it will graduate into the shared ``libs/sephela_evidence`` package.

Guarantees:
- ``envelope_version`` is additive-versioned.
- A provider failure is *partial* (recorded in ``errors``), never fatal — an
  unreachable or rate-limited feed must not fail the job.
- Findings carry provenance + framework mappings so scoring/reports are auditable.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field

ENVELOPE_VERSION = "1.0"


class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class FindingType(str, Enum):
    #: an IoC matched a known-bad record in at least one feed
    ioc_match = "ioc_match"
    #: a feed attributed the sample to a malware family
    family_attribution = "family_attribution"
    #: a feed attributed the sample to a threat actor / campaign
    actor_attribution = "actor_attribution"
    #: reputation signal short of a match (low score, few detections)
    reputation = "reputation"
    #: an AV/YARA signature name reported by a feed
    signature = "signature"


class Status(str, Enum):
    ok = "ok"
    partial = "partial"
    failed = "failed"


class EngineInfo(BaseModel):
    name: str
    version: str


class Provenance(BaseModel):
    """Where the evidence came from.

    For threat intel the ``extractor`` is the provider name and the ``locator``
    is the enriched IoC, so an analyst can retrace any verdict to the exact feed
    and indicator that produced it.
    """

    extractor: str
    locator: str | None = None  # e.g. "domain:evil.example"
    #: true when the verdict was served from the enrichment cache rather than a
    #: live API call — relevant when judging how fresh a verdict is
    cached: bool = False


class Mappings(BaseModel):
    mitre: list[str] = Field(default_factory=list)
    owasp_mobile: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    id: str
    type: FindingType
    severity: Severity = Severity.info
    confidence: float = 0.5
    detail: str
    provenance: Provenance
    mappings: Mappings = Field(default_factory=Mappings)


class ExtractorError(BaseModel):
    extractor: str
    message: str


class EvidenceEnvelope(BaseModel):
    envelope_version: str = ENVELOPE_VERSION
    job_id: str | None = None
    apk_sha256: str | None = None
    engine: EngineInfo
    produced_at: str | None = None  # ISO-8601
    status: Status = Status.ok
    #: how many IoCs were submitted for enrichment vs served from cache
    iocs_queried: int = 0
    iocs_cached: int = 0
    # engine-specific structured evidence, keyed by provider name
    evidence: dict[str, object] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)
    errors: list[ExtractorError] = Field(default_factory=list)
