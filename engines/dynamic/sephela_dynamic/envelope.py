"""Evidence Envelope — the universal engine contract for dynamic analysis.

Mirrors the static engine's envelope (``engines/static/sephela_static/envelope.py``)
so the orchestration pipeline and AI layer treat all evidence uniformly.
This is the dynamic engine's own copy; it will graduate into the shared
``libs/sephela_evidence`` package.

Guarantees:
- ``envelope_version`` is additive-versioned.
- An extractor failure is *partial* (recorded in ``errors``), never fatal.
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
    runtime_api = "runtime_api"
    network = "network"
    crypto = "crypto"
    evasion = "evasion"
    dynamic_load = "dynamic_load"
    sms = "sms"
    file_access = "file_access"
    behavior = "behavior"


class Status(str, Enum):
    ok = "ok"
    partial = "partial"
    failed = "failed"


class EngineInfo(BaseModel):
    name: str
    version: str


class Provenance(BaseModel):
    """Where the evidence was found."""

    extractor: str
    locator: str | None = None  # e.g. "frida_trace:line:42" or "pcap:packet:1023"
    timestamp_ms: int | None = None  # millis since sandbox boot


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
    sandbox_duration_ms: int | None = None  # total sandbox wall-clock time
    # engine-specific structured evidence, keyed by extractor name
    evidence: dict[str, object] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)
    errors: list[ExtractorError] = Field(default_factory=list)
