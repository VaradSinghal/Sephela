"""
ai/rag/models.py — Core value objects for the knowledge/RAG subsystem (Phase 12).

The single most important field in this module is ``KnowledgeDocument.trust``.
``docs/architecture/09-security.md`` requires that "retrieved RAG docs are
trusted-source only; sample-derived text is quarantined", because retrieval output
is spliced into an LLM prompt. If an attacker could get text from their own APK
into the knowledge base, they would gain a channel for writing instructions into
every future analysis prompt — a persistent, cross-tenant prompt injection.

Trust is therefore a property of the *document*, enforced at ingestion (nothing
untrusted is ever stored) and re-checked at retrieval (nothing untrusted is ever
rendered). Two independent checks for one rule, because the cost of getting it
wrong is paid by every subsequent job.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

#: Rough chars-per-token ratio, matching ``ai/agents/base.py``'s estimator.
CHARS_PER_TOKEN = 4


class SourceTrust(str, Enum):
    """Provenance class of a knowledge document.

    Only ``curated`` and ``vendor`` documents may reach a prompt. The remaining
    values exist so an ingestion attempt can be *rejected with a reason* rather
    than silently dropped — an operator needs to know why their corpus file did
    not load.
    """

    #: Written or reviewed by the security team. The default for the bundled corpus.
    curated = "curated"
    #: Published reference material (MITRE, OWASP, vendor threat reports).
    vendor = "vendor"
    #: Derived from an analyzed sample. NEVER retrievable — this is the quarantine.
    sample_derived = "sample_derived"
    #: Provenance not established. Treated as untrusted.
    unknown = "unknown"


#: The allowlist. Membership here is what makes a document eligible for a prompt.
TRUSTED_SOURCES: frozenset[SourceTrust] = frozenset(
    {SourceTrust.curated, SourceTrust.vendor}
)


def is_trusted(trust: SourceTrust) -> bool:
    return trust in TRUSTED_SOURCES


class DocumentKind(str, Enum):
    """What kind of knowledge a document carries.

    Used as a retrieval filter: the network agent wants C2 infrastructure
    patterns, the permission agent wants technique references. Filtering by kind
    keeps a small token budget spent on relevant material.
    """

    malware_family = "malware_family"
    technique = "technique"  # MITRE ATT&CK / OWASP Mobile reference
    behavior_pattern = "behavior_pattern"  # overlay abuse, accessibility abuse, …
    detection_rule = "detection_rule"
    playbook = "playbook"  # SOC response guidance
    reference = "reference"


@dataclass
class KnowledgeDocument:
    """One source document in the knowledge base, before chunking."""

    #: Stable identifier, typically the corpus-relative path.
    doc_id: str
    title: str
    text: str
    kind: DocumentKind = DocumentKind.reference
    trust: SourceTrust = SourceTrust.unknown
    #: Human-readable origin (URL, report name, "internal:soc-playbooks").
    source: str = ""
    #: Malware families this document is about, lowercased.
    families: list[str] = field(default_factory=list)
    #: MITRE technique ids this document covers.
    mitre: list[str] = field(default_factory=list)
    owasp_mobile: list[str] = field(default_factory=list)
    #: Free-form tags for filtering.
    tags: list[str] = field(default_factory=list)

    @property
    def content_hash(self) -> str:
        """Digest of the retrievable content.

        Ingestion is idempotent on this: re-running over an unchanged corpus
        rewrites nothing, and an edited document replaces exactly its own chunks.
        """
        return hashlib.sha256(self.text.encode("utf-8")).hexdigest()

    @property
    def trusted(self) -> bool:
        return is_trusted(self.trust)


@dataclass
class Chunk:
    """A retrievable slice of a document, carrying its parent's provenance.

    Provenance is copied onto the chunk rather than looked up through the parent
    because the vector store is the only thing the retriever reads at query time.
    A chunk that travelled without its trust label could not be re-checked before
    rendering, and the second half of the trusted-source rule would be
    unenforceable.
    """

    chunk_id: str
    doc_id: str
    text: str
    #: Position within the parent document, for stable ordering in the prompt.
    ordinal: int = 0
    #: Heading path within the document, e.g. "Cerberus > Overlay behaviour".
    heading: str = ""
    title: str = ""
    kind: DocumentKind = DocumentKind.reference
    trust: SourceTrust = SourceTrust.unknown
    source: str = ""
    families: list[str] = field(default_factory=list)
    mitre: list[str] = field(default_factory=list)
    owasp_mobile: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    content_hash: str = ""

    @property
    def trusted(self) -> bool:
        return is_trusted(self.trust)

    @property
    def estimated_tokens(self) -> int:
        return max(1, len(self.text) // CHARS_PER_TOKEN)

    def payload(self) -> dict[str, Any]:
        """Flat metadata dict, for storage alongside the vector."""
        return {
            "chunk_id": self.chunk_id,
            "doc_id": self.doc_id,
            "text": self.text,
            "ordinal": self.ordinal,
            "heading": self.heading,
            "title": self.title,
            "kind": self.kind.value,
            "trust": self.trust.value,
            "source": self.source,
            "families": list(self.families),
            "mitre": list(self.mitre),
            "owasp_mobile": list(self.owasp_mobile),
            "tags": list(self.tags),
            "content_hash": self.content_hash,
        }

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> Chunk:
        """Rebuild a chunk from stored metadata.

        Unrecognized ``kind``/``trust`` values degrade safely: an unknown kind
        becomes ``reference``, but an unknown trust becomes ``unknown`` — which is
        untrusted — so a corrupted or hand-edited payload fails closed.
        """
        try:
            kind = DocumentKind(payload.get("kind", ""))
        except ValueError:
            kind = DocumentKind.reference
        try:
            trust = SourceTrust(payload.get("trust", ""))
        except ValueError:
            trust = SourceTrust.unknown

        return cls(
            chunk_id=str(payload.get("chunk_id", "")),
            doc_id=str(payload.get("doc_id", "")),
            text=str(payload.get("text", "")),
            ordinal=int(payload.get("ordinal", 0) or 0),
            heading=str(payload.get("heading", "")),
            title=str(payload.get("title", "")),
            kind=kind,
            trust=trust,
            source=str(payload.get("source", "")),
            families=[str(f) for f in payload.get("families", []) or []],
            mitre=[str(m) for m in payload.get("mitre", []) or []],
            owasp_mobile=[str(o) for o in payload.get("owasp_mobile", []) or []],
            tags=[str(t) for t in payload.get("tags", []) or []],
            content_hash=str(payload.get("content_hash", "")),
        )


@dataclass
class ScoredChunk:
    """A chunk with its similarity to the query, as returned by a vector store."""

    chunk: Chunk
    score: float

    @property
    def trusted(self) -> bool:
        return self.chunk.trusted


@dataclass
class RetrievalQuery:
    """A retrieval request: what to look for, and what to allow back.

    ``text`` is built from a controlled vocabulary (see ``ai/rag/query.py``) —
    never from raw sample strings — so an attacker cannot steer retrieval with
    free text embedded in their APK.
    """

    text: str
    top_k: int = 6
    #: Restrict to these document kinds (empty = any).
    kinds: list[DocumentKind] = field(default_factory=list)
    #: Restrict to documents about these families (empty = any).
    families: list[str] = field(default_factory=list)
    #: Drop matches below this similarity. Guards against a near-empty corpus
    #: returning irrelevant material simply because it was the closest thing.
    min_score: float = 0.05
    #: Ceiling on the rendered context, so retrieval cannot crowd out evidence.
    max_tokens: int = 1200


@dataclass
class RetrievalResult:
    """What retrieval produced, plus why it produced that.

    The diagnostic counters are not decoration: a silently empty retrieval and a
    retrieval whose every hit was filtered out as untrusted are very different
    events, and only one of them is a security signal worth alerting on.
    """

    query: RetrievalQuery
    chunks: list[ScoredChunk] = field(default_factory=list)
    #: Candidates returned by the store before filtering.
    candidates: int = 0
    #: Dropped because their trust label is not in the allowlist.
    rejected_untrusted: int = 0
    #: Dropped for scoring below ``min_score``.
    rejected_low_score: int = 0
    #: Dropped because the token budget was already spent.
    rejected_budget: int = 0
    #: True when the retriever could not reach its backing store at all.
    degraded: bool = False
    error: str | None = None

    @property
    def estimated_tokens(self) -> int:
        return sum(c.chunk.estimated_tokens for c in self.chunks)

    @property
    def sources(self) -> list[str]:
        seen: list[str] = []
        for scored in self.chunks:
            label = scored.chunk.source or scored.chunk.doc_id
            if label not in seen:
                seen.append(label)
        return seen
