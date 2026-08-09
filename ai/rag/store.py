"""
ai/rag/store.py — Vector store abstraction + in-memory implementation.

``docs/architecture/04-data-model.md`` reserves Qdrant for vector data, and
``01-tech-stack.md`` allows pgvector "for small scale". Neither should leak into
the retriever, so the retriever depends on this narrow interface: upsert chunks,
search by vector with metadata filters, delete a document's chunks.

``InMemoryVectorStore`` is not only a test double. A curated knowledge corpus for
Android banking malware is on the order of hundreds of documents — a few thousand
chunks — which is well within the range where brute-force cosine search over a
Python list is faster end to end than a network round trip to a vector database.
It is a legitimate small-deployment backend, and it means the RAG path needs no
extra infrastructure to run at all.

Filtering happens *before* scoring in both implementations. That ordering is what
makes ``trust`` enforceable at the storage layer rather than only downstream: an
untrusted chunk cannot occupy a result slot it would then be filtered out of.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from ai.rag.embeddings import cosine_similarity
from ai.rag.models import Chunk, DocumentKind, ScoredChunk, is_trusted


class VectorStoreError(RuntimeError):
    """The vector store could not serve a request."""


@dataclass
class SearchFilter:
    """Metadata constraints applied before similarity scoring.

    ``trusted_only`` defaults to True: the safe behaviour must be what a caller
    gets by forgetting to think about it.
    """

    kinds: list[DocumentKind] = field(default_factory=list)
    families: list[str] = field(default_factory=list)
    mitre: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    trusted_only: bool = True

    def matches(self, chunk: Chunk) -> bool:
        if self.trusted_only and not chunk.trusted:
            return False
        if self.kinds and chunk.kind not in self.kinds:
            return False
        # Family/MITRE/tag constraints are disjunctive within a field: a chunk
        # about any of the candidate families is relevant, since the point is to
        # find material related to *this* sample's attribution.
        if self.families and not _overlaps(self.families, chunk.families):
            return False
        if self.mitre and not _overlaps(self.mitre, chunk.mitre):
            return False
        if self.tags and not _overlaps(self.tags, chunk.tags):
            return False
        return True


def _overlaps(wanted: list[str], present: list[str]) -> bool:
    lowered = {p.lower() for p in present}
    return any(w.lower() in lowered for w in wanted)


class VectorStore(ABC):
    """Storage and nearest-neighbour search over chunk embeddings."""

    @abstractmethod
    async def upsert(self, chunks: list[Chunk], vectors: list[list[float]]) -> int:
        """Insert or replace chunks by ``chunk_id``. Returns the number written."""

    @abstractmethod
    async def search(
        self, vector: list[float], *, top_k: int, filters: SearchFilter | None = None
    ) -> list[ScoredChunk]:
        """Return the ``top_k`` most similar chunks passing ``filters``."""

    @abstractmethod
    async def delete_document(self, doc_id: str) -> int:
        """Remove every chunk of one document. Returns the number removed."""

    @abstractmethod
    async def count(self) -> int:
        """Total stored chunks."""

    @abstractmethod
    async def document_hashes(self) -> dict[str, str]:
        """Map ``doc_id`` → stored ``content_hash``.

        This is what makes ingestion incremental: comparing the corpus on disk
        against this map identifies exactly which documents changed, so an
        unchanged corpus costs zero embedding calls.
        """


class InMemoryVectorStore(VectorStore):
    """Brute-force cosine search over a dict. Exact, dependency-free, fast enough."""

    def __init__(self) -> None:
        self._chunks: dict[str, Chunk] = {}
        self._vectors: dict[str, list[float]] = {}

    async def upsert(self, chunks: list[Chunk], vectors: list[list[float]]) -> int:
        if len(chunks) != len(vectors):
            raise VectorStoreError(
                f"upsert got {len(chunks)} chunks and {len(vectors)} vectors"
            )
        for chunk, vector in zip(chunks, vectors, strict=True):
            # Rejecting here rather than relying on the ingestor is the storage
            # half of the trusted-source rule: nothing untrusted can be persisted
            # even by a caller that skipped the ingestion path.
            if not is_trusted(chunk.trust):
                raise VectorStoreError(
                    f"refusing to store untrusted chunk {chunk.chunk_id} "
                    f"(trust={chunk.trust.value})"
                )
            self._chunks[chunk.chunk_id] = chunk
            self._vectors[chunk.chunk_id] = vector
        return len(chunks)

    async def search(
        self, vector: list[float], *, top_k: int, filters: SearchFilter | None = None
    ) -> list[ScoredChunk]:
        if top_k <= 0 or not self._chunks:
            return []
        active = filters or SearchFilter()

        scored: list[ScoredChunk] = []
        for chunk_id, chunk in self._chunks.items():
            if not active.matches(chunk):
                continue
            score = cosine_similarity(vector, self._vectors[chunk_id])
            scored.append(ScoredChunk(chunk=chunk, score=score))

        # Tie-break on chunk_id so equal scores order deterministically — a
        # non-deterministic prompt would make analysis runs irreproducible.
        scored.sort(key=lambda s: (-s.score, s.chunk.chunk_id))
        return scored[:top_k]

    async def delete_document(self, doc_id: str) -> int:
        ids = [cid for cid, chunk in self._chunks.items() if chunk.doc_id == doc_id]
        for chunk_id in ids:
            del self._chunks[chunk_id]
            del self._vectors[chunk_id]
        return len(ids)

    async def count(self) -> int:
        return len(self._chunks)

    async def document_hashes(self) -> dict[str, str]:
        hashes: dict[str, str] = {}
        for chunk in self._chunks.values():
            hashes.setdefault(chunk.doc_id, chunk.content_hash)
        return hashes
