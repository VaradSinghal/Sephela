"""
ai/rag/retriever.py — Turn a query into a bounded, trusted, diverse context set.

Placed before LLM inference in DFD-3 (``docs/architecture/07-data-flow.md``), so
everything it does is on the critical path of every AI analysis. Four concerns,
each of which changes the answer materially:

**Two-pass search when attribution exists.** With a known family, the
family-specific document is the single most valuable thing in the corpus — but
filtering the whole search on that family excludes every general technique
document, which is usually most of the corpus. So a family-attributed query runs
one filtered pass and one unfiltered pass and merges them. Filtering once would
either lose the family profile or lose the technique references; neither is
acceptable.

**Diversity over raw score.** A long family profile chunked into eight passages
will occupy all eight result slots, all saying much the same thing. Capping
chunks per document forces the budget to cover several sources, which is what
makes the retrieved context add information rather than repeat it.

**A token budget that is actually enforced.** Retrieved context competes with
evidence for prompt space, and evidence must win — the AI reasons over evidence,
with knowledge as background. Chunks are admitted until the budget is spent and
the remainder is reported as dropped.

**Failing open, never hard.** A vector store outage degrades the analysis (no
background knowledge) but must not fail the job. The result carries ``degraded``
so a caller can see the difference between "nothing relevant" and "retrieval was
broken".
"""

from __future__ import annotations

import logging

from ai.rag.embeddings import Embedder
from ai.rag.models import (
    Chunk,
    RetrievalQuery,
    RetrievalResult,
    ScoredChunk,
)
from ai.rag.store import SearchFilter, VectorStore

_LOG = logging.getLogger("sephela.rag")

#: Maximum chunks admitted from any one document, so a long profile cannot
#: monopolize the budget.
MAX_CHUNKS_PER_DOC = 2
#: Over-fetch factor: filtering (trust, score, budget, diversity) discards
#: candidates, so the store is asked for more than the caller wants.
OVERFETCH = 3


class KnowledgeRetriever:
    """Retrieves trusted knowledge for a query, within a token budget."""

    def __init__(self, store: VectorStore, embedder: Embedder) -> None:
        self.store = store
        self.embedder = embedder

    async def retrieve(self, query: RetrievalQuery) -> RetrievalResult:
        result = RetrievalResult(query=query)
        if query.top_k <= 0 or not query.text.strip():
            return result

        try:
            vector = await self.embedder.embed_one(query.text)
            candidates = await self._search(query, vector)
        except Exception as exc:  # noqa: BLE001 — retrieval must never fail a job
            _LOG.warning("rag_retrieval_failed: %s: %s", type(exc).__name__, exc)
            result.degraded = True
            result.error = f"{type(exc).__name__}: {exc}"
            return result

        result.candidates = len(candidates)
        result.chunks = self._select(candidates, query, result)
        return result

    async def _search(
        self, query: RetrievalQuery, vector: list[float]
    ) -> list[ScoredChunk]:
        """Run the search pass(es) and merge, keeping each chunk's best score."""
        fetch = max(query.top_k * OVERFETCH, query.top_k)

        general = await self.store.search(
            vector,
            top_k=fetch,
            filters=SearchFilter(kinds=list(query.kinds), trusted_only=True),
        )

        if not query.families:
            return general

        family_specific = await self.store.search(
            vector,
            top_k=fetch,
            filters=SearchFilter(
                kinds=list(query.kinds), families=list(query.families), trusted_only=True
            ),
        )
        return _merge_by_best_score(family_specific, general)

    def _select(
        self,
        candidates: list[ScoredChunk],
        query: RetrievalQuery,
        result: RetrievalResult,
    ) -> list[ScoredChunk]:
        """Apply trust, score, diversity, and budget in that order.

        Trust first — an untrusted chunk must not be able to displace a trusted
        one by scoring higher. The stores already filter on trust; re-checking
        here is the deliberate second enforcement point, so a store implementation
        that gets its filter wrong cannot put untrusted text into a prompt.
        """
        ordered = sorted(candidates, key=lambda s: (-s.score, s.chunk.chunk_id))

        selected: list[ScoredChunk] = []
        per_doc: dict[str, int] = {}
        tokens = 0

        for scored in ordered:
            if not scored.chunk.trusted:
                result.rejected_untrusted += 1
                _LOG.warning(
                    "rag_untrusted_chunk_filtered: chunk=%s trust=%s",
                    scored.chunk.chunk_id,
                    scored.chunk.trust.value,
                )
                continue
            if scored.score < query.min_score:
                result.rejected_low_score += 1
                continue
            if per_doc.get(scored.chunk.doc_id, 0) >= MAX_CHUNKS_PER_DOC:
                continue

            cost = scored.chunk.estimated_tokens
            if tokens + cost > query.max_tokens:
                # Keep scanning: a later, smaller chunk may still fit, and skipping
                # it because one large chunk did not would waste the remainder.
                result.rejected_budget += 1
                continue

            selected.append(scored)
            per_doc[scored.chunk.doc_id] = per_doc.get(scored.chunk.doc_id, 0) + 1
            tokens += cost

            if len(selected) >= query.top_k:
                break

        return selected


def _merge_by_best_score(
    primary: list[ScoredChunk], secondary: list[ScoredChunk]
) -> list[ScoredChunk]:
    """Union two result sets, keeping the higher score for chunks in both."""
    merged: dict[str, ScoredChunk] = {}
    for scored in [*primary, *secondary]:
        existing = merged.get(scored.chunk.chunk_id)
        if existing is None or scored.score > existing.score:
            merged[scored.chunk.chunk_id] = scored
    return list(merged.values())


def deduplicate_chunks(chunks: list[Chunk]) -> list[Chunk]:
    """Drop chunks with identical text, keeping the first.

    Corpora accumulate near-duplicates as documents are copied and edited; two
    identical passages in one prompt spend budget twice for one fact.
    """
    seen: set[str] = set()
    out: list[Chunk] = []
    for chunk in chunks:
        key = " ".join(chunk.text.split())
        if key in seen:
            continue
        seen.add(key)
        out.append(chunk)
    return out
