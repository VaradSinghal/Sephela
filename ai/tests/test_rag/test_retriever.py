"""Retrieval policy: trust, diversity, budget, two-pass search, and graceful failure."""

from __future__ import annotations

import pytest

from ai.rag.chunking import chunk_document
from ai.rag.models import (
    Chunk,
    DocumentKind,
    RetrievalQuery,
    ScoredChunk,
    SourceTrust,
)
from ai.rag.retriever import MAX_CHUNKS_PER_DOC, KnowledgeRetriever, deduplicate_chunks
from ai.rag.store import InMemoryVectorStore, SearchFilter, VectorStore
from ai.tests.test_rag.conftest import make_doc

pytestmark = pytest.mark.anyio


async def load(store, embedder, docs):  # type: ignore[no-untyped-def]
    for doc in docs:
        chunks = chunk_document(doc)
        vectors = await embedder.embed([c.text for c in chunks])
        await store.upsert(chunks, vectors)


class LeakyStore(VectorStore):
    """A store that returns untrusted chunks — models a buggy backend.

    The retriever must still refuse them. This is why trust is re-checked
    downstream of the store filter rather than trusted to it.
    """

    def __init__(self, chunks: list[Chunk]) -> None:
        self._chunks = chunks

    async def upsert(self, chunks, vectors):  # type: ignore[no-untyped-def]
        return 0

    async def search(self, vector, *, top_k, filters=None):  # type: ignore[no-untyped-def]
        return [ScoredChunk(chunk=c, score=0.9) for c in self._chunks[:top_k]]

    async def delete_document(self, doc_id):  # type: ignore[no-untyped-def]
        return 0

    async def count(self):  # type: ignore[no-untyped-def]
        return len(self._chunks)

    async def document_hashes(self):  # type: ignore[no-untyped-def]
        return {}


class BrokenStore(VectorStore):
    async def upsert(self, chunks, vectors):  # type: ignore[no-untyped-def]
        return 0

    async def search(self, vector, *, top_k, filters=None):  # type: ignore[no-untyped-def]
        raise ConnectionError("qdrant unreachable")

    async def delete_document(self, doc_id):  # type: ignore[no-untyped-def]
        return 0

    async def count(self):  # type: ignore[no-untyped-def]
        raise ConnectionError("qdrant unreachable")

    async def document_hashes(self):  # type: ignore[no-untyped-def]
        raise ConnectionError("qdrant unreachable")


class RecordingStore(InMemoryVectorStore):
    """Records the filters each search pass used."""

    def __init__(self) -> None:
        super().__init__()
        self.filters_seen: list[SearchFilter] = []

    async def search(self, vector, *, top_k, filters=None):  # type: ignore[no-untyped-def]
        self.filters_seen.append(filters or SearchFilter())
        return await super().search(vector, top_k=top_k, filters=filters)


class TestTrustEnforcement:
    async def test_untrusted_chunks_from_a_leaky_store_are_dropped(self, embedder) -> None:  # type: ignore[no-untyped-def]
        untrusted = chunk_document(make_doc(trust=SourceTrust.sample_derived))
        retriever = KnowledgeRetriever(LeakyStore(untrusted), embedder)

        result = await retriever.retrieve(RetrievalQuery(text="overlay credential theft"))

        assert result.chunks == []
        assert result.rejected_untrusted == len(untrusted)

    async def test_trusted_chunks_pass(self, embedder) -> None:  # type: ignore[no-untyped-def]
        trusted = chunk_document(make_doc(trust=SourceTrust.curated))
        retriever = KnowledgeRetriever(LeakyStore(trusted), embedder)

        result = await retriever.retrieve(RetrievalQuery(text="overlay credential theft"))

        assert result.chunks
        assert result.rejected_untrusted == 0

    async def test_searches_always_request_trusted_only(self, embedder) -> None:  # type: ignore[no-untyped-def]
        store = RecordingStore()
        await load(store, embedder, [make_doc()])
        await KnowledgeRetriever(store, embedder).retrieve(
            RetrievalQuery(text="overlay", families=["cerberus"])
        )
        assert all(f.trusted_only for f in store.filters_seen)


class TestTwoPassSearch:
    async def test_an_attributed_query_runs_a_filtered_and_an_unfiltered_pass(self, embedder) -> None:  # type: ignore[no-untyped-def]
        # Filtering the whole search on the family would drop every general
        # technique document, so both passes are needed.
        store = RecordingStore()
        await load(store, embedder, [make_doc()])

        await KnowledgeRetriever(store, embedder).retrieve(
            RetrievalQuery(text="overlay", families=["cerberus"])
        )

        assert len(store.filters_seen) == 2
        assert [bool(f.families) for f in store.filters_seen] == [False, True]

    async def test_an_unattributed_query_runs_one_pass(self, embedder) -> None:  # type: ignore[no-untyped-def]
        store = RecordingStore()
        await load(store, embedder, [make_doc()])

        await KnowledgeRetriever(store, embedder).retrieve(RetrievalQuery(text="overlay"))

        assert len(store.filters_seen) == 1

    async def test_family_documents_and_general_documents_can_both_be_returned(
        self, store, embedder
    ) -> None:  # type: ignore[no-untyped-def]
        await load(
            store,
            embedder,
            [
                make_doc(
                    doc_id="fam.md",
                    families=["cerberus"],
                    kind=DocumentKind.malware_family,
                    text="# Cerberus\n\n" + "Cerberus draws overlay windows over banking apps to steal credentials. " * 3,
                ),
                make_doc(
                    doc_id="tech.md",
                    families=[],
                    kind=DocumentKind.technique,
                    text="# Overlays\n\n" + "Overlay windows are drawn over other applications to phish credentials. " * 3,
                ),
            ],
        )
        result = await KnowledgeRetriever(store, embedder).retrieve(
            RetrievalQuery(text="overlay credential theft banking", families=["cerberus"])
        )
        assert {c.chunk.doc_id for c in result.chunks} == {"fam.md", "tech.md"}


class TestDiversity:
    async def test_one_document_cannot_monopolize_the_results(self, store, embedder) -> None:  # type: ignore[no-untyped-def]
        # A long profile chunked into many passages would otherwise fill every
        # slot with near-identical text.
        long_body = "\n\n".join(
            f"## Section {i}\n\nOverlay credential theft description number {i} which is "
            f"long enough to be its own chunk in this document."
            for i in range(10)
        )
        await load(store, embedder, [make_doc(doc_id="long.md", text=f"# Long\n\n{long_body}")])

        result = await KnowledgeRetriever(store, embedder).retrieve(
            RetrievalQuery(text="overlay credential theft", top_k=8, max_tokens=5000)
        )
        assert len(result.chunks) <= MAX_CHUNKS_PER_DOC

    async def test_the_budget_spreads_across_sources(self, store, embedder) -> None:  # type: ignore[no-untyped-def]
        await load(
            store,
            embedder,
            [
                make_doc(doc_id=f"d{i}.md", text=f"# D{i}\n\nOverlay credential theft in document {i} described at length here.")
                for i in range(4)
            ],
        )
        result = await KnowledgeRetriever(store, embedder).retrieve(
            RetrievalQuery(text="overlay credential theft", top_k=4, max_tokens=5000)
        )
        assert len({c.chunk.doc_id for c in result.chunks}) >= 3


class TestBudget:
    async def test_the_token_budget_is_enforced(self, store, embedder) -> None:  # type: ignore[no-untyped-def]
        await load(
            store,
            embedder,
            [
                make_doc(doc_id=f"d{i}.md", text=f"# D{i}\n\n" + "Overlay credential theft description repeated for length. " * 20)
                for i in range(5)
            ],
        )
        query = RetrievalQuery(text="overlay credential theft", top_k=5, max_tokens=100)
        result = await KnowledgeRetriever(store, embedder).retrieve(query)

        assert result.estimated_tokens <= query.max_tokens
        assert result.rejected_budget > 0

    async def test_a_zero_budget_returns_nothing(self, store, embedder) -> None:  # type: ignore[no-untyped-def]
        await load(store, embedder, [make_doc()])
        result = await KnowledgeRetriever(store, embedder).retrieve(
            RetrievalQuery(text="overlay", max_tokens=0)
        )
        assert result.chunks == []

    async def test_top_k_is_respected(self, store, embedder) -> None:  # type: ignore[no-untyped-def]
        await load(store, embedder, [make_doc(doc_id=f"d{i}.md") for i in range(6)])
        result = await KnowledgeRetriever(store, embedder).retrieve(
            RetrievalQuery(text="overlay accessibility sms", top_k=2, max_tokens=5000)
        )
        assert len(result.chunks) == 2


class TestScoreThreshold:
    async def test_low_scoring_matches_are_dropped(self, store, embedder) -> None:  # type: ignore[no-untyped-def]
        # Guards against a near-empty corpus returning irrelevant material simply
        # because it was the closest thing available.
        await load(store, embedder, [make_doc()])
        result = await KnowledgeRetriever(store, embedder).retrieve(
            RetrievalQuery(text="unrelated topic about baking bread", min_score=0.9)
        )
        assert result.chunks == []
        assert result.rejected_low_score > 0


class TestGracefulDegradation:
    async def test_a_store_outage_degrades_rather_than_raising(self, embedder) -> None:  # type: ignore[no-untyped-def]
        result = await KnowledgeRetriever(BrokenStore(), embedder).retrieve(
            RetrievalQuery(text="overlay")
        )
        assert result.degraded is True
        assert "ConnectionError" in (result.error or "")
        assert result.chunks == []

    async def test_an_empty_query_short_circuits(self, store, embedder) -> None:  # type: ignore[no-untyped-def]
        result = await KnowledgeRetriever(store, embedder).retrieve(RetrievalQuery(text="   "))
        assert result.chunks == []
        assert result.degraded is False

    async def test_degraded_is_distinguishable_from_empty(self, store, embedder) -> None:  # type: ignore[no-untyped-def]
        # "retrieval was broken" and "nothing relevant" must not look alike —
        # only one of them is worth alerting on.
        empty = await KnowledgeRetriever(store, embedder).retrieve(RetrievalQuery(text="overlay"))
        broken = await KnowledgeRetriever(BrokenStore(), embedder).retrieve(
            RetrievalQuery(text="overlay")
        )
        assert empty.degraded is False
        assert broken.degraded is True


class TestDeduplication:
    def test_identical_text_is_collapsed(self) -> None:
        chunks = chunk_document(make_doc(doc_id="a.md")) + chunk_document(
            make_doc(doc_id="b.md")
        )
        assert len(deduplicate_chunks(chunks)) < len(chunks)

    def test_whitespace_differences_do_not_defeat_it(self) -> None:
        base = chunk_document(make_doc())[0]
        spaced = Chunk(**{**base.__dict__, "chunk_id": "other", "text": base.text.replace(" ", "  ")})
        assert len(deduplicate_chunks([base, spaced])) == 1
