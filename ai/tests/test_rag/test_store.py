"""Vector store behaviour, including the trust enforcement it is responsible for."""

from __future__ import annotations

import pytest

from ai.rag.chunking import chunk_document
from ai.rag.models import DocumentKind, SourceTrust
from ai.rag.store import SearchFilter, VectorStoreError
from ai.tests.test_rag.conftest import make_doc

pytestmark = pytest.mark.anyio


async def load(store, embedder, docs):  # type: ignore[no-untyped-def]
    for doc in docs:
        chunks = chunk_document(doc)
        vectors = await embedder.embed([c.text for c in chunks])
        await store.upsert(chunks, vectors)


class TestUpsert:
    async def test_chunks_are_stored_and_counted(self, store, embedder) -> None:  # type: ignore[no-untyped-def]
        await load(store, embedder, [make_doc()])
        assert await store.count() > 0

    async def test_untrusted_chunks_are_refused(self, store, embedder) -> None:  # type: ignore[no-untyped-def]
        # The storage half of the trusted-source rule: enforced even for a caller
        # that bypassed the ingestion path entirely.
        doc = make_doc(trust=SourceTrust.sample_derived)
        chunks = chunk_document(doc)
        vectors = await embedder.embed([c.text for c in chunks])

        with pytest.raises(VectorStoreError, match="untrusted"):
            await store.upsert(chunks, vectors)
        assert await store.count() == 0

    async def test_unknown_trust_is_also_refused(self, store, embedder) -> None:  # type: ignore[no-untyped-def]
        doc = make_doc(trust=SourceTrust.unknown)
        chunks = chunk_document(doc)
        vectors = await embedder.embed([c.text for c in chunks])
        with pytest.raises(VectorStoreError):
            await store.upsert(chunks, vectors)

    async def test_mismatched_vector_count_is_an_error(self, store) -> None:  # type: ignore[no-untyped-def]
        chunks = chunk_document(make_doc())
        with pytest.raises(VectorStoreError):
            await store.upsert(chunks, [])

    async def test_reupserting_the_same_chunk_replaces_it(self, store, embedder) -> None:  # type: ignore[no-untyped-def]
        await load(store, embedder, [make_doc()])
        first = await store.count()
        await load(store, embedder, [make_doc()])
        assert await store.count() == first


class TestSearch:
    async def test_the_closest_chunk_ranks_first(self, store, embedder) -> None:  # type: ignore[no-untyped-def]
        await load(
            store,
            embedder,
            [
                make_doc(doc_id="sms.md", text="# SMS\n\n" + "SMS one time passcode interception by a high priority broadcast receiver. " * 4),
                make_doc(doc_id="overlay.md", text="# Overlay\n\n" + "Overlay windows drawn over banking apps to phish credentials. " * 4),
            ],
        )
        vector = await embedder.embed_one("overlay windows phishing banking credentials")
        results = await store.search(vector, top_k=1)
        assert results[0].chunk.doc_id == "overlay.md"

    async def test_top_k_bounds_the_result_set(self, store, embedder) -> None:  # type: ignore[no-untyped-def]
        await load(store, embedder, [make_doc(doc_id=f"d{i}.md") for i in range(5)])
        vector = await embedder.embed_one("overlay")
        assert len(await store.search(vector, top_k=2)) == 2

    async def test_zero_top_k_returns_nothing(self, store, embedder) -> None:  # type: ignore[no-untyped-def]
        await load(store, embedder, [make_doc()])
        vector = await embedder.embed_one("overlay")
        assert await store.search(vector, top_k=0) == []

    async def test_an_empty_store_returns_nothing(self, store, embedder) -> None:  # type: ignore[no-untyped-def]
        vector = await embedder.embed_one("overlay")
        assert await store.search(vector, top_k=5) == []

    async def test_equal_scores_order_deterministically(self, store, embedder) -> None:  # type: ignore[no-untyped-def]
        # Identical text in two documents scores identically; a non-deterministic
        # tie-break would make analysis runs irreproducible.
        body = "# T\n\nIdentical body text used in both documents for this test case.\n"
        await load(
            store,
            embedder,
            [make_doc(doc_id="b.md", text=body), make_doc(doc_id="a.md", text=body)],
        )
        vector = await embedder.embed_one("identical body text")
        first = [s.chunk.chunk_id for s in await store.search(vector, top_k=2)]
        second = [s.chunk.chunk_id for s in await store.search(vector, top_k=2)]
        assert first == second


class TestFilters:
    async def test_kind_filter_restricts_results(self, store, embedder) -> None:  # type: ignore[no-untyped-def]
        await load(
            store,
            embedder,
            [
                make_doc(doc_id="fam.md", kind=DocumentKind.malware_family),
                make_doc(doc_id="tech.md", kind=DocumentKind.technique),
            ],
        )
        vector = await embedder.embed_one("accessibility overlay")
        results = await store.search(
            vector, top_k=10, filters=SearchFilter(kinds=[DocumentKind.technique])
        )
        assert {s.chunk.doc_id for s in results} == {"tech.md"}

    async def test_family_filter_is_case_insensitive(self, store, embedder) -> None:  # type: ignore[no-untyped-def]
        await load(store, embedder, [make_doc(families=["Cerberus"])])
        vector = await embedder.embed_one("overlay")
        results = await store.search(
            vector, top_k=5, filters=SearchFilter(families=["CERBERUS"])
        )
        assert results

    async def test_family_filter_excludes_unrelated_documents(self, store, embedder) -> None:  # type: ignore[no-untyped-def]
        await load(store, embedder, [make_doc(families=["cerberus"])])
        vector = await embedder.embed_one("overlay")
        results = await store.search(
            vector, top_k=5, filters=SearchFilter(families=["flubot"])
        )
        assert results == []

    async def test_mitre_and_tag_filters_apply(self, store, embedder) -> None:  # type: ignore[no-untyped-def]
        await load(store, embedder, [make_doc(mitre=["T1417.001"], tags=["overlay"])])
        vector = await embedder.embed_one("overlay")
        assert await store.search(vector, top_k=5, filters=SearchFilter(mitre=["T1417.001"]))
        assert not await store.search(vector, top_k=5, filters=SearchFilter(mitre=["T9999"]))
        assert await store.search(vector, top_k=5, filters=SearchFilter(tags=["OVERLAY"]))

    async def test_trusted_only_defaults_to_true(self) -> None:
        # The safe behaviour must be what a caller gets by not thinking about it.
        assert SearchFilter().trusted_only is True


class TestMaintenance:
    async def test_deleting_a_document_removes_all_its_chunks(self, store, embedder) -> None:  # type: ignore[no-untyped-def]
        await load(store, embedder, [make_doc(doc_id="a.md"), make_doc(doc_id="b.md")])
        before = await store.count()

        removed = await store.delete_document("a.md")

        assert removed > 0
        assert await store.count() == before - removed
        assert "a.md" not in await store.document_hashes()

    async def test_deleting_an_absent_document_is_a_no_op(self, store) -> None:  # type: ignore[no-untyped-def]
        assert await store.delete_document("nope.md") == 0

    async def test_document_hashes_expose_one_hash_per_document(self, store, embedder) -> None:  # type: ignore[no-untyped-def]
        doc = make_doc()
        await load(store, embedder, [doc])
        hashes = await store.document_hashes()
        assert hashes == {doc.doc_id: doc.content_hash}

    async def test_hashes_are_what_make_ingestion_incremental(self, store, embedder) -> None:  # type: ignore[no-untyped-def]
        original = make_doc(text="# A\n\nOriginal text body for this document.")
        await load(store, embedder, [original])
        edited = make_doc(text="# A\n\nEdited text body for this document.")
        assert (await store.document_hashes())[original.doc_id] != edited.content_hash


class TestInMemoryStoreIsARealBackend:
    async def test_it_scales_to_a_realistic_corpus(self, store, embedder) -> None:  # type: ignore[no-untyped-def]
        # A curated corpus is hundreds of documents; brute force is genuinely
        # adequate at that size, which is why this is a supported backend.
        docs = [make_doc(doc_id=f"doc{i}.md") for i in range(200)]
        await load(store, embedder, docs)
        vector = await embedder.embed_one("overlay credential theft")
        results = await store.search(vector, top_k=5)
        assert len(results) == 5
