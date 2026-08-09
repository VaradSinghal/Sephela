"""Qdrant store: request construction, filter translation, and payload round-trip.

Driven through ``httpx.MockTransport`` so the real REST bodies are exercised
without a running Qdrant. No test here needs a container.
"""

from __future__ import annotations

import json

import httpx
import pytest

from ai.rag.chunking import chunk_document
from ai.rag.models import DocumentKind, SourceTrust
from ai.rag.qdrant import QdrantVectorStore, point_id
from ai.rag.store import SearchFilter, VectorStoreError
from ai.tests.test_rag.conftest import make_doc

pytestmark = pytest.mark.anyio


class FakeQdrant:
    """Records requests and replies from a scripted route table."""

    def __init__(self, routes: dict[str, object] | None = None) -> None:
        self.routes = routes or {}
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        for fragment, payload in self.routes.items():
            if fragment in str(request.url):
                if isinstance(payload, int):
                    return httpx.Response(payload, json={})
                return httpx.Response(200, json=payload)
        return httpx.Response(200, json={"result": True, "status": "ok"})

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handler))

    def body(self, index: int = 0) -> dict[str, object]:
        return json.loads(self.requests[index].content)


def store_for(fake: FakeQdrant) -> QdrantVectorStore:
    return QdrantVectorStore(
        url="http://qdrant:6333", collection="test_kb", dimensions=256, client=fake.client()
    )


class TestPointIds:
    def test_ids_are_deterministic_uuids(self) -> None:
        # Qdrant only accepts ints or UUIDs, and re-ingesting a chunk must
        # overwrite its point rather than duplicate it.
        assert point_id("families/cerberus.md#3") == point_id("families/cerberus.md#3")
        assert point_id("a#0") != point_id("a#1")
        assert len(point_id("a#0")) == 36


class TestUpsert:
    async def test_points_carry_the_full_payload(self, embedder) -> None:  # type: ignore[no-untyped-def]
        fake = FakeQdrant()
        chunks = chunk_document(make_doc())
        vectors = await embedder.embed([c.text for c in chunks])

        written = await store_for(fake).upsert(chunks, vectors)

        assert written == len(chunks)
        point = fake.body()["points"][0]  # type: ignore[index]
        assert point["id"] == point_id(chunks[0].chunk_id)
        assert point["payload"]["trust"] == "curated"
        assert point["payload"]["doc_id"] == chunks[0].doc_id
        assert point["payload"]["text"]

    async def test_untrusted_chunks_are_refused_before_any_request(self, embedder) -> None:  # type: ignore[no-untyped-def]
        fake = FakeQdrant()
        chunks = chunk_document(make_doc(trust=SourceTrust.sample_derived))
        vectors = await embedder.embed([c.text for c in chunks])

        with pytest.raises(VectorStoreError, match="untrusted"):
            await store_for(fake).upsert(chunks, vectors)
        assert fake.requests == []

    async def test_an_empty_batch_makes_no_request(self) -> None:
        fake = FakeQdrant()
        assert await store_for(fake).upsert([], []) == 0
        assert fake.requests == []

    async def test_mismatched_vector_count_is_an_error(self, embedder) -> None:  # type: ignore[no-untyped-def]
        fake = FakeQdrant()
        with pytest.raises(VectorStoreError):
            await store_for(fake).upsert(chunk_document(make_doc()), [])


class TestSearch:
    def payload_for(self, chunk) -> dict[str, object]:  # type: ignore[no-untyped-def]
        return {"result": [{"score": 0.87, "payload": chunk.payload()}]}

    async def test_results_round_trip_through_the_payload(self, embedder) -> None:  # type: ignore[no-untyped-def]
        chunk = chunk_document(make_doc())[0]
        fake = FakeQdrant({"/points/search": self.payload_for(chunk)})
        vector = await embedder.embed_one("overlay")

        results = await store_for(fake).search(vector, top_k=3)

        assert len(results) == 1
        assert results[0].score == pytest.approx(0.87)
        assert results[0].chunk.chunk_id == chunk.chunk_id
        assert results[0].chunk.trust is SourceTrust.curated
        assert results[0].chunk.families == chunk.families

    async def test_trusted_only_is_pushed_into_the_query(self, embedder) -> None:  # type: ignore[no-untyped-def]
        # Enforced by the database, so an untrusted point cannot be returned and
        # then need discarding.
        fake = FakeQdrant({"/points/search": {"result": []}})
        vector = await embedder.embed_one("overlay")

        await store_for(fake).search(vector, top_k=3, filters=SearchFilter())

        conditions = fake.body()["filter"]["must"]  # type: ignore[index]
        trust_condition = next(c for c in conditions if c["key"] == "trust")
        assert sorted(trust_condition["match"]["any"]) == ["curated", "vendor"]

    async def test_kind_family_mitre_and_tag_filters_translate(self, embedder) -> None:  # type: ignore[no-untyped-def]
        fake = FakeQdrant({"/points/search": {"result": []}})
        vector = await embedder.embed_one("overlay")

        await store_for(fake).search(
            vector,
            top_k=3,
            filters=SearchFilter(
                kinds=[DocumentKind.technique],
                families=["Cerberus"],
                mitre=["T1417.001"],
                tags=["Overlay"],
            ),
        )

        keys = {c["key"]: c for c in fake.body()["filter"]["must"]}  # type: ignore[index]
        assert keys["kind"]["match"]["any"] == ["technique"]
        assert keys["families"]["match"]["any"] == ["cerberus"]  # lowercased
        assert keys["mitre"]["match"]["any"] == ["T1417.001"]
        assert keys["tags"]["match"]["any"] == ["overlay"]

    async def test_an_unfiltered_search_sends_no_filter_key(self, embedder) -> None:  # type: ignore[no-untyped-def]
        fake = FakeQdrant({"/points/search": {"result": []}})
        vector = await embedder.embed_one("overlay")

        await store_for(fake).search(
            vector, top_k=3, filters=SearchFilter(trusted_only=False)
        )

        assert "filter" not in fake.body()

    async def test_zero_top_k_makes_no_request(self, embedder) -> None:  # type: ignore[no-untyped-def]
        fake = FakeQdrant()
        vector = await embedder.embed_one("overlay")
        assert await store_for(fake).search(vector, top_k=0) == []
        assert fake.requests == []

    async def test_malformed_results_are_skipped(self, embedder) -> None:  # type: ignore[no-untyped-def]
        fake = FakeQdrant({"/points/search": {"result": ["nonsense", {"score": 1.0}]}})
        vector = await embedder.embed_one("overlay")
        assert await store_for(fake).search(vector, top_k=3) == []

    async def test_a_corrupt_trust_value_fails_closed(self, embedder) -> None:  # type: ignore[no-untyped-def]
        # A hand-edited or corrupted payload must not become promptable.
        chunk = chunk_document(make_doc())[0]
        payload = chunk.payload()
        payload["trust"] = "definitely-fine"
        fake = FakeQdrant({"/points/search": {"result": [{"score": 1.0, "payload": payload}]}})
        vector = await embedder.embed_one("overlay")

        results = await store_for(fake).search(vector, top_k=3)

        assert results[0].chunk.trust is SourceTrust.unknown
        assert results[0].chunk.trusted is False


class TestCollectionLifecycle:
    async def test_an_absent_collection_is_created_with_payload_indexes(self) -> None:
        # Without the indexes Qdrant still filters correctly but scans, turning
        # the trust predicate into a full-collection walk per query.
        fake = FakeQdrant({"/collections/test_kb": 404})
        await store_for(fake).ensure_collection()

        methods = [(r.method, str(r.url)) for r in fake.requests]
        assert methods[0][0] == "GET"
        assert any(m == "PUT" and m2.endswith("/collections/test_kb") for m, m2 in methods)
        indexed = [json.loads(r.content)["field_name"] for r in fake.requests if "/index" in str(r.url)]
        assert set(indexed) == {"trust", "kind", "doc_id", "families", "mitre", "tags"}

    async def test_an_existing_collection_is_left_alone(self) -> None:
        fake = FakeQdrant({"/collections/test_kb": {"result": {"status": "green"}}})
        await store_for(fake).ensure_collection()
        assert len(fake.requests) == 1  # the existence probe only


class TestMaintenance:
    async def test_delete_uses_a_doc_id_filter(self) -> None:
        fake = FakeQdrant()
        await store_for(fake).delete_document("families/cerberus.md")

        condition = fake.body()["filter"]["must"][0]  # type: ignore[index]
        assert condition == {"key": "doc_id", "match": {"value": "families/cerberus.md"}}

    async def test_count_reads_the_exact_count(self) -> None:
        fake = FakeQdrant({"/points/count": {"result": {"count": 42}}})
        assert await store_for(fake).count() == 42
        assert fake.body()["exact"] is True

    async def test_document_hashes_pages_through_scroll(self) -> None:
        pages = iter(
            [
                {
                    "result": {
                        "points": [{"payload": {"doc_id": "a.md", "content_hash": "h1"}}],
                        "next_page_offset": 1,
                    }
                },
                {
                    "result": {
                        "points": [{"payload": {"doc_id": "b.md", "content_hash": "h2"}}],
                        "next_page_offset": None,
                    }
                },
            ]
        )

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=next(pages))

        store = QdrantVectorStore(
            collection="test_kb",
            dimensions=256,
            client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        )
        assert await store.document_hashes() == {"a.md": "h1", "b.md": "h2"}

    async def test_the_scroll_requests_only_the_fields_it_needs(self) -> None:
        fake = FakeQdrant({"/points/scroll": {"result": {"points": [], "next_page_offset": None}}})
        await store_for(fake).document_hashes()

        body = fake.body()
        assert body["with_payload"] == ["doc_id", "content_hash"]
        assert body["with_vector"] is False


class TestErrorHandling:
    async def test_a_server_error_raises(self, embedder) -> None:  # type: ignore[no-untyped-def]
        fake = FakeQdrant({"/points/search": 500})
        vector = await embedder.embed_one("overlay")
        with pytest.raises(VectorStoreError):
            await store_for(fake).search(vector, top_k=1)

    async def test_a_connection_failure_raises_a_store_error(self, embedder) -> None:  # type: ignore[no-untyped-def]
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused", request=request)

        store = QdrantVectorStore(
            dimensions=256, client=httpx.AsyncClient(transport=httpx.MockTransport(handler))
        )
        vector = await embedder.embed_one("overlay")
        with pytest.raises(VectorStoreError, match="ConnectError"):
            await store.search(vector, top_k=1)

    async def test_the_api_key_is_sent_when_configured(self, embedder) -> None:  # type: ignore[no-untyped-def]
        fake = FakeQdrant({"/points/search": {"result": []}})
        store = QdrantVectorStore(
            collection="test_kb", dimensions=256, api_key="qk", client=fake.client()
        )
        vector = await embedder.embed_one("overlay")
        await store.search(vector, top_k=1)
        assert fake.requests[0].headers["api-key"] == "qk"
