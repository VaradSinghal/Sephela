"""Embedding backends: determinism, normalization, batching, caching."""

from __future__ import annotations

import httpx
import pytest

from ai.rag.embeddings import (
    CachingEmbedder,
    EmbeddingError,
    HashingEmbedder,
    OpenAICompatibleEmbedder,
    cosine_similarity,
    normalize,
    tokenize,
)

pytestmark = pytest.mark.anyio


class TestTokenizer:
    def test_identifiers_survive_tokenization(self) -> None:
        # These are the terms the corpus is actually searched by; splitting them
        # would destroy retrieval for exactly the queries that matter.
        assert "t1417.001" in tokenize("Technique T1417.001 applies")
        assert "bind_accessibility_service" in tokenize("BIND_ACCESSIBILITY_SERVICE required")

    def test_punctuation_is_dropped(self) -> None:
        assert tokenize("overlay, phishing!") == ["overlay", "phishing"]


class TestNormalization:
    def test_vectors_are_unit_length(self) -> None:
        vector = normalize([3.0, 4.0])
        assert cosine_similarity(vector, vector) == pytest.approx(1.0)

    def test_the_zero_vector_survives(self) -> None:
        assert normalize([0.0, 0.0]) == [0.0, 0.0]

    def test_mismatched_dimensions_score_zero_rather_than_raising(self) -> None:
        # A corpus embedded by a different model should degrade retrieval, not
        # crash an analysis mid-run.
        assert cosine_similarity([1.0, 0.0], [1.0, 0.0, 0.0]) == 0.0


class TestHashingEmbedder:
    async def test_embedding_is_deterministic(self) -> None:
        a = HashingEmbedder(dimensions=64)
        b = HashingEmbedder(dimensions=64)
        assert await a.embed_one("overlay attack") == await b.embed_one("overlay attack")

    async def test_related_text_scores_above_unrelated(self) -> None:
        embedder = HashingEmbedder(dimensions=512)
        query = await embedder.embed_one("accessibility service keylogging")
        related = await embedder.embed_one(
            "The accessibility service performs keylogging of banking apps"
        )
        unrelated = await embedder.embed_one(
            "Recipe for sourdough bread using a wheat starter"
        )
        assert cosine_similarity(query, related) > cosine_similarity(query, unrelated)

    async def test_empty_text_embeds_to_zero(self) -> None:
        vector = await HashingEmbedder(dimensions=32).embed_one("")
        assert vector == [0.0] * 32

    async def test_batch_size_matches_input(self) -> None:
        vectors = await HashingEmbedder(dimensions=16).embed(["a", "b", "c"])
        assert len(vectors) == 3
        assert all(len(v) == 16 for v in vectors)

    async def test_repetition_is_damped(self) -> None:
        # 1 + log(tf) weighting: a word repeated many times must not dominate.
        embedder = HashingEmbedder(dimensions=256)
        once = await embedder.embed_one("overlay credential theft banking")
        many = await embedder.embed_one("overlay overlay overlay overlay credential theft banking")
        assert cosine_similarity(once, many) > 0.7

    def test_zero_dimensions_is_rejected(self) -> None:
        with pytest.raises(ValueError):
            HashingEmbedder(dimensions=0)


def api_response(vectors: list[list[float]]) -> dict[str, object]:
    return {"data": [{"index": i, "embedding": v} for i, v in enumerate(vectors)]}


def client_for(handler) -> httpx.AsyncClient:  # type: ignore[no-untyped-def]
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


class TestOpenAICompatibleEmbedder:
    async def test_vectors_are_returned_normalized(self) -> None:
        client = client_for(lambda _r: httpx.Response(200, json=api_response([[3.0, 4.0]])))
        embedder = OpenAICompatibleEmbedder(
            model="text-embedding-3-small", api_key="k", dimensions=2, client=client
        )
        async with client:
            vector = await embedder.embed_one("overlay")
        assert cosine_similarity(vector, vector) == pytest.approx(1.0)

    async def test_the_api_key_is_sent(self) -> None:
        seen: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return httpx.Response(200, json=api_response([[1.0, 0.0]]))

        client = client_for(handler)
        embedder = OpenAICompatibleEmbedder(
            model="m", api_key="secret", dimensions=2, client=client
        )
        async with client:
            await embedder.embed_one("x")
        assert seen[0].headers["Authorization"] == "Bearer secret"

    async def test_batches_respect_batch_size(self) -> None:
        calls: list[int] = []

        def handler(request: httpx.Request) -> httpx.Response:
            import json as _json

            inputs = _json.loads(request.content)["input"]
            calls.append(len(inputs))
            return httpx.Response(200, json=api_response([[1.0, 0.0]] * len(inputs)))

        client = client_for(handler)
        embedder = OpenAICompatibleEmbedder(
            model="m", dimensions=2, batch_size=2, client=client
        )
        async with client:
            vectors = await embedder.embed(["a", "b", "c", "d", "e"])
        assert calls == [2, 2, 1]
        assert len(vectors) == 5

    async def test_out_of_order_responses_are_reordered_by_index(self) -> None:
        payload = {
            "data": [
                {"index": 1, "embedding": [0.0, 1.0]},
                {"index": 0, "embedding": [1.0, 0.0]},
            ]
        }
        client = client_for(lambda _r: httpx.Response(200, json=payload))
        embedder = OpenAICompatibleEmbedder(model="m", dimensions=2, client=client)
        async with client:
            vectors = await embedder.embed(["first", "second"])
        assert vectors[0] == [1.0, 0.0]
        assert vectors[1] == [0.0, 1.0]

    async def test_http_errors_raise_rather_than_returning_partial_vectors(self) -> None:
        # A half-embedded corpus produces silently meaningless similarity scores,
        # which is worse than a loud ingestion failure.
        client = client_for(lambda _r: httpx.Response(500, json={}))
        embedder = OpenAICompatibleEmbedder(model="m", dimensions=2, client=client)
        async with client:
            with pytest.raises(EmbeddingError):
                await embedder.embed_one("x")

    async def test_a_short_response_is_an_error(self) -> None:
        client = client_for(lambda _r: httpx.Response(200, json=api_response([[1.0, 0.0]])))
        embedder = OpenAICompatibleEmbedder(model="m", dimensions=2, client=client)
        async with client:
            with pytest.raises(EmbeddingError):
                await embedder.embed(["a", "b"])

    async def test_non_json_response_is_an_error(self) -> None:
        client = client_for(lambda _r: httpx.Response(200, text="<html>nope</html>"))
        embedder = OpenAICompatibleEmbedder(model="m", dimensions=2, client=client)
        async with client:
            with pytest.raises(EmbeddingError):
                await embedder.embed_one("x")

    async def test_network_failure_is_an_embedding_error(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused", request=request)

        client = client_for(handler)
        embedder = OpenAICompatibleEmbedder(model="m", dimensions=2, client=client)
        async with client:
            with pytest.raises(EmbeddingError):
                await embedder.embed_one("x")

    async def test_empty_input_makes_no_call(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
            raise AssertionError("should not be called")

        client = client_for(handler)
        embedder = OpenAICompatibleEmbedder(model="m", dimensions=2, client=client)
        async with client:
            assert await embedder.embed([]) == []


class CountingEmbedder(HashingEmbedder):
    def __init__(self) -> None:
        super().__init__(dimensions=32)
        self.calls = 0

    async def embed(self, texts: list[str]) -> list[list[float]]:
        self.calls += len(texts)
        return await super().embed(texts)


class TestCachingEmbedder:
    async def test_repeat_text_is_not_re_embedded(self) -> None:
        inner = CountingEmbedder()
        cached = CachingEmbedder(inner)

        await cached.embed_one("overlay")
        await cached.embed_one("overlay")

        assert inner.calls == 1
        assert cached.hits == 1
        assert cached.misses == 1

    async def test_only_the_missing_members_of_a_batch_are_embedded(self) -> None:
        inner = CountingEmbedder()
        cached = CachingEmbedder(inner)

        await cached.embed(["a", "b"])
        await cached.embed(["b", "c"])

        assert inner.calls == 3  # a, b, then only c

    async def test_results_match_the_inner_embedder(self) -> None:
        inner = HashingEmbedder(dimensions=32)
        cached = CachingEmbedder(HashingEmbedder(dimensions=32))
        assert await cached.embed_one("overlay") == await inner.embed_one("overlay")

    async def test_eviction_keeps_the_cache_bounded(self) -> None:
        cached = CachingEmbedder(HashingEmbedder(dimensions=16), max_entries=2)
        await cached.embed(["a", "b", "c"])
        assert len(cached._cache) <= 2

    async def test_order_is_preserved(self) -> None:
        cached = CachingEmbedder(HashingEmbedder(dimensions=32))
        await cached.embed_one("b")
        vectors = await cached.embed(["a", "b"])
        direct = await HashingEmbedder(dimensions=32).embed(["a", "b"])
        assert vectors == direct
