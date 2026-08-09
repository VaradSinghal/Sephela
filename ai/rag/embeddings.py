"""
ai/rag/embeddings.py — Embedding backends behind one narrow interface.

Two implementations ship, for two different reasons.

**HashingEmbedder** is the default. It is a deterministic bag-of-n-grams
projection — no API key, no network, no model download, identical vectors on
every machine. That matters more here than embedding quality, because most of
what this corpus is queried by is *exact vocabulary*: family names (``cerberus``),
permission constants (``BIND_ACCESSIBILITY_SERVICE``), MITRE ids (``T1417.001``).
Lexical overlap retrieves those correctly, so the zero-configuration path is
genuinely useful rather than a stub, and the test suite is fast and hermetic.
Its limitation is real and worth stating: it cannot match paraphrases
("screen-reading abuse" → "accessibility service"). Deployments that need
semantic recall configure a real embedder.

**OpenAICompatibleEmbedder** covers that case, speaking the ``/v1/embeddings``
protocol that OpenAI, Azure, vLLM, Ollama, and LM Studio all implement — so one
adapter reaches both hosted and self-hosted models, the latter mattering for the
data-sovereignty requirement in ``docs/architecture/01-tech-stack.md``.

Both are wrapped by ``CachingEmbedder`` because ingestion and retrieval re-embed
the same text constantly (every retry, every re-ingest of an unchanged corpus).
"""

from __future__ import annotations

import hashlib
import math
import re
from abc import ABC, abstractmethod
from typing import Any

DEFAULT_DIMENSIONS = 512

#: Tokenizer for the hashing embedder. Keeps dots and underscores so
#: ``T1417.001`` and ``BIND_ACCESSIBILITY_SERVICE`` stay single tokens — splitting
#: them would destroy exactly the identifiers this corpus is searched by.
_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")


class EmbeddingError(RuntimeError):
    """An embedding backend could not produce vectors."""


class Embedder(ABC):
    """Turns text into unit-length vectors.

    Vectors are always L2-normalized, which makes cosine similarity a plain dot
    product — the vector stores rely on that, so normalization is the interface's
    responsibility rather than each store's.
    """

    name: str = "embedder"

    def __init__(self, dimensions: int = DEFAULT_DIMENSIONS) -> None:
        if dimensions <= 0:
            raise ValueError("dimensions must be positive")
        self.dimensions = dimensions

    @abstractmethod
    async def embed(self, texts: list[str]) -> list[list[float]]:
        """Embed a batch. Must return one vector per input, in order."""

    async def embed_one(self, text: str) -> list[float]:
        vectors = await self.embed([text])
        if not vectors:  # pragma: no cover — defensive
            raise EmbeddingError(f"{self.name}: no vector returned")
        return vectors[0]


def normalize(vector: list[float]) -> list[float]:
    """L2-normalize, mapping the zero vector to itself rather than dividing by 0."""
    norm = math.sqrt(sum(v * v for v in vector))
    if norm == 0.0:
        return list(vector)
    return [v / norm for v in vector]


def cosine_similarity(a: list[float], b: list[float]) -> float:
    """Dot product of two vectors, assumed unit-length.

    Mismatched dimensions return 0.0 rather than raising: a corpus embedded with
    a different model than the current query is a configuration problem that
    should degrade retrieval, not crash an analysis mid-run.
    """
    if len(a) != len(b):
        return 0.0
    return sum(x * y for x, y in zip(a, b, strict=True))


def tokenize(text: str) -> list[str]:
    """Lowercased tokens, preserving identifier punctuation."""
    return [m.group(0).lower() for m in _TOKEN_RE.finditer(text)]


class HashingEmbedder(Embedder):
    """Deterministic lexical embedding via the hashing trick.

    Unigrams and bigrams are hashed into ``dimensions`` buckets with sublinear
    term-frequency weighting (``1 + log tf``), the standard damping that stops a
    word repeated twenty times from dominating a passage that merely mentions it.
    Bigrams give a little word-order sensitivity, so "install packages" scores
    above a document that happens to contain both words far apart.
    """

    name = "hashing"

    def __init__(self, dimensions: int = DEFAULT_DIMENSIONS, *, use_bigrams: bool = True) -> None:
        super().__init__(dimensions)
        self.use_bigrams = use_bigrams

    def _bucket(self, token: str) -> int:
        digest = hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest()
        return int.from_bytes(digest, "big") % self.dimensions

    def _sign(self, token: str) -> float:
        """Signed hashing: halves the expected collision bias for free."""
        digest = hashlib.blake2b(token.encode("utf-8"), digest_size=1).digest()
        return 1.0 if digest[0] & 1 else -1.0

    def embed_sync(self, text: str) -> list[float]:
        tokens = tokenize(text)
        if not tokens:
            return [0.0] * self.dimensions

        counts: dict[str, int] = {}
        for token in tokens:
            counts[token] = counts.get(token, 0) + 1
        if self.use_bigrams:
            # Deliberately unequal lengths — the last token has no successor.
            for first, second in zip(tokens, tokens[1:], strict=False):
                bigram = f"{first}_{second}"
                counts[bigram] = counts.get(bigram, 0) + 1

        vector = [0.0] * self.dimensions
        for token, count in counts.items():
            weight = 1.0 + math.log(count)
            vector[self._bucket(token)] += weight * self._sign(token)
        return normalize(vector)

    async def embed(self, texts: list[str]) -> list[list[float]]:
        return [self.embed_sync(text) for text in texts]


class OpenAICompatibleEmbedder(Embedder):
    """Calls any ``POST /v1/embeddings`` endpoint (OpenAI, Azure, vLLM, Ollama).

    Batches are sent whole because these APIs bill and rate-limit per request, not
    per input. A failed batch raises rather than returning partial vectors: a
    corpus half-embedded by one model and half by another silently produces
    garbage similarity scores, which is far worse than a loud ingestion failure.
    """

    name = "openai_compatible"

    def __init__(
        self,
        *,
        model: str,
        api_key: str | None = None,
        base_url: str = "https://api.openai.com/v1",
        dimensions: int = 1536,
        batch_size: int = 64,
        timeout_secs: float = 30.0,
        client: Any = None,
    ) -> None:
        super().__init__(dimensions)
        self.model = model
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.batch_size = max(1, batch_size)
        self.timeout_secs = timeout_secs
        self._client = client

    async def embed(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []

        vectors: list[list[float]] = []
        for start in range(0, len(texts), self.batch_size):
            batch = texts[start : start + self.batch_size]
            vectors.extend(await self._embed_batch(batch))
        return vectors

    async def _embed_batch(self, batch: list[str]) -> list[list[float]]:
        import httpx

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        owns_client = self._client is None
        client = self._client or httpx.AsyncClient(timeout=httpx.Timeout(self.timeout_secs))
        try:
            response = await client.post(
                f"{self.base_url}/embeddings",
                headers=headers,
                json={"model": self.model, "input": batch},
            )
        except httpx.HTTPError as exc:
            raise EmbeddingError(f"{self.name}: {type(exc).__name__}: {exc}") from exc
        finally:
            if owns_client:
                await client.aclose()

        if response.status_code >= 400:
            raise EmbeddingError(
                f"{self.name}: embeddings endpoint returned HTTP {response.status_code}"
            )
        try:
            payload = response.json()
        except ValueError as exc:
            raise EmbeddingError(f"{self.name}: response was not valid JSON") from exc

        data = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(data, list) or len(data) != len(batch):
            raise EmbeddingError(
                f"{self.name}: expected {len(batch)} embeddings, got "
                f"{len(data) if isinstance(data, list) else 'none'}"
            )

        # Providers are documented to return data in input order, but the objects
        # carry an explicit index — trusting that over list order costs nothing
        # and protects against a reordering proxy.
        ordered: list[list[float]] = [[] for _ in batch]
        for position, item in enumerate(data):
            if not isinstance(item, dict):
                raise EmbeddingError(f"{self.name}: malformed embedding entry")
            index = item.get("index")
            slot = index if isinstance(index, int) and 0 <= index < len(batch) else position
            raw = item.get("embedding")
            if not isinstance(raw, list) or not raw:
                raise EmbeddingError(f"{self.name}: entry {slot} carried no embedding")
            ordered[slot] = normalize([float(v) for v in raw])

        if any(not vec for vec in ordered):
            raise EmbeddingError(f"{self.name}: response was missing an embedding")
        return ordered


class CachingEmbedder(Embedder):
    """Memoizes an inner embedder on exact text.

    Ingestion re-embeds an unchanged corpus on every run and retrieval re-embeds
    the same query on every agent, so the hit rate is high and the win is direct:
    fewer paid API calls, faster runs. Keyed on a digest rather than the text so
    the cache does not retain a second copy of the whole corpus.
    """

    name = "caching"

    def __init__(self, inner: Embedder, *, max_entries: int = 4096) -> None:
        super().__init__(inner.dimensions)
        self.inner = inner
        self.max_entries = max(1, max_entries)
        self._cache: dict[str, list[float]] = {}
        self.hits = 0
        self.misses = 0

    @staticmethod
    def _key(text: str) -> str:
        return hashlib.blake2b(text.encode("utf-8"), digest_size=16).hexdigest()

    async def embed(self, texts: list[str]) -> list[list[float]]:
        keys = [self._key(t) for t in texts]
        missing_positions = [i for i, key in enumerate(keys) if key not in self._cache]

        if missing_positions:
            self.misses += len(missing_positions)
            fresh = await self.inner.embed([texts[i] for i in missing_positions])
            for position, vector in zip(missing_positions, fresh, strict=True):
                self._store(keys[position], vector)

        self.hits += len(texts) - len(missing_positions)
        # A concurrent eviction could drop a just-written key; fall back to the
        # inner result shape rather than raising a KeyError mid-analysis.
        return [self._cache.get(key, [0.0] * self.dimensions) for key in keys]

    def _store(self, key: str, vector: list[float]) -> None:
        if len(self._cache) >= self.max_entries:
            # Plain FIFO eviction: access recency buys little here because the
            # working set is one corpus plus a handful of queries.
            self._cache.pop(next(iter(self._cache)))
        self._cache[key] = vector
