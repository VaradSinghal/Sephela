"""
ai/rag/qdrant.py — Qdrant-backed vector store (the reserved production backend).

Talks Qdrant's REST API over ``httpx`` rather than pulling in ``qdrant-client``.
The surface this store needs is four endpoints, the ``ai/`` package already
depends on httpx for LLM calls, and avoiding a client library keeps its version
skew and gRPC dependency out of a service whose real cost centre is LLM tokens.
If richer features (quantization, sharding config, snapshots) are ever needed,
they belong in an ops tool, not in the retrieval path.

Two implementation notes that are not obvious:

**Point ids are UUID5 of ``chunk_id``.** Qdrant only accepts unsigned integers or
UUIDs as point ids, while chunk ids are readable strings like
``families/cerberus.md#3``. A UUID5 derivation is deterministic, so re-ingesting
the same chunk overwrites its point instead of duplicating it — which is what
makes ingestion idempotent.

**Filters are pushed into the Qdrant query**, not applied client-side. Beyond the
efficiency, it means the ``trusted_only`` constraint is enforced by the database:
an untrusted point cannot be returned and then need discarding.
"""

from __future__ import annotations

import uuid
from typing import Any

from ai.rag.embeddings import normalize
from ai.rag.models import Chunk, ScoredChunk, is_trusted
from ai.rag.store import SearchFilter, VectorStore, VectorStoreError

DEFAULT_COLLECTION = "sephela_knowledge"
#: Namespace for deriving point UUIDs from chunk ids. Fixed forever — changing it
#: would orphan every existing point.
_POINT_NAMESPACE = uuid.UUID("6f9a1f2c-58d1-4f7e-9a3b-2c1d4e5f6a7b")


def point_id(chunk_id: str) -> str:
    return str(uuid.uuid5(_POINT_NAMESPACE, chunk_id))


class QdrantVectorStore(VectorStore):
    """Vector store over a Qdrant collection."""

    def __init__(
        self,
        *,
        url: str = "http://localhost:6333",
        collection: str = DEFAULT_COLLECTION,
        dimensions: int = 512,
        api_key: str | None = None,
        timeout_secs: float = 15.0,
        client: Any = None,
    ) -> None:
        self.url = url.rstrip("/")
        self.collection = collection
        self.dimensions = dimensions
        self.api_key = api_key
        self.timeout_secs = timeout_secs
        self._client = client

    # ---- HTTP plumbing ---------------------------------------------------

    async def _request(
        self, method: str, path: str, *, json_body: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        import httpx

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["api-key"] = self.api_key

        owns_client = self._client is None
        client = self._client or httpx.AsyncClient(timeout=httpx.Timeout(self.timeout_secs))
        try:
            response = await client.request(
                method, f"{self.url}{path}", headers=headers, json=json_body
            )
        except httpx.HTTPError as exc:
            raise VectorStoreError(f"qdrant: {type(exc).__name__}: {exc}") from exc
        finally:
            if owns_client:
                await client.aclose()

        if response.status_code == 404:
            # Collection-not-found is a normal state before ensure_collection.
            return {"status": "not_found", "result": None}
        if response.status_code >= 400:
            raise VectorStoreError(
                f"qdrant: HTTP {response.status_code} on {method} {path}: "
                f"{response.text[:200]}"
            )
        try:
            payload = response.json()
        except ValueError as exc:
            raise VectorStoreError("qdrant: response was not valid JSON") from exc
        return payload if isinstance(payload, dict) else {"result": payload}

    # ---- Collection lifecycle -------------------------------------------

    async def collection_exists(self) -> bool:
        payload = await self._request("GET", f"/collections/{self.collection}")
        return payload.get("status") != "not_found" and payload.get("result") is not None

    async def ensure_collection(self) -> None:
        """Create the collection and its payload indexes if absent.

        Payload indexes on the filtered fields are created explicitly: without
        them Qdrant still filters correctly but scans, which turns the
        ``trusted_only`` predicate into a full-collection walk on every query.
        """
        if await self.collection_exists():
            return

        await self._request(
            "PUT",
            f"/collections/{self.collection}",
            json_body={"vectors": {"size": self.dimensions, "distance": "Cosine"}},
        )
        for field_name, schema in (
            ("trust", "keyword"),
            ("kind", "keyword"),
            ("doc_id", "keyword"),
            ("families", "keyword"),
            ("mitre", "keyword"),
            ("tags", "keyword"),
        ):
            await self._request(
                "PUT",
                f"/collections/{self.collection}/index?wait=true",
                json_body={"field_name": field_name, "field_schema": schema},
            )

    # ---- VectorStore interface ------------------------------------------

    async def upsert(self, chunks: list[Chunk], vectors: list[list[float]]) -> int:
        if len(chunks) != len(vectors):
            raise VectorStoreError(
                f"upsert got {len(chunks)} chunks and {len(vectors)} vectors"
            )
        if not chunks:
            return 0

        points = []
        for chunk, vector in zip(chunks, vectors, strict=True):
            if not is_trusted(chunk.trust):
                raise VectorStoreError(
                    f"refusing to store untrusted chunk {chunk.chunk_id} "
                    f"(trust={chunk.trust.value})"
                )
            points.append(
                {
                    "id": point_id(chunk.chunk_id),
                    "vector": normalize(vector),
                    "payload": chunk.payload(),
                }
            )

        await self._request(
            "PUT",
            f"/collections/{self.collection}/points?wait=true",
            json_body={"points": points},
        )
        return len(points)

    async def search(
        self, vector: list[float], *, top_k: int, filters: SearchFilter | None = None
    ) -> list[ScoredChunk]:
        if top_k <= 0:
            return []

        body: dict[str, Any] = {
            "vector": normalize(vector),
            "limit": top_k,
            "with_payload": True,
        }
        qdrant_filter = _build_filter(filters or SearchFilter())
        if qdrant_filter:
            body["filter"] = qdrant_filter

        payload = await self._request(
            "POST", f"/collections/{self.collection}/points/search", json_body=body
        )
        results = payload.get("result")
        if not isinstance(results, list):
            return []

        scored: list[ScoredChunk] = []
        for item in results:
            if not isinstance(item, dict):
                continue
            item_payload = item.get("payload")
            if not isinstance(item_payload, dict):
                continue
            chunk = Chunk.from_payload(item_payload)
            score = item.get("score")
            scored.append(
                ScoredChunk(
                    chunk=chunk,
                    score=float(score) if isinstance(score, (int, float)) else 0.0,
                )
            )
        return scored

    async def delete_document(self, doc_id: str) -> int:
        """Delete by payload filter — chunk count is unknown to the caller."""
        await self._request(
            "POST",
            f"/collections/{self.collection}/points/delete?wait=true",
            json_body={
                "filter": {"must": [{"key": "doc_id", "match": {"value": doc_id}}]}
            },
        )
        # Qdrant's delete-by-filter reports operation status, not a row count.
        return -1

    async def count(self) -> int:
        payload = await self._request(
            "POST", f"/collections/{self.collection}/points/count", json_body={"exact": True}
        )
        result = payload.get("result")
        if isinstance(result, dict) and isinstance(result.get("count"), int):
            return int(result["count"])
        return 0

    async def document_hashes(self) -> dict[str, str]:
        """Scroll the collection collecting one content hash per document.

        Only the two payload fields needed are requested and vectors are excluded,
        so the scan stays cheap even on a large collection — this runs once per
        ingestion to decide what changed.
        """
        hashes: dict[str, str] = {}
        offset: Any = None

        while True:
            body: dict[str, Any] = {
                "limit": 256,
                "with_payload": ["doc_id", "content_hash"],
                "with_vector": False,
            }
            if offset is not None:
                body["offset"] = offset

            payload = await self._request(
                "POST", f"/collections/{self.collection}/points/scroll", json_body=body
            )
            result = payload.get("result")
            if not isinstance(result, dict):
                break

            for point in result.get("points") or []:
                if not isinstance(point, dict):
                    continue
                point_payload = point.get("payload")
                if not isinstance(point_payload, dict):
                    continue
                doc_id = point_payload.get("doc_id")
                content_hash = point_payload.get("content_hash")
                if isinstance(doc_id, str) and isinstance(content_hash, str):
                    hashes.setdefault(doc_id, content_hash)

            offset = result.get("next_page_offset")
            if offset is None:
                break
        return hashes


def _build_filter(filters: SearchFilter) -> dict[str, Any]:
    """Translate a ``SearchFilter`` into Qdrant's filter DSL."""
    must: list[dict[str, Any]] = []

    if filters.trusted_only:
        # `any` over the allowlist rather than excluding sample_derived: a new
        # untrusted trust value added later is then denied by default.
        from ai.rag.models import TRUSTED_SOURCES

        must.append(
            {"key": "trust", "match": {"any": sorted(t.value for t in TRUSTED_SOURCES)}}
        )
    if filters.kinds:
        must.append({"key": "kind", "match": {"any": [k.value for k in filters.kinds]}})
    if filters.families:
        must.append(
            {"key": "families", "match": {"any": [f.lower() for f in filters.families]}}
        )
    if filters.mitre:
        must.append({"key": "mitre", "match": {"any": list(filters.mitre)}})
    if filters.tags:
        must.append({"key": "tags", "match": {"any": [t.lower() for t in filters.tags]}})

    return {"must": must} if must else {}
