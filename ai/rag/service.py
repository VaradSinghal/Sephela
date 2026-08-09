"""
ai/rag/service.py — The façade the AI layer actually calls.

Agents should not know whether knowledge lives in memory or in Qdrant, which
embedder is configured, or how the trusted-source rule is enforced. They need one
call: *given this evidence, hand me a reference block for my prompt*. Everything
else is this module's problem.

Concentrating the wiring here also means the feature flag lives in exactly one
place. Phase 12 is flag-gated per ``docs/architecture/11-dev-standards.md``
("feature flags for phased capabilities"), and a disabled service returns an empty
block rather than raising — so every agent's prompt-building path is identical
whether RAG is on or off, and turning it off cannot break an analysis.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from ai.rag.context import context_summary, render_context
from ai.rag.embeddings import (
    CachingEmbedder,
    Embedder,
    HashingEmbedder,
    OpenAICompatibleEmbedder,
)
from ai.rag.ingest import IngestionReport, KnowledgeIngestor
from ai.rag.models import RetrievalResult
from ai.rag.qdrant import QdrantVectorStore
from ai.rag.query import build_query
from ai.rag.retriever import KnowledgeRetriever
from ai.rag.store import InMemoryVectorStore, VectorStore

_LOG = logging.getLogger("sephela.rag")

DEFAULT_TOP_K = 5
DEFAULT_MAX_TOKENS = 1200


def _env_flag(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, "").strip() or default)
    except ValueError:
        return default


class KnowledgeService:
    """Retrieval façade: evidence in, prompt-ready reference block out."""

    def __init__(
        self,
        *,
        store: VectorStore,
        embedder: Embedder,
        enabled: bool = True,
        top_k: int = DEFAULT_TOP_K,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> None:
        self.store = store
        self.embedder = embedder
        self.enabled = enabled
        self.top_k = top_k
        self.max_tokens = max_tokens
        self.retriever = KnowledgeRetriever(store, embedder)
        #: Trace of the most recent retrieval per agent, for auditing a finding
        #: that leaned on background knowledge.
        self.last_summary: dict[str, dict[str, Any]] = {}

    async def retrieve(
        self,
        evidence: dict[str, Any],
        *,
        findings: list[dict[str, Any]] | None = None,
        agent: str | None = None,
    ) -> RetrievalResult:
        query = build_query(
            evidence,
            findings=findings,
            agent=agent,
            top_k=self.top_k,
            max_tokens=self.max_tokens,
        )
        result = await self.retriever.retrieve(query)
        self.last_summary[agent or "unknown"] = context_summary(result)
        return result

    async def context_for(
        self,
        evidence: dict[str, Any],
        *,
        findings: list[dict[str, Any]] | None = None,
        agent: str | None = None,
    ) -> str:
        """Return a rendered reference block, or ``""`` if there is nothing to add.

        Returning a string (never None, never raising) is what lets every agent
        append the result unconditionally.
        """
        if not self.enabled:
            return ""
        result = await self.retrieve(evidence, findings=findings, agent=agent)
        return render_context(result)

    async def ingest(
        self, corpus_dir: Path | str | None = None, *, force: bool = False
    ) -> IngestionReport:
        return await KnowledgeIngestor(self.store, self.embedder).ingest_directory(
            corpus_dir, force=force
        )

    async def count(self) -> int:
        try:
            return await self.store.count()
        except Exception as exc:  # noqa: BLE001 — a probe must not raise
            _LOG.warning("rag_count_failed: %s: %s", type(exc).__name__, exc)
            return 0


def build_embedder() -> Embedder:
    """Construct the configured embedder, defaulting to the offline one.

    ``RAG_EMBEDDING_MODEL`` selects a remote model; without it the deterministic
    hashing embedder is used, so the default path needs no credentials. Either way
    the result is wrapped in the cache, because both ingestion and retrieval
    re-embed identical text constantly.
    """
    model = os.getenv("RAG_EMBEDDING_MODEL", "").strip()
    if not model:
        return CachingEmbedder(HashingEmbedder(dimensions=_env_int("RAG_DIMENSIONS", 512)))

    return CachingEmbedder(
        OpenAICompatibleEmbedder(
            model=model,
            api_key=os.getenv("RAG_EMBEDDING_API_KEY") or os.getenv("OPENAI_API_KEY"),
            base_url=os.getenv("RAG_EMBEDDING_BASE_URL", "https://api.openai.com/v1"),
            dimensions=_env_int("RAG_DIMENSIONS", 1536),
        )
    )


def build_store(dimensions: int) -> VectorStore:
    """Construct the configured vector store, defaulting to in-memory.

    In-memory is a real choice, not a placeholder: a curated corpus of a few
    thousand chunks searches faster by brute force than by network round trip. Set
    ``RAG_VECTOR_BACKEND=qdrant`` once the corpus outgrows that.
    """
    backend = os.getenv("RAG_VECTOR_BACKEND", "memory").strip().lower()
    if backend == "qdrant":
        return QdrantVectorStore(
            url=os.getenv("QDRANT_URL", "http://localhost:6333"),
            collection=os.getenv("QDRANT_COLLECTION", "sephela_knowledge"),
            api_key=os.getenv("QDRANT_API_KEY"),
            dimensions=dimensions,
        )
    return InMemoryVectorStore()


async def build_knowledge_service(
    *,
    corpus_dir: Path | str | None = None,
    ingest: bool = True,
    store: VectorStore | None = None,
    embedder: Embedder | None = None,
) -> KnowledgeService:
    """Build a ready-to-use service from environment configuration.

    Ingestion runs by default because the in-memory store starts empty and would
    otherwise retrieve nothing. It is incremental and content-hashed, so calling
    this against a warm Qdrant collection is cheap — unchanged documents cost no
    embedding calls.

    Ingestion failure does not fail construction: a service with an empty corpus
    degrades the analysis, while raising here would break the whole AI stage.
    """
    embedder = embedder or build_embedder()
    store = store or build_store(embedder.dimensions)

    service = KnowledgeService(
        store=store,
        embedder=embedder,
        enabled=_env_flag("RAG_ENABLED", True),
        top_k=_env_int("RAG_TOP_K", DEFAULT_TOP_K),
        max_tokens=_env_int("RAG_MAX_CONTEXT_TOKENS", DEFAULT_MAX_TOKENS),
    )

    if isinstance(store, QdrantVectorStore):
        try:
            await store.ensure_collection()
        except Exception as exc:  # noqa: BLE001
            _LOG.warning("rag_collection_setup_failed: %s: %s", type(exc).__name__, exc)

    if ingest and service.enabled:
        try:
            report = await service.ingest(corpus_dir)
            _LOG.info(
                "rag_service_ready: ingested=%d unchanged=%d chunks=%d",
                report.documents_ingested,
                report.documents_unchanged,
                report.chunks_written,
            )
        except Exception as exc:  # noqa: BLE001
            _LOG.warning("rag_ingestion_failed: %s: %s", type(exc).__name__, exc)

    return service
