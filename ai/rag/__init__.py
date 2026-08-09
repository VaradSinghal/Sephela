"""
Sephela RAG / Knowledge Service (Phase 12).

Retrieves curated threat-intelligence knowledge and injects it into agent prompts
as clearly-delimited reference material, sitting *before* LLM inference in DFD-3
(``docs/architecture/07-data-flow.md``).

The subsystem's defining constraint comes from ``09-security.md``: "retrieved RAG
docs are trusted-source only; sample-derived text is quarantined". Retrieval output
lands in an LLM prompt, so a knowledge base that could be poisoned with text from
an analyzed APK would be a persistent, cross-tenant prompt-injection channel. That
rule is enforced at three independent points:

1. **Ingestion** (``ingest.py``) refuses any document not declaring a trusted
   source, with a reason.
2. **Storage and retrieval** (``store.py``, ``retriever.py``) filter on trust, so
   an untrusted chunk cannot occupy a result slot.
3. **Rendering** (``context.py``) re-checks trust immediately before text enters a
   prompt, and logs an error if anything untrusted reached it.

Queries are built from a controlled vocabulary (``query.py``) — permission
constants, MITRE ids, API names, normalized family names — never from raw sample
strings, so an attacker cannot steer retrieval with free text in their APK.

Zero-configuration by default: ``HashingEmbedder`` needs no API key or model
download, and ``InMemoryVectorStore`` needs no database, so the RAG path runs
anywhere. Swap in ``OpenAICompatibleEmbedder`` and ``QdrantVectorStore`` for
semantic recall at scale.

Public API::

    from ai.rag import build_knowledge_service

    service = await build_knowledge_service()          # ingests the bundled corpus
    block = await service.context_for(evidence, findings=findings, agent="permission_agent")
"""

from ai.rag.chunking import chunk_document, chunk_documents
from ai.rag.context import context_summary, render_context
from ai.rag.embeddings import (
    CachingEmbedder,
    Embedder,
    HashingEmbedder,
    OpenAICompatibleEmbedder,
    cosine_similarity,
)
from ai.rag.ingest import (
    DEFAULT_CORPUS_DIR,
    IngestionReport,
    KnowledgeIngestor,
    load_document,
    parse_front_matter,
)
from ai.rag.models import (
    Chunk,
    DocumentKind,
    KnowledgeDocument,
    RetrievalQuery,
    RetrievalResult,
    ScoredChunk,
    SourceTrust,
    is_trusted,
)
from ai.rag.qdrant import QdrantVectorStore
from ai.rag.query import build_query, extract_terms
from ai.rag.retriever import KnowledgeRetriever
from ai.rag.service import KnowledgeService, build_knowledge_service
from ai.rag.store import InMemoryVectorStore, SearchFilter, VectorStore

__all__ = [
    "CachingEmbedder",
    "Chunk",
    "DEFAULT_CORPUS_DIR",
    "DocumentKind",
    "Embedder",
    "HashingEmbedder",
    "InMemoryVectorStore",
    "IngestionReport",
    "KnowledgeDocument",
    "KnowledgeIngestor",
    "KnowledgeRetriever",
    "KnowledgeService",
    "OpenAICompatibleEmbedder",
    "QdrantVectorStore",
    "RetrievalQuery",
    "RetrievalResult",
    "ScoredChunk",
    "SearchFilter",
    "SourceTrust",
    "VectorStore",
    "build_knowledge_service",
    "build_query",
    "chunk_document",
    "chunk_documents",
    "context_summary",
    "cosine_similarity",
    "extract_terms",
    "is_trusted",
    "load_document",
    "parse_front_matter",
    "render_context",
]
__version__ = "0.1.0"
