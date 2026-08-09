"""Fixtures for the RAG suite.

Everything is offline and deterministic: the hashing embedder needs no network,
and the in-memory store needs no database. That is a property of the design rather
than of the test setup — the zero-configuration path is the default production
path for small corpora.
"""

from __future__ import annotations

import pytest

from ai.rag.embeddings import HashingEmbedder
from ai.rag.ingest import KnowledgeIngestor
from ai.rag.models import DocumentKind, KnowledgeDocument, SourceTrust
from ai.rag.service import KnowledgeService
from ai.rag.store import InMemoryVectorStore


@pytest.fixture
def embedder() -> HashingEmbedder:
    return HashingEmbedder(dimensions=256)


@pytest.fixture
def store() -> InMemoryVectorStore:
    return InMemoryVectorStore()


def make_doc(
    doc_id: str = "families/cerberus.md",
    *,
    title: str = "Cerberus banking trojan",
    text: str | None = None,
    kind: DocumentKind = DocumentKind.malware_family,
    trust: SourceTrust = SourceTrust.curated,
    families: list[str] | None = None,
    mitre: list[str] | None = None,
    tags: list[str] | None = None,
) -> KnowledgeDocument:
    return KnowledgeDocument(
        doc_id=doc_id,
        title=title,
        text=text
        or (
            "# Cerberus banking trojan\n\n"
            "Cerberus abuses the accessibility service to keylog banking apps and "
            "draws overlay windows to steal credentials from the victim. It also "
            "intercepts SMS one-time passcodes using a high priority broadcast "
            "receiver, then aborts the broadcast so the victim never sees the code.\n"
        ),
        kind=kind,
        trust=trust,
        source="internal:threat-research",
        families=families if families is not None else ["cerberus"],
        mitre=mitre if mitre is not None else ["T1417.001"],
        tags=tags if tags is not None else ["banking", "overlay"],
    )


@pytest.fixture
def sample_doc() -> KnowledgeDocument:
    return make_doc()


def corpus_docs() -> list[KnowledgeDocument]:
    """A small three-document corpus spanning the kinds retrieval filters on."""
    return [
        make_doc(),
        make_doc(
            doc_id="techniques/accessibility.md",
            title="Accessibility service abuse",
            kind=DocumentKind.technique,
            families=[],
            mitre=["T1417.001", "T1626"],
            tags=["accessibility"],
            text=(
                "# Accessibility service abuse\n\n"
                "A bound accessibility service can read on screen text from other "
                "applications and perform clicks, which lets malware grant itself "
                "further permissions by tapping system dialog buttons.\n"
            ),
        ),
        make_doc(
            doc_id="playbooks/triage.md",
            title="SOC triage playbook",
            kind=DocumentKind.playbook,
            families=[],
            mitre=[],
            tags=["triage"],
            text=(
                "# SOC triage playbook\n\n"
                "Pivot on the signing certificate to find the rest of the campaign, "
                "then submit command and control endpoints for perimeter blocking "
                "and takedown.\n"
            ),
        ),
    ]


async def build_loaded_service(store, embedder) -> KnowledgeService:  # type: ignore[no-untyped-def]
    """Ingest ``corpus_docs()`` and return a service over it.

    A helper coroutine rather than an async fixture, matching how the existing
    ``ai/tests`` suite handles async setup.
    """
    await KnowledgeIngestor(store, embedder).ingest_documents(corpus_docs())
    return KnowledgeService(store=store, embedder=embedder, top_k=5, max_tokens=2000)
