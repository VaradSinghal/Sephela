"""
ai/rag/ingest.py — Knowledge-base ingestion: Markdown corpus → vector store.

Corpus documents are Markdown with a YAML-ish front-matter header carrying their
metadata. Front matter is parsed with a small hand-rolled reader rather than a
YAML dependency: the schema is six known keys, and a full YAML parser would accept
far more structure than this format should have.

Three properties matter more than throughput here.

**Trust is established at the door.** A document whose front matter does not
declare a trusted source is *rejected with a reason*, never ingested and filtered
later. This is the first of the three enforcement points for the trusted-source
rule in ``09-security.md``; getting it right means the store can only ever contain
promptable material.

**Ingestion is incremental and idempotent.** Every chunk carries its document's
content hash, so comparing the corpus on disk against the store's hashes
identifies exactly which documents changed. Re-running over an unchanged corpus
performs zero embedding calls — which matters when the embedder is a paid API, and
makes "re-ingest on deploy" a safe default.

**A changed document is replaced, not merged.** Editing a document that previously
produced five chunks and now produces three must not leave two stale chunks
behind, so the document's chunks are deleted before the new ones are written.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from ai.rag.chunking import chunk_document
from ai.rag.embeddings import Embedder
from ai.rag.models import (
    Chunk,
    DocumentKind,
    KnowledgeDocument,
    SourceTrust,
)
from ai.rag.store import VectorStore

_LOG = logging.getLogger("sephela.rag")

#: Front-matter keys accepted. Anything else is ignored rather than errored, so a
#: corpus file can carry editorial notes without breaking ingestion.
_LIST_KEYS = {"families", "mitre", "owasp_mobile", "tags"}
_SCALAR_KEYS = {"title", "kind", "trust", "source"}

CORPUS_GLOB = "**/*.md"
#: The bundled corpus lives beside this module.
DEFAULT_CORPUS_DIR = Path(__file__).parent / "knowledge"


@dataclass
class IngestionReport:
    """What an ingestion run did, and what it refused to do."""

    documents_seen: int = 0
    documents_ingested: int = 0
    documents_unchanged: int = 0
    documents_rejected: int = 0
    chunks_written: int = 0
    #: (path, reason) for every rejected document — surfaced so an operator can
    #: fix a corpus file rather than wonder why it never appears in retrieval.
    rejections: list[tuple[str, str]] = field(default_factory=list)

    def reject(self, path: str, reason: str) -> None:
        self.documents_rejected += 1
        self.rejections.append((path, reason))
        _LOG.warning("rag_document_rejected: %s: %s", path, reason)


def parse_front_matter(text: str) -> tuple[dict[str, object], str]:
    """Split a leading ``---`` delimited header from the body.

    Supports ``key: value`` and ``key: [a, b, c]``. Returns an empty header and the
    text unchanged when no front matter is present, so a plain Markdown file is
    still parseable (it will simply be rejected for lacking a trust declaration).
    """
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}, text

    header: dict[str, object] = {}
    body_start = len(lines)
    for index in range(1, len(lines)):
        stripped = lines[index].strip()
        if stripped == "---":
            body_start = index + 1
            break
        if not stripped or stripped.startswith("#"):
            continue
        if ":" not in stripped:
            continue

        key, _, raw = stripped.partition(":")
        key = key.strip().lower()
        raw = raw.strip()

        if key in _LIST_KEYS:
            header[key] = _parse_list(raw)
        elif key in _SCALAR_KEYS:
            header[key] = raw.strip("\"'")

    return header, "\n".join(lines[body_start:])


def _parse_list(raw: str) -> list[str]:
    inner = raw.strip()
    if inner.startswith("[") and inner.endswith("]"):
        inner = inner[1:-1]
    return [item.strip().strip("\"'") for item in inner.split(",") if item.strip()]


def load_document(path: Path, *, corpus_root: Path) -> tuple[KnowledgeDocument | None, str]:
    """Read one corpus file into a document, or return the reason it was refused."""
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        return None, f"unreadable: {exc}"
    except UnicodeDecodeError:
        return None, "not valid UTF-8"

    header, body = parse_front_matter(raw)
    if not body.strip():
        return None, "document body is empty"

    trust_raw = str(header.get("trust", "")).strip().lower()
    if not trust_raw:
        return None, "front matter does not declare `trust` (required)"
    try:
        trust = SourceTrust(trust_raw)
    except ValueError:
        return None, f"unrecognized trust value {trust_raw!r}"
    if trust not in (SourceTrust.curated, SourceTrust.vendor):
        # The quarantine boundary: refused at the door, never stored.
        return None, f"trust={trust.value} is not a promptable source"

    kind_raw = str(header.get("kind", "reference")).strip().lower()
    try:
        kind = DocumentKind(kind_raw)
    except ValueError:
        return None, f"unrecognized kind value {kind_raw!r}"

    doc_id = path.relative_to(corpus_root).as_posix()
    title = str(header.get("title") or _first_heading(body) or path.stem)

    return (
        KnowledgeDocument(
            doc_id=doc_id,
            title=title,
            text=body.strip(),
            kind=kind,
            trust=trust,
            source=str(header.get("source") or f"corpus:{doc_id}"),
            families=[f.lower() for f in _as_list(header.get("families"))],
            mitre=_as_list(header.get("mitre")),
            owasp_mobile=_as_list(header.get("owasp_mobile")),
            tags=[t.lower() for t in _as_list(header.get("tags"))],
        ),
        "",
    )


def _as_list(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value if str(v).strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def _first_heading(body: str) -> str | None:
    for line in body.splitlines():
        if line.startswith("#"):
            return line.lstrip("#").strip()
    return None


class KnowledgeIngestor:
    """Loads a Markdown corpus into a vector store, incrementally."""

    def __init__(self, store: VectorStore, embedder: Embedder) -> None:
        self.store = store
        self.embedder = embedder

    async def ingest_documents(
        self, documents: list[KnowledgeDocument], *, force: bool = False
    ) -> IngestionReport:
        """Ingest already-parsed documents, skipping unchanged ones.

        ``force`` re-embeds everything — needed when the *embedder* changes, since
        content hashes are unchanged but the existing vectors are from a different
        model and are no longer comparable to new queries.
        """
        report = IngestionReport(documents_seen=len(documents))
        if not documents:
            return report

        try:
            stored_hashes = await self.store.document_hashes()
        except Exception as exc:  # noqa: BLE001 — a cold/absent store is not fatal
            _LOG.warning("rag_hash_probe_failed: %s: %s", type(exc).__name__, exc)
            stored_hashes = {}

        for doc in documents:
            if not doc.trusted:
                # Defence in depth: the loader already refuses these, but
                # ingest_documents is public and may be called directly.
                report.reject(doc.doc_id, f"trust={doc.trust.value} is not promptable")
                continue

            if not force and stored_hashes.get(doc.doc_id) == doc.content_hash:
                report.documents_unchanged += 1
                continue

            chunks = chunk_document(doc)
            if not chunks:
                report.reject(doc.doc_id, "produced no chunks")
                continue

            written = await self._replace(doc, chunks)
            report.documents_ingested += 1
            report.chunks_written += written

        _LOG.info(
            "rag_ingestion_complete: seen=%d ingested=%d unchanged=%d rejected=%d chunks=%d",
            report.documents_seen,
            report.documents_ingested,
            report.documents_unchanged,
            report.documents_rejected,
            report.chunks_written,
        )
        return report

    async def _replace(self, doc: KnowledgeDocument, chunks: list[Chunk]) -> int:
        """Delete the document's previous chunks, then write the new ones.

        Delete-before-write rather than upsert-only: an edit that reduces the chunk
        count would otherwise leave orphans that still match queries and quote text
        no longer in the corpus.
        """
        await self.store.delete_document(doc.doc_id)
        vectors = await self.embedder.embed([c.text for c in chunks])
        return await self.store.upsert(chunks, vectors)

    async def ingest_directory(
        self, corpus_dir: Path | str | None = None, *, force: bool = False
    ) -> IngestionReport:
        """Load and ingest every Markdown file under ``corpus_dir``."""
        root = Path(corpus_dir) if corpus_dir is not None else DEFAULT_CORPUS_DIR
        if not root.is_dir():
            report = IngestionReport()
            report.reject(str(root), "corpus directory does not exist")
            return report

        documents: list[KnowledgeDocument] = []
        pre_report = IngestionReport()
        for path in sorted(root.glob(CORPUS_GLOB)):
            if not path.is_file():
                continue
            doc, reason = load_document(path, corpus_root=root)
            if doc is None:
                pre_report.reject(path.relative_to(root).as_posix(), reason)
                continue
            documents.append(doc)

        report = await self.ingest_documents(documents, force=force)
        # Fold in the load-time rejections; documents_seen must count files found
        # on disk, not just the ones that parsed.
        report.documents_seen += pre_report.documents_rejected
        report.documents_rejected += pre_report.documents_rejected
        report.rejections.extend(pre_report.rejections)
        return report
