"""
ai/rag/chunking.py — Split knowledge documents into retrievable chunks.

The corpus is human-written Markdown (family profiles, technique references, SOC
playbooks), and its headings already mark the boundaries a security analyst would
draw. So chunking follows headings first and only falls back to size-based
splitting when a single section is too long. A fixed-window splitter would cut
"Cerberus → Overlay behaviour" in half and strand the behaviour description from
the family it belongs to, which is exactly the association retrieval needs.

Each chunk carries its heading path in the text. That costs a few tokens and buys
two things: the embedding sees the section's topic even when the body uses
pronouns, and the rendered prompt shows an analyst where the passage came from.

Overlap exists only for the size-based fallback, where a cut is arbitrary and a
sentence spanning the boundary would otherwise be lost to both sides.
"""

from __future__ import annotations

import re

from ai.rag.models import CHARS_PER_TOKEN, Chunk, KnowledgeDocument

#: Target chunk size in tokens. Small enough that a handful fit in a prompt
#: budget, large enough to hold a complete idea.
DEFAULT_MAX_TOKENS = 320
#: Overlap for the size-based fallback only.
DEFAULT_OVERLAP_TOKENS = 40
#: Sections shorter than this are merged into the next one rather than becoming
#: their own chunk — a lone heading retrieves nothing useful.
MIN_CHUNK_CHARS = 80

_HEADING_RE = re.compile(r"^(#{1,6})\s+(.*)$")
_SENTENCE_END_RE = re.compile(r"(?<=[.!?])\s+")


def chunk_document(
    doc: KnowledgeDocument,
    *,
    max_tokens: int = DEFAULT_MAX_TOKENS,
    overlap_tokens: int = DEFAULT_OVERLAP_TOKENS,
) -> list[Chunk]:
    """Split one document into chunks, preserving heading context and provenance."""
    max_chars = max(1, max_tokens) * CHARS_PER_TOKEN
    overlap_chars = max(0, overlap_tokens) * CHARS_PER_TOKEN

    sections = _split_sections(doc.text)
    pieces: list[tuple[str, str]] = []  # (heading path, body)
    for heading, body in sections:
        body = body.strip()
        if not body:
            continue
        for part in _split_oversized(body, max_chars, overlap_chars):
            pieces.append((heading, part))

    pieces = _merge_runts(pieces)

    chunks: list[Chunk] = []
    content_hash = doc.content_hash
    for ordinal, (heading, body) in enumerate(pieces):
        text = f"{heading}\n\n{body}" if heading else body
        chunks.append(
            Chunk(
                # Deterministic and ordinal-based, so re-ingesting an unchanged
                # document produces identical ids and the upsert is a no-op.
                chunk_id=f"{doc.doc_id}#{ordinal}",
                doc_id=doc.doc_id,
                text=text,
                ordinal=ordinal,
                heading=heading,
                title=doc.title,
                kind=doc.kind,
                trust=doc.trust,
                source=doc.source,
                families=list(doc.families),
                mitre=list(doc.mitre),
                owasp_mobile=list(doc.owasp_mobile),
                tags=list(doc.tags),
                content_hash=content_hash,
            )
        )
    return chunks


def _split_sections(text: str) -> list[tuple[str, str]]:
    """Split Markdown into (heading path, body) pairs.

    The heading path accumulates ancestors, so a level-3 heading under a level-1
    title reads "Cerberus > Overlay behaviour" — retrieval on "overlay" then still
    surfaces which family it describes.
    """
    sections: list[tuple[str, str]] = []
    stack: list[tuple[int, str]] = []
    current: list[str] = []
    heading_path = ""

    for line in text.splitlines():
        match = _HEADING_RE.match(line)
        if match is None:
            current.append(line)
            continue

        # Close the previous section before descending.
        if current:
            sections.append((heading_path, "\n".join(current)))
            current = []

        level = len(match.group(1))
        title = match.group(2).strip()
        while stack and stack[-1][0] >= level:
            stack.pop()
        stack.append((level, title))
        heading_path = " > ".join(t for _, t in stack)

    if current:
        sections.append((heading_path, "\n".join(current)))

    # A document with no headings at all is one unheaded section.
    if not sections:
        return [("", text)]
    return sections


def _split_oversized(body: str, max_chars: int, overlap_chars: int) -> list[str]:
    """Break an over-long section on sentence boundaries, with overlap.

    Sentence-aligned cuts keep each piece readable; the overlap means a sentence
    straddling a boundary survives in the following piece rather than being
    truncated out of both.
    """
    if len(body) <= max_chars:
        return [body]

    sentences = _SENTENCE_END_RE.split(body)
    parts: list[str] = []
    buffer = ""

    for sentence in sentences:
        candidate = f"{buffer} {sentence}".strip() if buffer else sentence
        if len(candidate) <= max_chars:
            buffer = candidate
            continue

        if buffer:
            parts.append(buffer)
            tail = buffer[-overlap_chars:] if overlap_chars else ""
            buffer = f"{tail} {sentence}".strip() if tail else sentence
        else:
            # A single sentence longer than the window (a table row, a long URL
            # list) — hard-split it rather than emit an over-budget chunk.
            parts.extend(_hard_split(sentence, max_chars))
            buffer = ""

        # The overlap tail may itself have overflowed the window.
        while len(buffer) > max_chars:
            parts.append(buffer[:max_chars])
            buffer = buffer[max_chars - overlap_chars :] if overlap_chars else buffer[max_chars:]

    if buffer:
        parts.append(buffer)
    return [p for p in parts if p.strip()]


def _hard_split(text: str, max_chars: int) -> list[str]:
    return [text[i : i + max_chars] for i in range(0, len(text), max_chars)]


def _merge_runts(pieces: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Fold tiny sections into the next one under the same heading path.

    A heading followed by one short line ("See also: ...") is not independently
    retrievable, and storing it wastes a result slot at query time.
    """
    merged: list[tuple[str, str]] = []
    pending: tuple[str, str] | None = None

    for heading, body in pieces:
        if pending is not None:
            pending_heading, pending_body = pending
            if pending_heading == heading:
                body = f"{pending_body}\n\n{body}"
            else:
                merged.append(pending)
            pending = None

        if len(body) < MIN_CHUNK_CHARS:
            pending = (heading, body)
            continue
        merged.append((heading, body))

    if pending is not None:
        # Nothing followed it — append to the previous chunk if the heading
        # matches, otherwise keep it rather than lose content.
        if merged and merged[-1][0] == pending[0]:
            heading, body = merged[-1]
            merged[-1] = (heading, f"{body}\n\n{pending[1]}")
        else:
            merged.append(pending)
    return merged


def chunk_documents(
    docs: list[KnowledgeDocument],
    *,
    max_tokens: int = DEFAULT_MAX_TOKENS,
    overlap_tokens: int = DEFAULT_OVERLAP_TOKENS,
) -> list[Chunk]:
    chunks: list[Chunk] = []
    for doc in docs:
        chunks.extend(
            chunk_document(doc, max_tokens=max_tokens, overlap_tokens=overlap_tokens)
        )
    return chunks
