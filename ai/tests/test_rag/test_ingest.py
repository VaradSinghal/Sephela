"""Ingestion: front matter, the trust gate at the door, and incrementality."""

from __future__ import annotations

from pathlib import Path

import pytest

from ai.rag.ingest import (
    DEFAULT_CORPUS_DIR,
    KnowledgeIngestor,
    load_document,
    parse_front_matter,
)
from ai.rag.models import DocumentKind, SourceTrust
from ai.tests.test_rag.conftest import make_doc

pytestmark = pytest.mark.anyio

VALID = """---
title: Cerberus profile
kind: malware_family
trust: curated
source: internal:threat-research
families: [cerberus, alien]
mitre: [T1417.001, T1626]
tags: [banking, overlay]
---

# Cerberus profile

Cerberus abuses the accessibility service and draws overlays over banking apps.
"""


def write(tmp_path: Path, name: str, content: str) -> Path:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


class TestFrontMatter:
    def test_scalars_and_lists_are_parsed(self) -> None:
        header, body = parse_front_matter(VALID)
        assert header["title"] == "Cerberus profile"
        assert header["kind"] == "malware_family"
        assert header["families"] == ["cerberus", "alien"]
        assert header["mitre"] == ["T1417.001", "T1626"]
        assert body.strip().startswith("# Cerberus profile")

    def test_a_file_without_front_matter_returns_the_text_unchanged(self) -> None:
        header, body = parse_front_matter("# Just markdown\n\nBody.")
        assert header == {}
        assert body == "# Just markdown\n\nBody."

    def test_unknown_keys_are_ignored_not_errors(self) -> None:
        # A corpus file should be able to carry editorial notes.
        header, _ = parse_front_matter("---\ntrust: curated\nreviewer: alice\n---\nBody")
        assert header == {"trust": "curated"}

    def test_quotes_are_stripped(self) -> None:
        header, _ = parse_front_matter("---\ntitle: \"Quoted\"\ntrust: 'curated'\n---\nBody")
        assert header["title"] == "Quoted"
        assert header["trust"] == "curated"


class TestTrustGateAtTheDoor:
    def test_a_curated_document_loads(self, tmp_path: Path) -> None:
        path = write(tmp_path, "families/cerberus.md", VALID)
        doc, reason = load_document(path, corpus_root=tmp_path)
        assert reason == ""
        assert doc is not None
        assert doc.trust is SourceTrust.curated
        assert doc.doc_id == "families/cerberus.md"
        assert doc.kind is DocumentKind.malware_family

    def test_a_vendor_document_loads(self, tmp_path: Path) -> None:
        path = write(tmp_path, "v.md", "---\ntrust: vendor\n---\n# V\n\nVendor reference body.")
        doc, _ = load_document(path, corpus_root=tmp_path)
        assert doc is not None and doc.trust is SourceTrust.vendor

    def test_sample_derived_content_is_refused_with_a_reason(self, tmp_path: Path) -> None:
        # The quarantine boundary. Refused at the door, never stored.
        path = write(
            tmp_path, "bad.md", "---\ntrust: sample_derived\n---\n# X\n\nStrings from an APK."
        )
        doc, reason = load_document(path, corpus_root=tmp_path)
        assert doc is None
        assert "not a promptable source" in reason

    def test_a_missing_trust_declaration_is_refused(self, tmp_path: Path) -> None:
        # Fails closed: no declaration means not promptable.
        path = write(tmp_path, "x.md", "# No front matter\n\nBody text.")
        doc, reason = load_document(path, corpus_root=tmp_path)
        assert doc is None
        assert "does not declare `trust`" in reason

    def test_an_unrecognized_trust_value_is_refused(self, tmp_path: Path) -> None:
        path = write(tmp_path, "x.md", "---\ntrust: totally-fine-honestly\n---\n# X\n\nBody.")
        doc, reason = load_document(path, corpus_root=tmp_path)
        assert doc is None
        assert "unrecognized trust value" in reason

    def test_an_unrecognized_kind_is_refused(self, tmp_path: Path) -> None:
        path = write(tmp_path, "x.md", "---\ntrust: curated\nkind: nonsense\n---\n# X\n\nBody.")
        doc, reason = load_document(path, corpus_root=tmp_path)
        assert doc is None
        assert "unrecognized kind" in reason

    def test_an_empty_body_is_refused(self, tmp_path: Path) -> None:
        path = write(tmp_path, "x.md", "---\ntrust: curated\n---\n\n")
        doc, reason = load_document(path, corpus_root=tmp_path)
        assert doc is None
        assert "empty" in reason


class TestMetadataDefaults:
    def test_the_title_falls_back_to_the_first_heading(self, tmp_path: Path) -> None:
        path = write(tmp_path, "x.md", "---\ntrust: curated\n---\n# Derived Title\n\nBody text.")
        doc, _ = load_document(path, corpus_root=tmp_path)
        assert doc is not None and doc.title == "Derived Title"

    def test_the_kind_defaults_to_reference(self, tmp_path: Path) -> None:
        path = write(tmp_path, "x.md", "---\ntrust: curated\n---\n# T\n\nBody text.")
        doc, _ = load_document(path, corpus_root=tmp_path)
        assert doc is not None and doc.kind is DocumentKind.reference

    def test_families_and_tags_are_lowercased(self, tmp_path: Path) -> None:
        path = write(
            tmp_path,
            "x.md",
            "---\ntrust: curated\nfamilies: [Cerberus]\ntags: [Banking]\n---\n# T\n\nBody.",
        )
        doc, _ = load_document(path, corpus_root=tmp_path)
        assert doc is not None
        assert doc.families == ["cerberus"]
        assert doc.tags == ["banking"]


class TestIngestDocuments:
    async def test_documents_are_chunked_and_stored(self, store, embedder) -> None:  # type: ignore[no-untyped-def]
        report = await KnowledgeIngestor(store, embedder).ingest_documents([make_doc()])
        assert report.documents_ingested == 1
        assert report.chunks_written > 0
        assert await store.count() == report.chunks_written

    async def test_untrusted_documents_are_rejected_here_too(self, store, embedder) -> None:  # type: ignore[no-untyped-def]
        # Defence in depth: ingest_documents is public and may be called directly,
        # bypassing the loader's gate.
        doc = make_doc(trust=SourceTrust.sample_derived)
        report = await KnowledgeIngestor(store, embedder).ingest_documents([doc])

        assert report.documents_ingested == 0
        assert report.documents_rejected == 1
        assert "not promptable" in report.rejections[0][1]
        assert await store.count() == 0

    async def test_an_unchanged_document_is_not_re_embedded(self, store, embedder) -> None:  # type: ignore[no-untyped-def]
        ingestor = KnowledgeIngestor(store, embedder)
        await ingestor.ingest_documents([make_doc()])

        second = await ingestor.ingest_documents([make_doc()])

        assert second.documents_unchanged == 1
        assert second.documents_ingested == 0
        assert second.chunks_written == 0

    async def test_force_re_embeds_everything(self, store, embedder) -> None:  # type: ignore[no-untyped-def]
        # Needed when the *embedder* changes: hashes are unchanged but the stored
        # vectors are from a different model.
        ingestor = KnowledgeIngestor(store, embedder)
        await ingestor.ingest_documents([make_doc()])

        forced = await ingestor.ingest_documents([make_doc()], force=True)

        assert forced.documents_ingested == 1
        assert forced.documents_unchanged == 0

    async def test_an_edited_document_replaces_its_old_chunks(self, store, embedder) -> None:  # type: ignore[no-untyped-def]
        # A five-chunk document edited down to one must not leave four orphans
        # that still match queries and quote text no longer in the corpus.
        ingestor = KnowledgeIngestor(store, embedder)
        long_body = "\n\n".join(
            f"## S{i}\n\nSection {i} body text long enough to be its own chunk here."
            for i in range(5)
        )
        await ingestor.ingest_documents([make_doc(text=f"# T\n\n{long_body}")])
        before = await store.count()

        await ingestor.ingest_documents([make_doc(text="# T\n\nA single short body now.")])

        assert await store.count() < before
        assert len(await store.document_hashes()) == 1

    async def test_an_empty_batch_is_a_no_op(self, store, embedder) -> None:  # type: ignore[no-untyped-def]
        report = await KnowledgeIngestor(store, embedder).ingest_documents([])
        assert report.documents_seen == 0


class TestIngestDirectory:
    async def test_a_corpus_directory_is_walked_recursively(self, tmp_path, store, embedder) -> None:  # type: ignore[no-untyped-def]
        write(tmp_path, "families/cerberus.md", VALID)
        write(tmp_path, "techniques/overlay.md", VALID.replace("malware_family", "technique"))

        report = await KnowledgeIngestor(store, embedder).ingest_directory(tmp_path)

        assert report.documents_ingested == 2
        assert set(await store.document_hashes()) == {
            "families/cerberus.md",
            "techniques/overlay.md",
        }

    async def test_rejected_files_are_reported_not_silently_skipped(self, tmp_path, store, embedder) -> None:  # type: ignore[no-untyped-def]
        # An operator needs to know why their corpus file never appears.
        write(tmp_path, "good.md", VALID)
        write(tmp_path, "bad.md", "# No front matter\n\nBody.")

        report = await KnowledgeIngestor(store, embedder).ingest_directory(tmp_path)

        assert report.documents_ingested == 1
        assert report.documents_rejected == 1
        assert report.rejections[0][0] == "bad.md"

    async def test_a_missing_directory_is_reported_not_raised(self, tmp_path, store, embedder) -> None:  # type: ignore[no-untyped-def]
        report = await KnowledgeIngestor(store, embedder).ingest_directory(tmp_path / "nope")
        assert report.documents_rejected == 1
        assert "does not exist" in report.rejections[0][1]


class TestBundledCorpus:
    async def test_the_shipped_corpus_ingests_cleanly(self, store, embedder) -> None:  # type: ignore[no-untyped-def]
        report = await KnowledgeIngestor(store, embedder).ingest_directory(DEFAULT_CORPUS_DIR)

        assert report.documents_rejected == 0, report.rejections
        assert report.documents_ingested >= 5
        assert report.chunks_written > 10

    async def test_every_shipped_document_declares_a_trusted_source(self) -> None:
        for path in sorted(DEFAULT_CORPUS_DIR.glob("**/*.md")):
            doc, reason = load_document(path, corpus_root=DEFAULT_CORPUS_DIR)
            assert doc is not None, f"{path.name}: {reason}"
            assert doc.trusted, f"{path.name} is not a trusted source"
