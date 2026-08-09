"""Heading-aware chunking."""

from __future__ import annotations

from ai.rag.chunking import chunk_document, chunk_documents
from ai.rag.models import CHARS_PER_TOKEN, DocumentKind, KnowledgeDocument, SourceTrust
from ai.tests.test_rag.conftest import make_doc


def doc_with(text: str) -> KnowledgeDocument:
    return make_doc(text=text)


class TestHeadingStructure:
    def test_sections_become_separate_chunks(self) -> None:
        chunks = chunk_document(
            doc_with(
                "# Family\n\nIntro paragraph long enough to survive the runt merge "
                "threshold comfortably.\n\n"
                "## Overlays\n\nOverlay behaviour description that is also long "
                "enough to stand on its own as a chunk.\n\n"
                "## SMS\n\nSMS interception description that is likewise long enough "
                "to stand on its own as a chunk.\n"
            )
        )
        assert len(chunks) == 3
        assert [c.ordinal for c in chunks] == [0, 1, 2]

    def test_heading_path_accumulates_ancestors(self) -> None:
        # "overlay" must retrieve alongside the family it belongs to, which only
        # works if the ancestor heading travels with the chunk.
        chunks = chunk_document(
            doc_with(
                "# Cerberus\n\nA long enough introduction paragraph for the family "
                "section to be kept.\n\n"
                "## Overlay behaviour\n\nDetailed overlay description long enough to "
                "be its own chunk without merging.\n"
            )
        )
        overlay = chunks[-1]
        assert overlay.heading == "Cerberus > Overlay behaviour"
        assert "Cerberus > Overlay behaviour" in overlay.text

    def test_sibling_headings_do_not_nest(self) -> None:
        chunks = chunk_document(
            doc_with(
                "# Top\n\nIntroduction text that is long enough to remain its own "
                "chunk after merging.\n\n"
                "## A\n\nSection A content long enough to remain its own chunk here.\n\n"
                "## B\n\nSection B content long enough to remain its own chunk here.\n"
            )
        )
        headings = [c.heading for c in chunks]
        assert "Top > A" in headings
        assert "Top > B" in headings
        assert "Top > A > B" not in headings

    def test_a_document_without_headings_is_one_chunk(self) -> None:
        chunks = chunk_document(doc_with("Just a paragraph of prose with no headings."))
        assert len(chunks) == 1
        assert chunks[0].heading == ""


class TestSizeHandling:
    def test_oversized_sections_are_split(self) -> None:
        sentence = "Overlay windows steal banking credentials from the victim. "
        chunks = chunk_document(doc_with(f"# Big\n\n{sentence * 200}"), max_tokens=100)
        assert len(chunks) > 1
        # Each piece must respect the budget it was chunked for, allowing for the
        # heading prefix that is added afterwards.
        for chunk in chunks:
            assert len(chunk.text) <= 100 * CHARS_PER_TOKEN + 100

    def test_split_pieces_overlap(self) -> None:
        sentence = "Alpha beta gamma delta epsilon zeta eta theta iota kappa. "
        chunks = chunk_document(
            doc_with(f"# Big\n\n{sentence * 60}"), max_tokens=60, overlap_tokens=20
        )
        assert len(chunks) >= 2
        # The tail of one chunk should reappear at the head of the next, so a
        # sentence spanning the cut is not lost to both sides.
        tail_words = set(chunks[0].text.split()[-6:])
        assert tail_words & set(chunks[1].text.split())

    def test_a_single_giant_sentence_is_hard_split(self) -> None:
        chunks = chunk_document(doc_with("# Big\n\n" + "x" * 5000), max_tokens=50)
        assert len(chunks) > 1

    def test_tiny_sections_are_merged_not_emitted_alone(self) -> None:
        chunks = chunk_document(
            doc_with(
                "# Top\n\nSee also.\n\n"
                "Then a substantial paragraph that easily exceeds the minimum chunk "
                "size and should absorb the short line above it.\n"
            )
        )
        assert len(chunks) == 1
        assert "See also." in chunks[0].text


class TestProvenance:
    def test_every_chunk_inherits_document_provenance(self) -> None:
        doc = make_doc(
            kind=DocumentKind.technique,
            trust=SourceTrust.vendor,
            families=["cerberus", "alien"],
            mitre=["T1417.001"],
            tags=["overlay"],
        )
        for chunk in chunk_document(doc):
            # Trust must travel with the chunk — the retriever only ever sees
            # chunks, so a chunk without its trust label could not be re-checked.
            assert chunk.trust is SourceTrust.vendor
            assert chunk.trusted is True
            assert chunk.kind is DocumentKind.technique
            assert chunk.families == ["cerberus", "alien"]
            assert chunk.doc_id == doc.doc_id
            assert chunk.content_hash == doc.content_hash

    def test_chunk_ids_are_deterministic(self) -> None:
        doc = make_doc()
        first = [c.chunk_id for c in chunk_document(doc)]
        second = [c.chunk_id for c in chunk_document(doc)]
        assert first == second
        assert first[0] == f"{doc.doc_id}#0"

    def test_editing_a_document_changes_its_content_hash(self) -> None:
        original = chunk_document(make_doc(text="# A\n\nOriginal body text here."))
        edited = chunk_document(make_doc(text="# A\n\nEdited body text here."))
        assert original[0].content_hash != edited[0].content_hash


class TestBatch:
    def test_chunk_documents_concatenates(self) -> None:
        docs = [make_doc(doc_id="a.md"), make_doc(doc_id="b.md")]
        chunks = chunk_documents(docs)
        assert {c.doc_id for c in chunks} == {"a.md", "b.md"}

    def test_an_empty_document_yields_no_chunks(self) -> None:
        assert chunk_document(make_doc(text="   \n\n  ")) == []
