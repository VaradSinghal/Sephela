"""HashExtractor — the sample's identity.

Small surface, disproportionate consequences: the SHA-256 is the storage key, the
deduplication key, the threat-intel lookup key, and what an analyst quotes in a report.
"""

from __future__ import annotations

import hashlib

from sephela_static.extractors.hashes import HashExtractor


class TestHashes:
    def test_the_digests_are_of_the_whole_file(self, make_context) -> None:
        ctx = make_context({"classes.dex": b"dex-bytes"})
        raw = ctx.apk_path.read_bytes()

        evidence = HashExtractor().extract(ctx).evidence

        assert evidence["sha256"] == hashlib.sha256(raw).hexdigest()
        assert evidence["sha1"] == hashlib.sha1(raw).hexdigest()
        assert evidence["md5"] == hashlib.md5(raw).hexdigest()

    def test_the_file_size_is_reported(self, make_context) -> None:
        ctx = make_context({"classes.dex": b"x" * 100})

        evidence = HashExtractor().extract(ctx).evidence

        assert evidence["file_size"] == len(ctx.apk_path.read_bytes())

    def test_the_digests_are_lowercase_hex_of_the_expected_length(self, make_context) -> None:
        # Threat-intel providers are matched against these; a differently-cased or
        # truncated digest silently matches nothing.
        evidence = HashExtractor().extract(make_context()).evidence

        assert len(evidence["sha256"]) == 64
        assert len(evidence["sha1"]) == 40
        assert len(evidence["md5"]) == 32
        for digest in ("sha256", "sha1", "md5"):
            assert evidence[digest] == evidence[digest].lower()
            assert all(c in "0123456789abcdef" for c in evidence[digest])

    def test_two_different_files_hash_differently(self, make_context) -> None:
        first = HashExtractor().extract(make_context({"classes.dex": b"a"})).evidence
        second = HashExtractor().extract(make_context({"classes.dex": b"b"})).evidence

        assert first["sha256"] != second["sha256"]

    def test_it_needs_no_tooling(self) -> None:
        # It runs on every sample including ones where androguard fails, so it must not
        # be gated behind the tool-requiring path.
        assert HashExtractor.requires_tools is False

    def test_it_raises_no_findings(self, make_context) -> None:
        # A hash is an identity, not a judgement — a finding here would be noise in
        # every report.
        assert HashExtractor().extract(make_context()).findings == []
