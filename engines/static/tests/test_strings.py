"""StringExtractor — the corpus every later extractor and agent reads.

The URL and IP extractors read its output, the code and network agents read its
derived views, and the code-intel engine reads the corpus. A gap here propagates
everywhere without ever looking like a failure.
"""

from __future__ import annotations

import pytest

from sephela_static.extractors.strings import (
    _ENTROPY_THRESHOLD,
    _MIN_ENTROPY_LENGTH,
    _SUSPICIOUS_PATTERNS,
    StringExtractor,
    shannon_entropy,
)


def _extract(entries: dict[str, bytes], make_context):
    return StringExtractor().extract(make_context(entries)).evidence


class TestCorpus:
    def test_printable_runs_are_extracted_from_dex(self, make_context) -> None:
        evidence = _extract({"classes.dex": b"\x00\x01hello-world\x00\x02"}, make_context)

        assert "hello-world" in evidence["strings"]

    def test_resources_arsc_is_also_read(self, make_context) -> None:
        evidence = _extract({"resources.arsc": b"\x00from-resources\x00"}, make_context)

        assert "from-resources" in evidence["strings"]

    def test_multiple_dex_files_are_all_read(self, make_context) -> None:
        # Multidex is normal above the 64k method limit, and malware often puts its
        # payload in the second one.
        evidence = _extract(
            {"classes.dex": b"\x00first-dex\x00", "classes2.dex": b"\x00second-dex\x00"},
            make_context,
        )

        assert {"first-dex", "second-dex"} <= set(evidence["strings"])

    def test_other_archive_entries_are_ignored(self, make_context) -> None:
        # Reading every asset would drown the corpus in PNG and font bytes.
        evidence = _extract(
            {"res/drawable/icon.png": b"\x00ignore-this-string\x00", "classes.dex": b"keep-this"},
            make_context,
        )

        assert "keep-this" in evidence["strings"]
        assert "ignore-this-string" not in evidence["strings"]

    def test_runs_shorter_than_five_characters_are_dropped(self, make_context) -> None:
        # Two-character fragments are noise, and there are millions in a DEX.
        evidence = _extract({"classes.dex": b"\x00ab\x00cd\x00keeper\x00"}, make_context)

        assert "keeper" in evidence["strings"]
        assert "ab" not in evidence["strings"]

    def test_duplicates_are_collapsed(self, make_context) -> None:
        evidence = _extract({"classes.dex": b"repeat-me\x00repeat-me\x00repeat-me"}, make_context)

        assert evidence["strings"].count("repeat-me") == 1

    def test_the_count_matches_the_list(self, make_context) -> None:
        evidence = _extract({"classes.dex": b"alpha\x00bravo\x00charlie"}, make_context)

        assert evidence["count"] == len(evidence["strings"])

    def test_an_apk_with_no_dex_yields_an_empty_corpus(self, make_context) -> None:
        # A resources-only split APK is a real input, not a malformed one.
        evidence = _extract({"AndroidManifest.xml": b"\x03\x00"}, make_context)

        assert evidence["count"] == 0
        assert evidence["truncated"] is False

    def test_an_unreadable_entry_does_not_stop_the_others(self, make_context) -> None:
        # ctx.zip.read raises on a corrupt member; the rest of the archive is still
        # worth reading, since a broken entry is itself common in tampered APKs.
        ctx = make_context({"classes.dex": b"first-string", "classes2.dex": b"second-string"})
        original = ctx.zip.read

        def _read(entry):
            if getattr(entry, "filename", entry) == "classes.dex":
                raise RuntimeError("corrupt member")
            return original(entry)

        ctx.zip.read = _read  # type: ignore[method-assign]

        evidence = StringExtractor().extract(ctx).evidence

        assert "second-string" in evidence["strings"]


class TestTruncation:
    def test_a_hostile_corpus_is_capped_and_says_so(self, make_context, monkeypatch) -> None:
        # An APK can be crafted to emit millions of unique strings; the flag is what
        # tells a reader the absence of a string is not evidence it was not there.
        monkeypatch.setattr("sephela_static.extractors.strings._MAX_STRINGS", 10)
        blob = b"\x00".join(f"string-{i:05d}".encode() for i in range(100))

        evidence = _extract({"classes.dex": blob}, make_context)

        assert evidence["count"] == 10
        assert evidence["truncated"] is True

    def test_an_ordinary_corpus_is_not_flagged_as_truncated(self, make_context) -> None:
        evidence = _extract({"classes.dex": b"alpha\x00bravo"}, make_context)

        assert evidence["truncated"] is False


class TestEntropy:
    def test_entropy_of_a_single_repeated_character_is_zero(self) -> None:
        assert shannon_entropy("aaaaaaaa") == 0.0

    def test_entropy_of_an_empty_string_is_zero(self) -> None:
        assert shannon_entropy("") == 0.0

    def test_a_uniform_alphabet_reaches_its_theoretical_maximum(self) -> None:
        # 4 symbols used equally = 2 bits per character.
        assert shannon_entropy("abcdabcdabcd") == pytest.approx(2.0)

    def test_random_looking_data_scores_above_the_threshold(self) -> None:
        assert shannon_entropy("q7Z3kL9mXp2WvB8nRt4YuH6c") > _ENTROPY_THRESHOLD

    def test_prose_and_identifiers_score_below_it(self) -> None:
        for ordinary in (
            "com.example.app.MainActivity",
            "android.permission.INTERNET",
            "Unable to connect to the server",
        ):
            assert shannon_entropy(ordinary) < _ENTROPY_THRESHOLD, ordinary


class TestHighEntropyStrings:
    def test_a_long_random_string_is_flagged(self, make_context) -> None:
        # In an APK this is an encrypted C2 configuration, a packed payload, or a key.
        blob = b"\x00" + b"Qk7ZmL3xPv9RtY2wBn8HuJ6cFd4sGa5e" + b"\x00"

        evidence = _extract({"classes.dex": blob}, make_context)

        assert evidence["high_entropy_count"] == 1
        assert "Qk7ZmL3xPv9RtY2wBn8HuJ6cFd4sGa5e" in evidence["high_entropy"]

    def test_a_short_random_string_is_not_flagged(self, make_context) -> None:
        # Entropy over a handful of characters is a coincidence, not a signal.
        short = b"Xq7#mB"
        assert len(short) < _MIN_ENTROPY_LENGTH

        evidence = _extract({"classes.dex": b"\x00" + short + b"\x00"}, make_context)

        assert evidence["high_entropy_count"] == 0

    def test_a_long_ordinary_string_is_not_flagged(self, make_context) -> None:
        blob = b"\x00com.example.app.ui.activities.MainActivity\x00"

        evidence = _extract({"classes.dex": blob}, make_context)

        assert evidence["high_entropy_count"] == 0

    def test_the_flagged_list_is_bounded_but_the_count_is_not(
        self, make_context, monkeypatch
    ) -> None:
        # A packed APK can hold thousands of blobs. The list goes into a prompt so it is
        # capped; the count is what tells a reader the scale.
        monkeypatch.setattr("sephela_static.extractors.strings._MAX_DERIVED", 3)
        blob = b"\x00".join(f"Qk7ZmL3xPv9RtY2wBn8HuJ6cFd4sG{i:03d}".encode() for i in range(20))

        evidence = _extract({"classes.dex": blob}, make_context)

        assert evidence["high_entropy_count"] == 20
        assert len(evidence["high_entropy"]) == 3


class TestSuspiciousStrings:
    """The field three agent prompts read and nothing used to produce."""

    def test_the_field_exists_at_all(self, make_context) -> None:
        # Regression: the code and network agents read `suspicious` and
        # `high_entropy_count` from this evidence, and neither was ever emitted — so
        # every prompt told the model the sample had none.
        evidence = _extract({"classes.dex": b"anything"}, make_context)

        assert "suspicious" in evidence
        assert "high_entropy_count" in evidence

    @pytest.mark.parametrize("category", sorted(_SUSPICIOUS_PATTERNS))
    def test_every_category_can_be_matched(self, category: str, make_context) -> None:
        keyword = _SUSPICIOUS_PATTERNS[category][0]
        blob = b"\x00" + f"prefix-{keyword}-suffix".encode() + b"\x00"

        evidence = _extract({"classes.dex": blob}, make_context)

        assert evidence["suspicious"], f"{category}: {keyword} matched nothing"
        assert category in evidence["suspicious_categories"]

    def test_the_accessibility_capability_is_detected(self, make_context) -> None:
        # The single most important string in a banking-overlay trojan.
        blob = b"\x00android.accessibilityservice.AccessibilityService\x00"

        evidence = _extract({"classes.dex": blob}, make_context)

        assert "accessibility" in evidence["suspicious_categories"]

    def test_matching_is_case_insensitive(self, make_context) -> None:
        blob = b"\x00SMSMANAGER.SENDTEXTMESSAGE\x00"

        evidence = _extract({"classes.dex": blob}, make_context)

        assert "sms" in evidence["suspicious_categories"]

    def test_a_benign_corpus_flags_nothing(self, make_context) -> None:
        # A false positive here inflates a report an analyst has to triage.
        blob = b"\x00".join(
            [b"com.example.app.MainActivity", b"Hello, world", b"android.intent.action.MAIN"]
        )

        evidence = _extract({"classes.dex": blob}, make_context)

        assert evidence["suspicious"] == []
        assert evidence["suspicious_categories"] == {}

    def test_one_string_can_match_several_categories(self, make_context) -> None:
        blob = b"\x00DexClassLoader loads /system/bin/su\x00"

        evidence = _extract({"classes.dex": blob}, make_context)

        assert {"dynamic_code", "shell"} <= set(evidence["suspicious_categories"])

    def test_the_suspicious_list_is_bounded(self, make_context, monkeypatch) -> None:
        monkeypatch.setattr("sephela_static.extractors.strings._MAX_DERIVED", 2)
        blob = b"\x00".join(f"SmsManager call {i}".encode() for i in range(10))

        evidence = _extract({"classes.dex": blob}, make_context)

        assert len(evidence["suspicious"]) == 2
        assert evidence["suspicious_categories"]["sms"] == 10

    def test_the_categories_are_counted(self, make_context) -> None:
        blob = b"\x00".join([b"SmsManager one", b"sendTextMessage two", b"DexClassLoader three"])

        evidence = _extract({"classes.dex": blob}, make_context)

        assert evidence["suspicious_categories"] == {"sms": 2, "dynamic_code": 1}


class TestPatternTable:
    def test_every_category_lists_keywords(self) -> None:
        for category, keywords in _SUSPICIOUS_PATTERNS.items():
            assert keywords, f"{category} can never match"

    def test_no_keyword_is_short_enough_to_match_everything(self) -> None:
        # A three-character keyword matched substring-wise fires on half the framework,
        # which would make the field useless rather than noisy.
        for category, keywords in _SUSPICIOUS_PATTERNS.items():
            for keyword in keywords:
                assert len(keyword) >= 5, f"{category}: {keyword!r} is too short to be specific"

    def test_the_banking_trojan_capabilities_are_all_covered(self) -> None:
        assert {"accessibility", "sms", "dynamic_code", "device_admin"} <= set(_SUSPICIOUS_PATTERNS)


class TestSharedContract:
    def test_the_corpus_is_where_the_url_and_ip_extractors_look(self, make_context) -> None:
        # UrlExtractor reads ctx.shared["strings"]["strings"]; renaming the key here
        # would leave both silently finding nothing.
        evidence = _extract({"classes.dex": b"https://example.com/path"}, make_context)

        assert isinstance(evidence["strings"], list)

    def test_it_needs_no_tooling(self) -> None:
        assert StringExtractor.requires_tools is False
