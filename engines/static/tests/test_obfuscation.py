"""Obfuscation heuristic and packer detection.

The obfuscation extractor reads the smali class list out of ``ctx.shared``, so like the
URL and IP extractors it silently finds nothing if it runs first.
"""

from __future__ import annotations

import importlib.util

import pytest

from sephela_static.envelope import FindingType, Severity
from sephela_static.extractors.obfuscation import (
    _SHORT_NAME,
    ObfuscationExtractor,
    PackerExtractor,
)


def _analyse(classes: list[str], make_context):
    return ObfuscationExtractor().extract(make_context(shared={"smali": {"classes": classes}}))


def _mangled(count: int) -> list[str]:
    """Class names shaped the way ProGuard renames them."""
    letters = "abcdefghijklmnopqrstuvwxyz"
    return [f"L{letters[i % 26]}/{letters[(i // 26) % 26]};" for i in range(count)]


def _readable(count: int) -> list[str]:
    return [f"Lcom/example/app/Service{i};" for i in range(count)]


class TestNameShapeRecognition:
    @pytest.mark.parametrize("name", ["La/b/c;", "La/b;", "La;", "La/bc;", "La/b/cd;"])
    def test_a_mangled_name_is_recognised(self, name: str) -> None:
        assert _SHORT_NAME.search(name) is not None

    @pytest.mark.parametrize(
        "name",
        [
            "Lcom/example/app/MainActivity;",
            "Lcom/example/Foo;",
            "Landroidx/appcompat/app/AppCompatActivity;",
        ],
    )
    def test_a_readable_name_is_not(self, name: str) -> None:
        assert _SHORT_NAME.search(name) is None

    def test_a_short_class_inside_a_real_package_is_not_mangled(self) -> None:
        # Package structure surviving means the names were not wholesale renamed, which
        # is the thing the heuristic is actually about.
        assert _SHORT_NAME.search("Lcom/example/ab;") is None


class TestObfuscationScore:
    def test_a_fully_mangled_class_list_scores_one(self, make_context) -> None:
        evidence = _analyse(_mangled(20), make_context).evidence

        assert evidence["obfuscated_ratio"] == 1.0
        assert evidence["likely_obfuscated"] is True

    def test_a_readable_class_list_scores_zero(self, make_context) -> None:
        evidence = _analyse(_readable(20), make_context).evidence

        assert evidence["obfuscated_ratio"] == 0.0
        assert evidence["likely_obfuscated"] is False

    def test_the_ratio_is_short_names_over_the_total(self, make_context) -> None:
        evidence = _analyse(_mangled(3) + _readable(7), make_context).evidence

        assert evidence["analyzed"] == 10
        assert evidence["short_named_classes"] == 3
        assert evidence["obfuscated_ratio"] == 0.3

    def test_the_ratio_is_rounded_for_a_stable_envelope(self, make_context) -> None:
        # Two runs of the same sample must produce identical evidence, so a float tail
        # would make every re-analysis look like a change.
        evidence = _analyse(_mangled(1) + _readable(2), make_context).evidence

        assert evidence["obfuscated_ratio"] == round(1 / 3, 3)

    def test_an_empty_class_list_scores_zero_without_dividing_by_it(self, make_context) -> None:
        # The smali extractor fails independently, and a stripped or resource-only APK
        # genuinely has no classes.
        result = _analyse([], make_context)

        assert result.evidence == {"analyzed": 0, "obfuscated_ratio": 0.0}
        assert result.findings == []

    def test_a_missing_smali_evidence_block_does_not_raise(self, make_context) -> None:
        result = ObfuscationExtractor().extract(make_context())

        assert result.evidence["analyzed"] == 0


class TestObfuscationFinding:
    def test_a_majority_mangled_list_raises_a_finding(self, make_context) -> None:
        result = _analyse(_mangled(9) + _readable(1), make_context)

        (finding,) = result.findings
        assert finding.id == "obfuscation:name-mangling"
        assert finding.type is FindingType.obfuscation
        assert finding.severity is Severity.medium
        assert finding.mappings.mitre == ["T1027"]
        assert finding.mappings.owasp_mobile == ["M9"]

    def test_the_threshold_is_forty_percent(self, make_context) -> None:
        # Ordinary apps ship obfuscated third-party libraries, so a low bar would flag
        # almost everything and the signal would be worthless.
        below = _analyse(_mangled(4) + _readable(6), make_context)
        above = _analyse(_mangled(5) + _readable(5), make_context)

        assert below.findings == []
        assert above.findings != []

    def test_the_detail_states_the_ratio_a_report_can_quote(self, make_context) -> None:
        result = _analyse(_mangled(9) + _readable(1), make_context)

        assert "90%" in result.findings[0].detail

    def test_confidence_tracks_the_ratio(self, make_context) -> None:
        # A more thoroughly mangled sample is a more confident call.
        weaker = _analyse(_mangled(5) + _readable(5), make_context)
        stronger = _analyse(_mangled(9) + _readable(1), make_context)

        assert stronger.findings[0].confidence > weaker.findings[0].confidence

    def test_confidence_never_reaches_certainty(self, make_context) -> None:
        # It is a name-shape heuristic, not a proof; 1.0 would misrepresent it.
        result = _analyse(_mangled(20), make_context)

        assert result.findings[0].confidence <= 0.95

    def test_it_needs_no_tooling(self) -> None:
        assert ObfuscationExtractor.requires_tools is False


class TestPackerExtractor:
    def test_it_raises_a_clear_error_when_apkid_is_absent(self, make_context) -> None:
        # The common case on any machine without the engine image. The pipeline isolates
        # the failure into `errors` and the run degrades to `partial`, so this message is
        # what an operator actually sees — it has to name the missing tool.
        if importlib.util.find_spec("apkid") is not None:
            pytest.skip("apkid is installed; the absent-tool path cannot be exercised here")

        with pytest.raises(RuntimeError, match="APKID not installed"):
            PackerExtractor().extract(make_context())

    def test_it_declares_that_it_needs_tooling(self) -> None:
        # This is what tells a caller the extractor can be expected to fail on a host
        # without the engine image.
        assert PackerExtractor.requires_tools is True

    def test_it_is_last_in_the_default_chain(self) -> None:
        # It is the slowest and the most likely to be missing, so everything else has
        # already produced its evidence before it runs.
        from sephela_static.extractors import default_extractors

        assert default_extractors()[-1].name == "packers"


class TestSharedEvidenceContract:
    def test_it_reads_the_key_the_smali_extractor_writes(self) -> None:
        from sephela_static.extractors.decompile import SmaliExtractor

        assert SmaliExtractor.name == "smali"

    def test_it_runs_after_smali_in_the_default_chain(self) -> None:
        from sephela_static.extractors import default_extractors

        names = [e.name for e in default_extractors()]

        assert names.index("smali") < names.index("obfuscation")
