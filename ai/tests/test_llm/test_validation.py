"""The validation layer: JSON repair → schema validation → business rules.

Every one of these modules was written, documented as being in the agent execution
path, and never called from it. They are the difference between "the model said so"
and "the model said so and it is consistent with the evidence", so they are now wired
into ``BaseAgent.execute`` and covered here.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import BaseModel, Field

from ai.validation.json_repair import JSONRepair
from ai.validation.response_validator import ResponseValidator
from ai.validation.schema_validator import (
    IssueSeverity,
    SchemaValidator,
    ValidationReport,
    ValidationStatus,
)


def _model(report: ValidationReport) -> Any:
    """The validated instance, asserted present — keeps the assertions below readable."""
    assert report.model_instance is not None
    return report.model_instance


class Verdict(BaseModel):
    verdict: str
    score: float = Field(0.0, ge=0.0, le=100.0)
    confidence_overall: float = Field(0.5, ge=0.0, le=1.0)
    findings: list[dict[str, Any]] = Field(default_factory=list)
    evidence_references: list[dict[str, Any]] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# JSON repair
# ---------------------------------------------------------------------------


class TestJSONRepair:
    def test_clean_json_parses_directly(self) -> None:
        result = JSONRepair.repair('{"a": 1}')

        assert result.success is True
        assert result.data == {"a": 1}
        # Recorded so a report can say whether the model needed help.
        assert result.strategy_used == "direct_parse"

    def test_a_json_code_fence_is_stripped(self) -> None:
        result = JSONRepair.repair('```json\n{"a": 1}\n```')

        assert result.data == {"a": 1}

    def test_an_unlabelled_code_fence_is_stripped(self) -> None:
        result = JSONRepair.repair('```\n{"a": 1}\n```')

        assert result.data == {"a": 1}

    def test_json_wrapped_in_prose_is_extracted(self) -> None:
        # Models preface answers constantly, and it is not worth a retry.
        result = JSONRepair.repair('Here is my analysis:\n{"a": 1}\nHope that helps!')

        assert result.data == {"a": 1}

    def test_a_trailing_comma_is_removed(self) -> None:
        result = JSONRepair.repair('{"a": 1, "b": 2,}')

        assert result.data == {"a": 1, "b": 2}

    def test_single_quoted_keys_are_fixed(self) -> None:
        result = JSONRepair.repair("{'a': 1}")

        assert result.data == {"a": 1}

    def test_a_python_dict_repr_is_parsed(self) -> None:
        # Single quotes on the *values* too, which the key-only regex could not fix.
        result = JSONRepair.repair("{'verdict': 'clean'}")

        assert result.data == {"verdict": "clean"}

    def test_python_boolean_and_none_spellings_are_accepted(self) -> None:
        result = JSONRepair.repair("{'debuggable': True, 'config': None}")

        assert result.data == {"debuggable": True, "config": None}

    def test_an_apostrophe_inside_a_value_survives(self) -> None:
        # The reason this is parsed rather than quote-swapped: a regex would turn the
        # apostrophe into a syntax error and lose the whole response.
        result = JSONRepair.repair("{'note': \"doesn't decrypt\"}")

        assert result.data == {"note": "doesn't decrypt"}

    def test_a_json_array_at_the_root_is_not_accepted_as_an_object(self) -> None:
        # Every agent schema is an object; a list means the model answered a different
        # question, and coercing it would invent structure.
        assert JSONRepair.repair("['a', 'b']").success is False

    def test_a_truncated_object_is_closed(self) -> None:
        # This is what a max_tokens cutoff looks like. Recovering the complete part is
        # better than discarding a whole expensive turn.
        result = JSONRepair.repair('{"verdict": "clean", "score": 12')

        assert result.success is True
        assert result.data is not None
        assert result.data["verdict"] == "clean"

    def test_unrecoverable_text_reports_failure_rather_than_raising(self) -> None:
        result = JSONRepair.repair("I am not going to answer that.")

        assert result.success is False
        assert result.error

    def test_the_original_text_is_always_retained(self) -> None:
        # Needed to show an analyst what the model actually said.
        result = JSONRepair.repair('```json\n{"a": 1}\n```')

        assert "```" in result.original_text


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------


class TestSchemaValidator:
    def test_valid_output_is_reported_as_valid(self) -> None:
        report = SchemaValidator(Verdict).validate('{"verdict": "clean"}')

        assert report.status is ValidationStatus.VALID
        assert report.is_usable is True
        assert _model(report).verdict == "clean"

    def test_repaired_output_is_labelled_as_repaired(self) -> None:
        # The distinction matters: repeated repairs are a signal the prompt or the
        # model choice is wrong, not just noise to swallow.
        report = SchemaValidator(Verdict).validate('```json\n{"verdict": "clean"}\n```')

        assert report.status is ValidationStatus.REPAIRED
        assert report.repair_strategy == "fence_extract"

    def test_unparseable_output_is_invalid_and_unusable(self) -> None:
        report = SchemaValidator(Verdict).validate("no json here")

        assert report.status is ValidationStatus.INVALID
        assert report.is_usable is False
        assert report.model_instance is None
        assert report.errors

    def test_a_missing_required_field_is_an_error(self) -> None:
        report = SchemaValidator(Verdict).validate('{"score": 10}')

        assert report.is_usable is False
        assert any(i.field_path == "verdict" for i in report.errors)

    def test_a_stringified_number_is_coerced(self) -> None:
        # Models emit "42" for a float field routinely; a retry buys nothing.
        report = SchemaValidator(Verdict).validate('{"verdict": "clean", "score": "42"}')

        assert report.is_usable is True
        assert _model(report).score == 42.0

    def test_an_out_of_bound_optional_field_degrades_to_partial(self) -> None:
        # It cannot be coerced into range, so the field falls back to its default and
        # the result is kept as PARTIAL with an error recorded. Silently reporting a
        # score of 0.0 for a model that said 9001 would be the worst outcome, which is
        # why BaseAgent.execute treats an error-severity issue as grounds for a retry.
        report = SchemaValidator(Verdict).validate('{"verdict": "clean", "score": 9001}')

        assert report.status is ValidationStatus.PARTIAL
        assert report.is_usable is True
        assert _model(report).score == 0.0
        assert any(i.field_path == "score" for i in report.errors)

    def test_an_out_of_bound_required_field_is_unusable(self) -> None:
        class Strict(BaseModel):
            score: float = Field(..., ge=0.0, le=100.0)

        report = SchemaValidator(Strict).validate('{"score": 9001}')

        assert report.is_usable is False

    def test_validate_dict_skips_repair(self) -> None:
        report = SchemaValidator(Verdict).validate_dict({"verdict": "clean"})

        assert report.is_usable is True

    def test_the_report_summary_is_one_line(self) -> None:
        summary = SchemaValidator(Verdict).validate('{"verdict": "clean"}').summary()

        assert "\n" not in summary
        assert "status=valid" in summary

    def test_validation_never_raises_whatever_the_input(self) -> None:
        # It sits between an untrusted model response and the rest of the pipeline, so
        # raising would turn a bad answer into a failed job.
        for raw in ["", "   ", "null", "[]", "[1,2,3]", '{"a": ', "\x00\x01", "𝕁𝕊𝕆ℕ"]:
            report = SchemaValidator(Verdict).validate(raw)
            assert isinstance(report.is_usable, bool)


# ---------------------------------------------------------------------------
# Business rules — the checks the schema cannot express
# ---------------------------------------------------------------------------


class TestConfidenceAndScoreBounds:
    def test_a_confidence_inside_the_unit_interval_passes(self) -> None:
        report = ResponseValidator(Verdict).validate(
            '{"verdict": "clean", "confidence_overall": 0.7}'
        )

        assert report.errors == []

    def test_a_score_within_range_passes(self) -> None:
        report = ResponseValidator(Verdict).validate('{"verdict": "clean", "score": 55}')

        assert report.errors == []


class TestMitreMappingRule:
    def _report(self, findings: list[dict[str, Any]]):
        import json

        return ResponseValidator(Verdict).validate(
            json.dumps({"verdict": "malicious", "findings": findings})
        )

    def test_a_critical_finding_without_a_technique_is_warned_about(self) -> None:
        # An unmapped critical finding cannot be placed on an ATT&CK matrix, which is
        # how a SOC triages it — so it is worth flagging without failing the analysis.
        report = self._report([{"severity": "critical", "title": "Overlay abuse"}])

        assert any("MITRE" in w.message for w in report.warnings)

    def test_a_high_finding_without_a_technique_is_warned_about(self) -> None:
        report = self._report([{"severity": "high", "title": "SMS interception"}])

        assert any("MITRE" in w.message for w in report.warnings)

    def test_a_mapped_critical_finding_is_silent(self) -> None:
        report = self._report(
            [{"severity": "critical", "title": "Overlay", "mitre_techniques": ["T1417.002"]}]
        )

        assert report.warnings == []

    def test_the_alternative_field_name_is_accepted(self) -> None:
        report = self._report(
            [{"severity": "critical", "title": "Overlay", "mitre_mappings": ["T1417.002"]}]
        )

        assert report.warnings == []

    def test_a_low_finding_needs_no_technique(self) -> None:
        # Mapping every informational finding would bury the ones that matter.
        report = self._report([{"severity": "low", "title": "Backup allowed"}])

        assert report.warnings == []

    def test_a_non_dict_finding_is_skipped_rather_than_crashing(self) -> None:
        report = ResponseValidator(Verdict).validate('{"verdict": "x", "findings": []}')

        assert report.is_usable is True


class TestEvidenceGrounding:
    """The anti-hallucination check: a claim must cite analysis that ran."""

    EVIDENCE: dict[str, Any] = {"manifest": {}, "permissions": {}, "network": {}}

    def _report(self, refs: list[dict[str, Any]], evidence: dict[str, Any] | None = None):
        import json

        return ResponseValidator(Verdict).validate(
            json.dumps({"verdict": "malicious", "evidence_references": refs}),
            evidence=self.EVIDENCE if evidence is None else evidence,
        )

    def test_a_reference_to_a_real_extractor_passes(self) -> None:
        assert self._report([{"extractor": "manifest"}]).warnings == []

    def test_a_reference_to_an_extractor_that_did_not_run_is_flagged(self) -> None:
        report = self._report([{"extractor": "dynamic"}])

        (warning,) = report.warnings
        assert "dynamic" in warning.message
        # The available set is named, so the message is actionable rather than a scold.
        assert "manifest" in warning.message

    def test_the_flag_is_a_warning_not_an_error(self) -> None:
        # The surrounding analysis may be sound; an analyst needs to see the claim and
        # that it was unsupported, not lose the whole agent result.
        report = self._report([{"extractor": "invented"}])

        assert report.is_usable is True
        assert report.errors == []

    def test_each_bad_reference_is_reported_separately(self) -> None:
        report = self._report([{"extractor": "a"}, {"extractor": "b"}])

        assert len(report.warnings) == 2

    def test_without_an_evidence_envelope_nothing_is_checked(self) -> None:
        # Grounding cannot be judged against evidence that was not supplied, and
        # guessing would produce false accusations.
        assert self._report([{"extractor": "invented"}], evidence={}).warnings == []

    def test_a_reference_with_no_extractor_named_is_skipped(self) -> None:
        assert self._report([{"path": "permissions"}]).warnings == []

    def test_a_malformed_reference_does_not_crash_the_check(self) -> None:
        import json

        report = ResponseValidator(Verdict).validate(
            json.dumps({"verdict": "x", "evidence_references": [{}]}),
            evidence=self.EVIDENCE,
        )

        assert report.is_usable is True


class TestResponseValidatorContract:
    def test_it_reports_rather_than_raises_on_unusable_output(self) -> None:
        report = ResponseValidator(Verdict).validate("total nonsense")

        assert report.is_usable is False
        assert report.errors

    def test_errors_and_warnings_are_separable(self) -> None:
        # BaseAgent.execute keys its retry decision on errors alone, so a warning must
        # never look like one.
        report = ResponseValidator(Verdict).validate(
            '{"verdict": "x", "findings": [{"severity": "critical", "title": "t"}]}'
        )

        assert report.warnings
        assert report.errors == []
        assert all(i.severity is IssueSeverity.WARNING for i in report.warnings)

    def test_the_agent_name_is_accepted_for_log_correlation(self) -> None:
        report = ResponseValidator(Verdict).validate(
            '{"verdict": "clean"}', agent_name="manifest_agent"
        )

        assert report.is_usable is True

    def test_validate_dict_runs_the_business_rules_too(self) -> None:
        report = ResponseValidator(Verdict).validate_dict(
            {"verdict": "x", "evidence_references": [{"extractor": "invented"}]},
            evidence={"manifest": {}},
        )

        assert report.warnings


@pytest.mark.parametrize(
    "raw",
    [
        '{"verdict": "clean"}',
        '```json\n{"verdict": "clean"}\n```',
        'Analysis follows.\n{"verdict": "clean"}',
        '{"verdict": "clean",}',
        "{'verdict': 'clean'}",
    ],
)
def test_every_shape_a_model_realistically_returns_is_accepted(raw: str) -> None:
    """One place to see the full set of malformations that must not cost a retry."""
    report = ResponseValidator(Verdict).validate(raw)

    assert report.is_usable is True
    assert _model(report).verdict == "clean"
