"""ReportAgent — prompt assembly from every prior stage, and the deterministic report.

The dict/model handling is the focus. ``GraphState.all_findings`` is declared as
``list[dict[str, Any]]``, so dicts are the shape this agent actually receives in
production — and the inline access it used to do raised ``AttributeError`` on every
one of them, meaning the final report stage failed on any job that found something.
"""

from __future__ import annotations

from typing import Any

from ai.agents.report import ReportAgent, generate_report_deterministic
from ai.schemas.base import Confidence, Finding, Severity

DICT_FINDING: dict[str, Any] = {
    "id": "perm-accessibility",
    "type": "permission",
    "severity": "critical",
    "title": "Accessibility service requested",
    "description": "Can read every screen and synthesise input.",
    "mitre_techniques": ["T1417.001"],
    "owasp_mobile": ["M1"],
}

MODEL_FINDING = Finding(
    id="net-c2",
    type="network",
    severity=Severity.high,
    confidence=Confidence.high,
    title="Hardcoded C2 host",
    description="Public IP embedded in strings.",
    mitre_techniques=["T1071.001"],
    owasp_mobile=["M3"],
)


class TestPromptWithDictFindings:
    def test_a_dict_finding_is_rendered(self) -> None:
        prompt = ReportAgent().build_prompt({}, {"all_findings": [DICT_FINDING]})

        assert "perm-accessibility" in prompt
        assert "T1417.001" in prompt
        assert '"severity": "critical"' in prompt

    def test_the_finding_count_is_stated(self) -> None:
        prompt = ReportAgent().build_prompt(
            {}, {"all_findings": [DICT_FINDING, DICT_FINDING, DICT_FINDING]}
        )

        assert "ALL FINDINGS (3)" in prompt

    def test_a_finding_missing_optional_keys_does_not_break_the_prompt(self) -> None:
        # An agent can emit a finding without MITRE mappings; the report still has to
        # render, because a report that fails to generate loses every other finding too.
        prompt = ReportAgent().build_prompt({}, {"all_findings": [{"id": "bare"}]})

        assert "bare" in prompt
        assert '"mitre": []' in prompt


class TestPromptWithModelFindings:
    def test_a_model_finding_is_rendered_with_its_enum_value(self) -> None:
        prompt = ReportAgent().build_prompt({}, {"all_findings": [MODEL_FINDING]})

        assert "net-c2" in prompt
        # The enum's value, not "Severity.high" — the report is read by people.
        assert '"severity": "high"' in prompt
        assert "Severity.high" not in prompt

    def test_dicts_and_models_can_be_mixed(self) -> None:
        # Nothing guarantees one shape: the graph produces dicts, a direct caller
        # produces models, and a partially-migrated pipeline produces both.
        prompt = ReportAgent().build_prompt({}, {"all_findings": [DICT_FINDING, MODEL_FINDING]})

        assert "perm-accessibility" in prompt
        assert "net-c2" in prompt


class TestPromptContext:
    def test_the_job_and_sample_identity_are_carried(self) -> None:
        prompt = ReportAgent().build_prompt({"job_id": "job-42", "sample_sha256": "a" * 64}, {})

        assert "job-42" in prompt
        assert "a" * 64 in prompt

    def test_the_risk_assessment_is_carried(self) -> None:
        prompt = ReportAgent().build_prompt(
            {},
            {"risk_agent_output": {"score": 88.5, "tier": "malicious", "confidence": 0.9}},
        )

        assert "88.5" in prompt
        assert "malicious" in prompt

    def test_a_missing_risk_assessment_degrades_to_not_available(self) -> None:
        # Scoring is a separate stage and can be skipped, so this is a real input.
        prompt = ReportAgent().build_prompt({}, {})

        assert "Score: N/A" in prompt

    def test_each_agent_output_is_truncated_rather_than_dropped(self) -> None:
        # A single agent's output can be enormous; the report needs a sample of each
        # rather than all of one and none of the rest.
        prompt = ReportAgent().build_prompt({}, {"manifest_agent_output": {"blob": "x" * 5000}})

        assert "x" * 100 in prompt
        assert "x" * 5000 not in prompt

    def test_an_entirely_empty_context_still_builds(self) -> None:
        assert ReportAgent().build_prompt({}, {}).strip()


class TestDeterministicReport:
    def test_it_produces_a_report_from_an_evidence_envelope(self) -> None:
        result = generate_report_deterministic({"job_id": "job-7"}, {})

        assert result.report is not None
        assert result.generation_time_ms >= 0

    def test_an_empty_envelope_is_a_valid_input(self) -> None:
        assert generate_report_deterministic({}, {}).report is not None


class TestFindingsExtraction:
    def test_the_report_agent_emits_no_new_findings(self) -> None:
        # It summarises what the others found; inventing findings here would produce a
        # claim with no analysis behind it.
        result = generate_report_deterministic({"job_id": "j"}, {})

        assert ReportAgent().extract_findings(result) == []
