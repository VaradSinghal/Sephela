"""RiskAgent — the deterministic engine runs first, the model only narrates it.

That ordering is the design: ``build_prompt`` scores the findings with
``RiskScoringEngine`` and hands the model the result, so the number in the report is
computed rather than generated. These tests pin that the engine actually runs, that
its output reaches the prompt, and that the agent tolerates the finding shapes the
graph produces.
"""

from __future__ import annotations

from typing import Any

from ai.agents.risk import RiskAgent, _finding_summary
from ai.schemas.base import Confidence, Finding, Severity
from ai.schemas.risk import RiskAnalysis

CRITICAL_DICT: dict[str, Any] = {
    "id": "perm-accessibility",
    "type": "permission",
    "severity": "critical",
    "title": "Accessibility service requested",
    "mitre_techniques": ["T1417.001"],
    "owasp_mobile": ["M1"],
}

CRITICAL_MODEL = Finding(
    id="net-c2",
    type="network",
    severity=Severity.critical,
    confidence=Confidence.very_high,
    title="Hardcoded C2 host",
    description="Public IP embedded in strings.",
    mitre_techniques=["T1071.001"],
    owasp_mobile=["M3"],
)


class TestTheEngineRunsFirst:
    def test_a_deterministic_score_is_in_the_prompt(self) -> None:
        prompt = RiskAgent().build_prompt({}, {"manifest_agent_findings": [CRITICAL_DICT]})

        assert "=== DETERMINISTIC SCORE ===" in prompt
        assert "Final Score:" in prompt
        assert "Tier:" in prompt

    def test_the_model_is_told_to_keep_the_computed_score(self) -> None:
        # The whole point of scoring outside the model is that the number is
        # reproducible; a prompt that invited the model to revise it would undo that.
        prompt = RiskAgent().build_prompt({}, {"manifest_agent_findings": [CRITICAL_DICT]})

        assert "as-is" in prompt

    def test_findings_raise_the_score_above_an_empty_run(self) -> None:
        def final_score(prompt: str) -> float:
            line = next(ln for ln in prompt.splitlines() if ln.startswith("Final Score:"))
            return float(line.split(":", 1)[1])

        empty = final_score(RiskAgent().build_prompt({}, {}))
        loaded = final_score(
            RiskAgent().build_prompt(
                {},
                {
                    "manifest_agent_findings": [CRITICAL_DICT],
                    "network_agent_findings": [CRITICAL_MODEL],
                },
            )
        )

        assert loaded > empty

    def test_the_domain_breakdown_is_carried(self) -> None:
        prompt = RiskAgent().build_prompt({}, {"permission_agent_findings": [CRITICAL_DICT]})

        assert "=== DOMAIN BREAKDOWN ===" in prompt

    def test_synergy_rules_are_reported_even_when_none_fired(self) -> None:
        # "None" is information: it says the score is a sum of independent signals
        # rather than a combination the rules recognised as a known malware shape.
        prompt = RiskAgent().build_prompt({}, {})

        assert "=== SYNERGY RULES FIRED ===" in prompt
        assert "None" in prompt


class TestFindingCollection:
    def test_findings_are_collected_from_every_upstream_agent(self) -> None:
        context = {
            f"{agent}_findings": [dict(CRITICAL_DICT, id=f"{agent}-1")]
            for agent in (
                "manifest_agent",
                "permission_agent",
                "code_agent",
                "api_agent",
                "network_agent",
                "threat_intel_agent",
            )
        }

        prompt = RiskAgent().build_prompt({}, context)

        assert "ALL FINDINGS (6 total)" in prompt

    def test_findings_present_directly_in_the_evidence_are_included(self) -> None:
        prompt = RiskAgent().build_prompt({"findings": [CRITICAL_DICT]}, {})

        assert "ALL FINDINGS (1 total)" in prompt

    def test_the_rendered_finding_list_is_bounded(self) -> None:
        # The count reports everything; only the rendered sample is capped, so the
        # score is never computed from a truncated set.
        findings = [dict(CRITICAL_DICT, id=f"f-{i}", title=f"finding {i}") for i in range(60)]

        prompt = RiskAgent().build_prompt({}, {"manifest_agent_findings": findings})

        assert "ALL FINDINGS (60 total)" in prompt
        assert "finding 49" in prompt
        assert "finding 50" not in prompt

    def test_an_agent_that_produced_nothing_is_simply_absent(self) -> None:
        prompt = RiskAgent().build_prompt({}, {})

        assert "ALL FINDINGS (0 total)" in prompt


class TestPermissionExtraction:
    def test_permissions_are_read_from_the_extractor_shape(self) -> None:
        prompt = RiskAgent().build_prompt(
            {"permissions": {"permissions": ["android.permission.READ_SMS"]}}, {}
        )

        assert prompt.strip()

    def test_permissions_given_as_a_bare_list_are_also_accepted(self) -> None:
        # Both shapes exist in the envelope depending on which stage wrote it.
        prompt = RiskAgent().build_prompt({"permissions": ["android.permission.READ_SMS"]}, {})

        assert prompt.strip()


class TestFindingSummary:
    def test_a_dict_finding_is_summarised(self) -> None:
        assert _finding_summary(CRITICAL_DICT) == {
            "type": "permission",
            "severity": "critical",
            "title": "Accessibility service requested",
        }

    def test_a_model_finding_is_summarised(self) -> None:
        summary = _finding_summary(CRITICAL_MODEL)

        assert summary["type"] == "network"
        assert summary["title"] == "Hardcoded C2 host"

    def test_a_long_title_is_truncated(self) -> None:
        summary = _finding_summary({"title": "x" * 500})

        assert len(summary["title"]) == 100

    def test_a_finding_missing_every_key_yields_empty_strings(self) -> None:
        assert _finding_summary({}) == {"type": "", "severity": "", "title": ""}


class TestFindingsExtraction:
    def test_the_risk_agent_emits_no_new_findings(self) -> None:
        # It scores what the others found. A finding invented at scoring time would
        # have no evidence behind it and no provenance to expand to.
        analysis = RiskAnalysis(
            score=0.0,
            tier="benign",
            confidence=0.5,
            breakdown={
                "base_score": 0.0,
                "final_score": 0.0,
                "computed_at": "2026-01-01T00:00:00Z",
                "confidence": 0.5,
            },
        )

        assert RiskAgent().extract_findings(analysis) == []
