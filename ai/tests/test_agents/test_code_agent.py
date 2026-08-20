"""CodeAgent — prompt assembly from code-intel evidence and findings merging."""

from __future__ import annotations

from typing import Any

import pytest

from ai.agents.code import DANGEROUS_API_PACKAGES, CodeAgent
from ai.schemas.base import Confidence, Severity
from ai.schemas.code import APIUsageFinding, CodeAnalysis, ControlFlowFinding


def _control_flow(**overrides: Any) -> ControlFlowFinding:
    base: dict[str, Any] = {
        "id": "cf-1",
        "type": "control_flow",
        "severity": Severity.high,
        "confidence": Confidence.high,
        "title": "String decryption loop",
        "description": "Obfuscated string handling",
        "method_signature": "Lcom/evil/A;->decrypt(Ljava/lang/String;)Ljava/lang/String;",
        "anomaly_type": "obfuscated",
    }
    return ControlFlowFinding(**{**base, **overrides})


def _api_usage(**overrides: Any) -> APIUsageFinding:
    base: dict[str, Any] = {
        "id": "api-1",
        "type": "api_usage",
        "severity": Severity.critical,
        "confidence": Confidence.very_high,
        "title": "Overlay window created",
        "description": "TYPE_APPLICATION_OVERLAY added",
        "api_class": "WindowManager",
        "api_method": "addView",
        "api_package": "android.view",
    }
    return APIUsageFinding(**{**base, **overrides})


class TestPrompt:
    def test_it_carries_the_code_intel_summary(self, sample_evidence: dict[str, Any]) -> None:
        prompt = CodeAgent().build_prompt(sample_evidence, {})

        assert "AccessibilityService" in prompt
        assert "DexClassLoader" in prompt

    def test_it_reports_call_graph_scale_rather_than_the_whole_graph(
        self, sample_evidence: dict[str, Any]
    ) -> None:
        # The graph can be tens of thousands of edges; the agent needs its shape, not
        # its contents, and the sinks are what matter for reachability.
        prompt = CodeAgent().build_prompt(sample_evidence, {})

        assert "Nodes: 2" in prompt
        assert "WindowManager.addView" in prompt

    def test_it_carries_the_control_flow_anomalies(self, sample_evidence: dict[str, Any]) -> None:
        prompt = CodeAgent().build_prompt(sample_evidence, {})

        assert "String decryption loop" in prompt

    def test_it_carries_the_decompilation_scope(self) -> None:
        # Regression: the smali and decompiled_java lookups were expression statements
        # whose results were discarded, so the agent asked to interpret the code was
        # never told how much code there was or whether decompilation had succeeded.
        prompt = CodeAgent().build_prompt(
            {
                "static_evidence": {
                    "smali": {
                        "class_count": 1200,
                        "method_count": 8400,
                        "classes": ["Lcom/evil/Payload;"],
                    },
                    "decompiled_java": {"java_file_count": 940, "jadx_exit_code": 0},
                }
            },
            {},
        )

        assert "Smali classes: 1200" in prompt
        assert "Smali methods: 8400" in prompt
        assert "Decompiled Java files: 940" in prompt
        assert "Lcom/evil/Payload;" in prompt

    def test_a_failed_decompilation_is_visible_in_the_prompt(self) -> None:
        # A non-zero exit means the Java tree is partial, which changes how much weight
        # the model should put on the absence of a finding.
        prompt = CodeAgent().build_prompt(
            {"static_evidence": {"decompiled_java": {"jadx_exit_code": 1}}}, {}
        )

        assert "Decompiler exit code: 1" in prompt

    def test_the_class_listing_is_bounded(self) -> None:
        # The smali extractor caps its listing at 5000; spending the whole context on
        # class names would crowd out the evidence that carries signal.
        from ai.agents.code import _CLASS_SAMPLE

        classes = [f"Lcom/example/C{i};" for i in range(_CLASS_SAMPLE + 50)]
        prompt = CodeAgent().build_prompt({"static_evidence": {"smali": {"classes": classes}}}, {})

        assert f"Lcom/example/C{_CLASS_SAMPLE - 1};" in prompt
        assert f"Lcom/example/C{_CLASS_SAMPLE};" not in prompt

    def test_suspicious_strings_are_bounded_to_fifty(self) -> None:
        strings = [f"marker-{i}" for i in range(80)]
        prompt = CodeAgent().build_prompt(
            {"static_evidence": {"strings": {"suspicious": strings}}}, {}
        )

        assert "marker-49" in prompt
        assert "marker-50" not in prompt

    def test_it_carries_the_dangerous_package_reference(self) -> None:
        prompt = CodeAgent().build_prompt({}, {})

        for category in DANGEROUS_API_PACKAGES:
            assert category in prompt

    def test_an_empty_envelope_still_builds(self) -> None:
        assert CodeAgent().build_prompt({}, {}).strip()


class TestPackageTable:
    @pytest.mark.parametrize("category", sorted(DANGEROUS_API_PACKAGES))
    def test_every_category_lists_packages(self, category: str) -> None:
        assert DANGEROUS_API_PACKAGES[category], f"{category} lists nothing to match"

    def test_the_banking_trojan_capabilities_are_all_covered(self) -> None:
        assert {"overlay", "accessibility", "sms", "device_admin"} <= set(DANGEROUS_API_PACKAGES)


class TestFindingsExtraction:
    def test_both_finding_kinds_are_merged(self) -> None:
        analysis = CodeAnalysis(
            control_flow_findings=[_control_flow()],
            api_usage_findings=[_api_usage()],
        )

        findings = CodeAgent().extract_findings(analysis)

        assert [f.id for f in findings] == ["cf-1", "api-1"]

    def test_control_flow_findings_come_first(self) -> None:
        # Order is what the report renders in, and structural anomalies frame the API
        # calls that follow rather than the other way round.
        analysis = CodeAnalysis(
            control_flow_findings=[_control_flow(id="cf-a"), _control_flow(id="cf-b")],
            api_usage_findings=[_api_usage(id="api-a")],
        )

        assert [f.id for f in CodeAgent().extract_findings(analysis)] == [
            "cf-a",
            "cf-b",
            "api-a",
        ]

    def test_an_empty_analysis_yields_nothing(self) -> None:
        assert CodeAgent().extract_findings(CodeAnalysis()) == []

    def test_the_generic_findings_list_is_not_double_counted(self) -> None:
        # CodeAnalysis has its own `findings` field. extract_findings deliberately
        # reads the two typed lists instead, so a value in both cannot appear twice.
        analysis = CodeAnalysis(api_usage_findings=[_api_usage()], findings=[_api_usage()])

        assert len(CodeAgent().extract_findings(analysis)) == 1
