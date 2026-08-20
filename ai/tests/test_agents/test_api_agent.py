"""APIAgent — dangerous-API signature table and findings mapping."""

from __future__ import annotations

import re
from typing import Any

import pytest

from ai.agents.api import DANGEROUS_API_SIGNATURES, APIAgent
from ai.schemas.api import APIAnalysis, APICall
from ai.schemas.base import Confidence, Severity


class TestPrompt:
    def test_it_carries_the_call_sites_from_code_intel(
        self, sample_evidence: dict[str, Any]
    ) -> None:
        prompt = APIAgent().build_prompt(sample_evidence, {})

        assert "WindowManager.addView" in prompt

    def test_it_carries_the_signature_reference_table(self) -> None:
        # The model is asked to classify against the same categories the report uses,
        # so the table has to be in the prompt rather than assumed known.
        prompt = APIAgent().build_prompt({}, {})

        for category in DANGEROUS_API_SIGNATURES:
            assert category in prompt


class TestSignatureTable:
    @pytest.mark.parametrize("category", sorted(DANGEROUS_API_SIGNATURES))
    def test_every_category_is_complete(self, category: str) -> None:
        entry = DANGEROUS_API_SIGNATURES[category]

        assert entry["patterns"], f"{category} matches nothing"
        assert isinstance(entry["severity"], Severity)
        assert entry["owasp"], f"{category} has no OWASP category"
        assert str(entry["description"]).strip()

    @pytest.mark.parametrize("category", sorted(DANGEROUS_API_SIGNATURES))
    def test_a_high_severity_category_maps_to_mitre(self, category: str) -> None:
        # The threshold is the project's own, from ResponseValidator._check_mitre_mappings:
        # a high or critical finding without a technique is flagged, a low one is not.
        # keystore_access and logging_sensitive are deliberately unmapped and low.
        entry = DANGEROUS_API_SIGNATURES[category]
        if entry["severity"] in (Severity.high, Severity.critical):
            assert entry["mitre"], f"{category} is {entry['severity'].value} with no MITRE mapping"

    @pytest.mark.parametrize("category", sorted(DANGEROUS_API_SIGNATURES))
    def test_every_pattern_compiles(self, category: str) -> None:
        # They are written as regexes and fed to the model as such; one that cannot
        # compile is a pattern nothing will ever apply.
        for pattern in DANGEROUS_API_SIGNATURES[category]["patterns"]:
            re.compile(pattern)

    def test_the_categories_a_banking_trojan_needs_are_all_present(self) -> None:
        # Overlay + accessibility + SMS interception is the Anubis/Cerberus shape; a
        # table missing any of them cannot classify the family this platform exists for.
        assert {"reflection_abuse", "sms_intercept", "crypto_misuse"} <= set(
            DANGEROUS_API_SIGNATURES
        )


class TestFindingsExtraction:
    def _call(self, **overrides: Any) -> APICall:
        base: dict[str, Any] = {
            "api_class": "SmsManager",
            "api_method": "sendTextMessage",
            "api_package": "android.telephony",
            "call_sites": ["Lcom/evil/A;->run()V"],
            "severity": Severity.critical,
            "confidence": Confidence.high,
            "mitre_techniques": ["T1582"],
            "owasp_categories": ["M1"],
        }
        return APICall(**{**base, **overrides})

    def test_each_api_call_becomes_one_finding(self) -> None:
        analysis = APIAnalysis(api_calls=[self._call(), self._call(api_method="getDefault")])

        findings = APIAgent().extract_findings(analysis)

        assert len(findings) == 2
        assert {f.type for f in findings} == {"dangerous_api"}

    def test_the_finding_carries_the_severity_and_mappings_of_its_call(self) -> None:
        analysis = APIAnalysis(api_calls=[self._call()])

        (finding,) = APIAgent().extract_findings(analysis)

        assert finding.severity is Severity.critical
        assert finding.mitre_techniques == ["T1582"]
        assert finding.owasp_mobile == ["M1"]

    def test_the_finding_id_identifies_the_api(self) -> None:
        analysis = APIAnalysis(api_calls=[self._call()])

        (finding,) = APIAgent().extract_findings(analysis)

        assert "SmsManager" in finding.id
        assert "sendTextMessage" in finding.id

    def test_the_call_sites_survive_into_the_metadata(self) -> None:
        # This is the provenance an analyst expands to in the dashboard, so losing it
        # would leave a finding with nothing behind it.
        analysis = APIAnalysis(api_calls=[self._call()])

        (finding,) = APIAgent().extract_findings(analysis)

        assert finding.metadata["call_sites"] == ["Lcom/evil/A;->run()V"]
        assert finding.evidence_refs[0].extractor == "api_usage"

    def test_reflection_and_dynamic_loading_are_recorded(self) -> None:
        analysis = APIAnalysis(api_calls=[self._call(is_reflection=True, is_dynamic_loading=True)])

        (finding,) = APIAgent().extract_findings(analysis)

        assert finding.metadata["is_reflection"] is True
        assert finding.metadata["is_dynamic_loading"] is True

    def test_no_api_calls_yields_no_findings(self) -> None:
        assert APIAgent().extract_findings(APIAnalysis()) == []
