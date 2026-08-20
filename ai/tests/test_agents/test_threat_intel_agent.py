"""ThreatIntelAgent — IOC correlation and malware-family attribution.

URL and certificate correlation are covered here because they were missing: the two
lookups existed as expression statements whose results were thrown away, so
``url_matches`` and ``cert_matches`` were always empty and ``total_ioc_matches``
under-counted every sample.
"""

from __future__ import annotations

from typing import Any

import pytest

from ai.agents.threat_intel import (
    MALWARE_FAMILIES_BANKING,
    ThreatIntelAgent,
    analyze_threat_intel_deterministic,
)
from ai.schemas.base import Confidence, Severity

SHA256 = "a" * 64
CERT_SHA256 = "c" * 64


def _analyse(
    *,
    sha256: str = SHA256,
    domains: list[str] | None = None,
    ips: list[str] | None = None,
    urls: list[str] | None = None,
    certificates: list[dict[str, Any]] | None = None,
    ti_cache: dict[str, Any] | None = None,
):
    return analyze_threat_intel_deterministic(
        {
            "static_evidence": {
                "hashes": {"sha256": sha256},
                "network": {
                    "domains": domains or [],
                    "ips": ips or [],
                    "urls": urls or [],
                },
                "certificate": {"certificates": certificates or []},
            }
        },
        ti_cache,
    )


class TestPrompt:
    def test_it_carries_the_hash_and_the_family_table(
        self, sample_evidence: dict[str, Any]
    ) -> None:
        prompt = ThreatIntelAgent().build_prompt(sample_evidence, {})

        assert "Anubis" in prompt


class TestNoIntel:
    def test_without_a_cache_nothing_is_matched(self) -> None:
        analysis = _analyse(domains=["c2.example.net"], ips=["1.2.3.4"], urls=["http://x/y"])

        assert analysis.total_ioc_matches == 0
        assert analysis.findings == []

    def test_an_empty_envelope_is_a_valid_input(self) -> None:
        analysis = analyze_threat_intel_deterministic({})

        assert analysis.total_ioc_matches == 0


class TestHashMatching:
    def test_a_known_hash_is_a_critical_match(self) -> None:
        analysis = _analyse(
            ti_cache={"hashes": {SHA256: {"source": "MalwareBazaar", "tags": ["trojan"]}}}
        )

        (match,) = analysis.hash_matches
        assert match.indicator_type == "hash"
        assert match.severity is Severity.critical
        assert match.confidence is Confidence.very_high
        assert analysis.malicious_hash_matches == 1

    def test_a_different_hash_does_not_match(self) -> None:
        analysis = _analyse(sha256="b" * 64, ti_cache={"hashes": {SHA256: {}}})

        assert analysis.hash_matches == []


class TestFamilyAttribution:
    def test_a_known_banking_family_produces_an_attribution_finding(self) -> None:
        analysis = _analyse(ti_cache={"hashes": {SHA256: {"families": ["Anubis"]}}})

        (finding,) = analysis.findings
        assert finding.connection_type == "family_attribution"
        assert finding.severity is Severity.critical
        assert "Anubis" in finding.title
        assert finding.mitre_techniques == MALWARE_FAMILIES_BANKING["Anubis"]["mitre"]
        assert analysis.family_attributions == 1

    def test_an_unrecognised_family_is_not_attributed(self) -> None:
        # The hash still matches; only the family claim is dropped, because there is
        # no profile behind it to justify a critical attribution.
        analysis = _analyse(ti_cache={"hashes": {SHA256: {"families": ["NotInTheTable"]}}})

        assert analysis.hash_matches
        assert analysis.malware_families == []
        assert analysis.findings == []

    @pytest.mark.parametrize("family", sorted(MALWARE_FAMILIES_BANKING))
    def test_every_family_in_the_table_can_be_attributed(self, family: str) -> None:
        analysis = _analyse(ti_cache={"hashes": {SHA256: {"families": [family]}}})

        (attributed,) = analysis.malware_families
        assert attributed.family_name == family
        assert attributed.target_sectors == ["financial"]
        assert attributed.mitre_techniques

    def test_the_attribution_points_back_at_the_hash_evidence(self) -> None:
        analysis = _analyse(ti_cache={"hashes": {SHA256: {"families": ["TeaBot"]}}})

        (finding,) = analysis.findings
        assert finding.evidence_refs[0].extractor == "hashes"
        assert finding.evidence_refs[0].path == "sha256"


class TestDomainAndIPMatching:
    def test_a_malicious_domain_is_critical_and_a_known_one_is_medium(self) -> None:
        analysis = _analyse(
            domains=["bad.example", "seen.example"],
            ti_cache={
                "domains": {
                    "bad.example": {"malicious": True, "categories": ["c2"]},
                    "seen.example": {"malicious": False},
                }
            },
        )

        by_indicator = {m.indicator: m for m in analysis.domain_matches}
        assert by_indicator["bad.example"].severity is Severity.critical
        assert by_indicator["seen.example"].severity is Severity.medium
        assert analysis.malicious_domain_matches == 1

    def test_a_malicious_ip_is_counted(self) -> None:
        analysis = _analyse(ips=["1.2.3.4"], ti_cache={"ips": {"1.2.3.4": {"malicious": True}}})

        assert analysis.malicious_ip_matches == 1
        assert analysis.ip_matches[0].indicator_type == "ip"


class TestURLMatching:
    """Regression: the URL lookup's result was discarded, so this never matched."""

    def test_a_known_malicious_url_is_matched(self) -> None:
        url = "http://drop.example/payload.apk"
        analysis = _analyse(
            urls=[url],
            ti_cache={"urls": {url: {"malicious": True, "categories": ["payload"]}}},
        )

        (match,) = analysis.url_matches
        assert match.indicator == url
        assert match.indicator_type == "url"
        assert match.severity is Severity.critical
        assert match.source == "URLhaus"

    def test_a_url_match_is_counted_in_the_total(self) -> None:
        url = "http://drop.example/payload.apk"
        analysis = _analyse(urls=[url], ti_cache={"urls": {url: {"malicious": True}}})

        assert analysis.total_ioc_matches == 1

    def test_a_url_whose_domain_is_known_does_not_match_on_that_alone(self) -> None:
        # A compromised host serves one bad path among many good ones, so the URL is
        # correlated in its own right rather than inheriting its domain's verdict.
        analysis = _analyse(
            urls=["http://cdn.example/ok.js"],
            ti_cache={"domains": {"cdn.example": {"malicious": True}}},
        )

        assert analysis.url_matches == []

    def test_an_unknown_url_does_not_match(self) -> None:
        analysis = _analyse(
            urls=["http://clean.example/"],
            ti_cache={"urls": {"http://other.example/": {"malicious": True}}},
        )

        assert analysis.url_matches == []


class TestCertificateMatching:
    """Regression: the certificate lookup's result was discarded too."""

    def test_a_known_signing_certificate_is_matched(self) -> None:
        analysis = _analyse(
            certificates=[{"sha256": CERT_SHA256, "subject": "CN=X"}],
            ti_cache={"certificates": {CERT_SHA256: {"malicious": True, "families": ["Cerberus"]}}},
        )

        (match,) = analysis.cert_matches
        assert match.indicator == CERT_SHA256
        assert match.indicator_type == "certificate"
        assert match.malware_families == ["Cerberus"]

    def test_a_certificate_match_is_counted_in_the_total(self) -> None:
        analysis = _analyse(
            certificates=[{"sha256": CERT_SHA256}],
            ti_cache={"certificates": {CERT_SHA256: {"malicious": True}}},
        )

        assert analysis.total_ioc_matches == 1

    def test_a_certificate_with_no_digest_is_skipped_rather_than_crashing(self) -> None:
        # The static extractor emits sha256=None when the signature scheme could not
        # be parsed, which is common on v3-only signing.
        analysis = _analyse(
            certificates=[{"subject": "CN=X", "sha256": None}],
            ti_cache={"certificates": {CERT_SHA256: {"malicious": True}}},
        )

        assert analysis.cert_matches == []

    def test_an_unknown_certificate_does_not_match(self) -> None:
        analysis = _analyse(
            certificates=[{"sha256": "d" * 64}],
            ti_cache={"certificates": {CERT_SHA256: {}}},
        )

        assert analysis.cert_matches == []


class TestTotals:
    def test_the_total_sums_every_indicator_class(self) -> None:
        url = "http://drop.example/x"
        analysis = _analyse(
            domains=["bad.example"],
            ips=["1.2.3.4"],
            urls=[url],
            certificates=[{"sha256": CERT_SHA256}],
            ti_cache={
                "hashes": {SHA256: {}},
                "domains": {"bad.example": {"malicious": True}},
                "ips": {"1.2.3.4": {"malicious": True}},
                "urls": {url: {"malicious": True}},
                "certificates": {CERT_SHA256: {"malicious": True}},
            },
        )

        assert analysis.total_ioc_matches == 5


class TestFamilyTable:
    def test_every_family_declares_mitre_techniques(self) -> None:
        for family, profile in MALWARE_FAMILIES_BANKING.items():
            assert profile.get("mitre"), f"{family} has no MITRE techniques to attribute"


class TestFindingsExtraction:
    def test_findings_pass_through_unchanged(self) -> None:
        analysis = _analyse(ti_cache={"hashes": {SHA256: {"families": ["Anubis"]}}})

        assert ThreatIntelAgent().extract_findings(analysis) == analysis.findings
