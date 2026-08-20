"""NetworkAgent — C2 heuristics, certificate posture, cleartext, IP classification."""

from __future__ import annotations

import re
from typing import Any

import pytest

from ai.agents.network import (
    BANKING_TARGET_KEYWORDS,
    KNOWN_C2_PATTERNS,
    SUSPICIOUS_TLDS,
    NetworkAgent,
    _is_routable,
    analyze_network_deterministic,
)
from ai.schemas.base import Severity


def _analyse(
    *,
    domains: list[str] | None = None,
    ips: list[str] | None = None,
    urls: list[str] | None = None,
    certificates: list[dict[str, Any]] | None = None,
    manifest: dict[str, Any] | None = None,
    ti_context: dict[str, Any] | None = None,
):
    return analyze_network_deterministic(
        {
            "static_evidence": {
                "network": {
                    "domains": domains or [],
                    "ips": ips or [],
                    "urls": urls or [],
                },
                "certificate": {"certificates": certificates or []},
                "manifest": manifest or {},
            }
        },
        ti_context,
    )


def _connection(analysis, host: str):
    return next(c for c in analysis.connections if c.host == host)


class TestPrompt:
    def test_it_carries_the_indicators_and_the_heuristic_tables(
        self, sample_evidence: dict[str, Any]
    ) -> None:
        prompt = NetworkAgent().build_prompt(sample_evidence, {})

        assert "malicious.tk" in prompt
        # The model is given the same tables the deterministic path uses, so its
        # reasoning is anchored to them rather than to its own recollection.
        assert ".tk" in prompt
        assert "bank" in prompt


class TestDomainHeuristics:
    def test_an_ordinary_domain_is_not_suspicious(self) -> None:
        analysis = _analyse(domains=["example.com"])

        assert _connection(analysis, "example.com").is_suspicious is False

    @pytest.mark.parametrize("tld", sorted(SUSPICIOUS_TLDS))
    def test_every_listed_tld_is_flagged(self, tld: str) -> None:
        domain = f"payload{tld}"

        connection = _connection(_analyse(domains=[domain]), domain)

        assert connection.is_suspicious is True
        assert any(tld in reason for reason in connection.suspicion_reasons)

    @pytest.mark.parametrize(
        "domain",
        [
            "malware.ddns.net",
            "panel.no-ip.com",
            "host.dyndns.org",
            "c2.hopto.org",
            "drop.servehttp.com",
            "beacon.zapto.org",
        ],
    )
    def test_dynamic_dns_hosts_match_a_c2_pattern(self, domain: str) -> None:
        connection = _connection(_analyse(domains=[domain]), domain)

        assert connection.is_suspicious is True
        assert any("C2 pattern" in reason for reason in connection.suspicion_reasons)

    def test_a_long_random_looking_domain_matches_the_dga_pattern(self) -> None:
        domain = "a1b2c3d4e5f6g7h8i9j0k.com"

        assert _connection(_analyse(domains=[domain]), domain).is_suspicious is True

    @pytest.mark.parametrize("keyword", ["bank", "paypal", "coinbase"])
    def test_a_banking_keyword_in_the_host_is_flagged(self, keyword: str) -> None:
        domain = f"secure-{keyword}-login.com"

        connection = _connection(_analyse(domains=[domain]), domain)

        assert connection.is_suspicious is True
        assert any(keyword in reason for reason in connection.suspicion_reasons)

    def test_the_keyword_match_is_case_insensitive(self) -> None:
        domain = "Secure-BANK-Login.com"

        assert _connection(_analyse(domains=[domain]), domain).is_suspicious is True

    def test_a_domain_with_no_dot_does_not_crash_the_tld_check(self) -> None:
        # String extraction produces junk; a bare token must not take the stage down.
        assert _analyse(domains=["localhost"]).connections[0].is_suspicious is False


class TestIPClassification:
    @pytest.mark.parametrize("ip", ["1.2.3.4", "8.8.8.8", "172.32.0.1"])
    def test_a_public_address_is_suspicious(self, ip: str) -> None:
        # A hardcoded public IP is usually a C2 endpoint that skips DNS.
        assert _connection(_analyse(ips=[ip]), ip).is_suspicious is True

    @pytest.mark.parametrize(
        "ip", ["10.0.0.1", "192.168.1.1", "172.16.0.1", "172.20.5.5", "172.31.255.255", "127.0.0.1"]
    )
    def test_a_private_or_loopback_address_is_not(self, ip: str) -> None:
        # Regression: the check was `not ip.startswith(("10.","192.168.","172.16.","127."))`,
        # so everything in 172.17–172.31 — most of the private /12 — read as public.
        assert _connection(_analyse(ips=[ip]), ip).is_suspicious is False

    def test_the_cloud_metadata_address_is_link_local_not_public(self) -> None:
        assert _is_routable("169.254.169.254") is False

    def test_an_unparseable_address_is_not_treated_as_evidence(self) -> None:
        assert _is_routable("not-an-ip") is False


class TestCertificates:
    def test_a_self_signed_certificate_raises_a_high_finding(self) -> None:
        analysis = _analyse(
            certificates=[
                {"subject": "CN=X", "issuer": "CN=X", "self_signed": True, "sha256": "f" * 64}
            ]
        )

        (finding,) = analysis.findings
        assert finding.severity is Severity.high
        assert finding.finding_type == "cert_pinning"
        assert finding.mitre_techniques == ["T1573.002"]

    def test_a_ca_signed_certificate_raises_nothing(self) -> None:
        analysis = _analyse(
            certificates=[{"subject": "CN=app", "issuer": "CN=Real CA", "self_signed": False}]
        )

        assert analysis.findings == []

    def test_certificate_fields_are_carried_into_the_analysis(self) -> None:
        analysis = _analyse(
            certificates=[
                {
                    "subject": "CN=app",
                    "issuer": "CN=CA",
                    "serial": "1234",
                    "sha256": "a" * 64,
                    "not_before": "2026-01-01",
                    "not_after": "2027-01-01",
                }
            ]
        )

        (cert,) = analysis.certificates
        assert (cert.subject, cert.issuer, cert.serial_number) == ("CN=app", "CN=CA", "1234")
        assert cert.not_after == "2027-01-01"


class TestTransportPosture:
    def test_cleartext_traffic_raises_a_finding(self) -> None:
        analysis = _analyse(manifest={"uses_cleartext_traffic": True})

        (finding,) = analysis.findings
        assert finding.finding_type == "cleartext"
        assert analysis.cleartext_permitted is True

    def test_no_cleartext_raises_nothing(self) -> None:
        analysis = _analyse(manifest={"uses_cleartext_traffic": False})

        assert analysis.findings == []
        assert analysis.cleartext_permitted is False

    def test_a_pin_set_in_the_network_config_is_recognised_as_pinning(self) -> None:
        analysis = _analyse(manifest={"network_security_config": "<pin-set>...</pin-set>"})

        assert analysis.pinning_implemented is True

    def test_a_config_without_pins_is_not_pinning(self) -> None:
        analysis = _analyse(manifest={"network_security_config": "<base-config/>"})

        assert analysis.pinning_implemented is False


class TestThreatIntelCorrelation:
    def test_a_domain_confirmed_malicious_raises_a_critical_finding(self) -> None:
        analysis = _analyse(
            domains=["c2.example.net"],
            ti_context={
                "domains": {
                    "c2.example.net": {
                        "malicious": True,
                        "categories": ["c2"],
                        "families": ["Anatsa"],
                    }
                }
            },
        )

        (finding,) = analysis.findings
        assert finding.severity is Severity.critical
        assert finding.indicator == "c2.example.net"
        assert analysis.domain_intel[0].related_malware_families == ["Anatsa"]

    def test_intel_that_clears_a_domain_records_it_without_a_finding(self) -> None:
        analysis = _analyse(
            domains=["cdn.example.com"],
            ti_context={"domains": {"cdn.example.com": {"malicious": False}}},
        )

        assert analysis.findings == []
        assert analysis.domain_intel[0].is_malicious is False

    def test_without_intel_a_domain_gets_no_intel_record(self) -> None:
        assert _analyse(domains=["example.com"]).domain_intel == []


class TestEmptyEvidence:
    def test_an_empty_envelope_yields_an_empty_but_valid_analysis(self) -> None:
        analysis = analyze_network_deterministic({})

        assert analysis.domains == []
        assert analysis.connections == []
        assert analysis.findings == []


class TestHeuristicTables:
    def test_every_c2_pattern_compiles(self) -> None:
        for pattern in KNOWN_C2_PATTERNS:
            re.compile(pattern)

    def test_every_suspicious_tld_is_written_with_its_dot(self) -> None:
        # The lookup builds "." + last label, so an entry without the dot never matches.
        for tld in SUSPICIOUS_TLDS:
            assert tld.startswith("."), tld

    def test_banking_keywords_are_lowercase(self) -> None:
        # They are compared against `domain.lower()`, so an uppercase entry is dead.
        for keyword in BANKING_TARGET_KEYWORDS:
            assert keyword == keyword.lower(), keyword


class TestFindingsExtraction:
    def test_findings_pass_through_unchanged(self) -> None:
        analysis = _analyse(manifest={"uses_cleartext_traffic": True})

        assert NetworkAgent().extract_findings(analysis) == analysis.findings
