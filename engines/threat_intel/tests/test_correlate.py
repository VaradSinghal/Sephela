"""Cross-provider correlation — consensus, severity, and attribution promotion."""

from __future__ import annotations

import pytest

from sephela_threat_intel.base import ProviderResult, Verdict
from sephela_threat_intel.correlate import build_findings, consensus
from sephela_threat_intel.envelope import FindingType, Severity
from sephela_threat_intel.iocs import Ioc, IocType

HASH = Ioc(IocType.hash, "a" * 64, "sample")
DOMAIN = Ioc(IocType.domain, "c2.evil.tk", "static")
IP = Ioc(IocType.ip, "45.55.1.2", "dynamic")


def result(
    ioc: Ioc,
    provider: str,
    verdict: Verdict = Verdict.malicious,
    score: float = 0.8,
    **kwargs: object,
) -> ProviderResult:
    return ProviderResult(ioc=ioc, provider=provider, verdict=verdict, score=score, **kwargs)  # type: ignore[arg-type]


class TestConsensus:
    def test_worst_verdict_wins_over_a_clean_answer(self) -> None:
        # A blocklist is authoritative about what it lists and silent otherwise,
        # so "benign" must never cancel "malicious".
        items = consensus(
            [
                result(DOMAIN, "urlhaus", Verdict.malicious),
                result(DOMAIN, "virustotal", Verdict.benign, score=0.0),
            ]
        )
        assert len(items) == 1
        assert items[0].verdict is Verdict.malicious

    def test_corroboration_raises_confidence_above_any_single_provider(self) -> None:
        single = consensus([result(DOMAIN, "urlhaus", score=0.8)])[0]
        double = consensus(
            [result(DOMAIN, "urlhaus", score=0.8), result(DOMAIN, "otx", score=0.5)]
        )[0]
        assert single.confidence == pytest.approx(0.8)
        assert double.confidence == pytest.approx(0.95)  # 0.8 + 0.15

    def test_confidence_is_capped_at_one(self) -> None:
        item = consensus([result(DOMAIN, f"p{i}", score=0.9) for i in range(5)])[0]
        assert item.confidence == 1.0

    def test_clean_indicators_gain_confidence_from_feed_count(self) -> None:
        one = consensus([result(DOMAIN, "a", Verdict.benign, score=0.0)])[0]
        three = consensus(
            [result(DOMAIN, p, Verdict.benign, score=0.0) for p in ("a", "b", "c")]
        )[0]
        assert three.confidence > one.confidence
        assert three.verdict is Verdict.benign

    def test_grouping_is_per_indicator_and_order_preserving(self) -> None:
        items = consensus(
            [result(DOMAIN, "urlhaus"), result(IP, "abuseipdb"), result(DOMAIN, "otx")]
        )
        assert [i.ioc for i in items] == [DOMAIN, IP]
        assert len(items[0].results) == 2

    def test_all_cached_is_only_true_when_every_answer_was_cached(self) -> None:
        mixed = consensus(
            [
                ProviderResult(ioc=DOMAIN, provider="a", cached=True),
                ProviderResult(ioc=DOMAIN, provider="b", cached=False),
            ]
        )[0]
        every = consensus([ProviderResult(ioc=DOMAIN, provider="a", cached=True)])[0]
        assert mixed.all_cached is False
        assert every.all_cached is True


class TestFindingSeverity:
    def test_a_known_malicious_hash_is_critical(self) -> None:
        # The sample itself is confirmed malware — the strongest possible signal.
        findings, _ = build_findings([result(HASH, "bazaar", score=1.0)])
        match = next(f for f in findings if f.type is FindingType.ioc_match)
        assert match.severity is Severity.critical

    def test_network_indicators_are_graded_below_a_hash_match(self) -> None:
        domain_findings, _ = build_findings([result(DOMAIN, "urlhaus")])
        ip_findings, _ = build_findings([result(IP, "abuseipdb")])
        assert domain_findings[0].severity is Severity.high
        # IPs are shared and rotated far more than domain names.
        assert ip_findings[0].severity is Severity.medium

    def test_suspicious_verdicts_are_downgraded(self) -> None:
        findings, _ = build_findings([result(DOMAIN, "otx", Verdict.suspicious, score=0.3)])
        assert findings[0].severity is Severity.medium

    def test_clean_and_unknown_indicators_produce_no_match_finding(self) -> None:
        findings, reconciled = build_findings(
            [
                result(DOMAIN, "urlhaus", Verdict.unknown, score=0.0),
                result(IP, "abuseipdb", Verdict.benign, score=0.0),
            ]
        )
        assert [f for f in findings if f.type is FindingType.ioc_match] == []
        # They still appear in the consensus record, so the report can show that
        # the indicators were checked and came back clean.
        assert len(reconciled) == 2


class TestAttribution:
    def test_family_is_promoted_to_its_own_finding(self) -> None:
        findings, _ = build_findings([result(HASH, "bazaar", families=["Cerberus"])])
        family = next(f for f in findings if f.type is FindingType.family_attribution)
        assert "Cerberus" in family.detail
        assert family.severity is Severity.high

    def test_family_reported_by_two_providers_is_one_corroborated_finding(self) -> None:
        findings, _ = build_findings(
            [
                result(HASH, "bazaar", families=["Cerberus"]),
                result(DOMAIN, "otx", families=["Cerberus"]),
            ]
        )
        families = [f for f in findings if f.type is FindingType.family_attribution]
        assert len(families) == 1
        # Corroboration across independent feeds escalates it to critical.
        assert families[0].severity is Severity.critical
        assert families[0].confidence == pytest.approx(0.8)

    def test_actors_become_their_own_findings(self) -> None:
        findings, _ = build_findings([result(DOMAIN, "otx", actors=["TA505"])])
        actor = next(f for f in findings if f.type is FindingType.actor_attribution)
        assert "TA505" in actor.detail

    def test_signatures_are_one_finding_per_indicator_not_per_name(self) -> None:
        findings, _ = build_findings(
            [result(HASH, "virustotal", signatures=[f"Vendor{i}: Trojan" for i in range(15)])]
        )
        signatures = [f for f in findings if f.type is FindingType.signature]
        assert len(signatures) == 1
        assert "+5 more" in signatures[0].detail


class TestFindingIdentity:
    def test_ids_are_stable_across_runs(self) -> None:
        first, _ = build_findings([result(DOMAIN, "urlhaus", families=["Cerberus"])])
        second, _ = build_findings([result(DOMAIN, "otx", families=["Cerberus"])])
        ids_first = {f.id for f in first}
        ids_second = {f.id for f in second}
        # Same indicator + same family ⇒ same ids, which is what makes the
        # backend's upsert-on-finding-id idempotent across stage retries.
        assert ids_first == ids_second

    def test_long_urls_produce_bounded_ids(self) -> None:
        long_url = Ioc(IocType.url, "http://evil.tk/" + "a" * 500)
        findings, _ = build_findings([result(long_url, "urlhaus")])
        assert len(findings[0].id) <= 128
        # ...and still unique per URL.
        other = Ioc(IocType.url, "http://evil.tk/" + "b" * 500)
        other_findings, _ = build_findings([result(other, "urlhaus")])
        assert findings[0].id != other_findings[0].id

    def test_mappings_reflect_the_indicator_class(self) -> None:
        network, _ = build_findings([result(DOMAIN, "urlhaus")])
        code, _ = build_findings([result(HASH, "bazaar")])
        assert "T1071.001" in network[0].mappings.mitre
        assert network[0].mappings.owasp_mobile == ["M5"]
        assert code[0].mappings.owasp_mobile == ["M8"]

    def test_provenance_records_the_flagging_provider_and_indicator(self) -> None:
        findings, _ = build_findings([result(DOMAIN, "urlhaus")])
        assert findings[0].provenance.extractor == "urlhaus"
        assert findings[0].provenance.locator == "domain:c2.evil.tk"


class TestEmptyInput:
    def test_no_results_yields_no_findings(self) -> None:
        findings, reconciled = build_findings([])
        assert findings == []
        assert reconciled == []
