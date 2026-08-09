"""IoC normalization + harvesting.

These are the engine's cost-control and privacy boundary: everything that
survives this module gets sent to a third party, so the tests are written around
"what must never leave the box" as much as around correctness.
"""

from __future__ import annotations

from sephela_threat_intel.iocs import (
    Ioc,
    IocType,
    dedupe,
    expand_urls,
    is_benign_domain,
    make_ioc,
    normalize_hash,
    normalize_ip,
    normalize_url,
)
from sephela_threat_intel.sources import iocs_from_findings, sample_iocs


class TestNormalization:
    def test_hash_is_lowercased_and_length_checked(self) -> None:
        assert normalize_hash("A" * 64) == "a" * 64
        assert normalize_hash("  " + "b" * 32 + " ") == "b" * 32
        assert normalize_hash("c" * 40) == "c" * 40
        # Not a recognized digest length.
        assert normalize_hash("d" * 50) is None
        # Not hex.
        assert normalize_hash("z" * 64) is None

    def test_private_and_reserved_ips_are_rejected(self) -> None:
        # Sending internal addresses to a public feed is both useless and a leak.
        for private in ("10.0.0.5", "192.168.1.1", "172.16.0.1", "127.0.0.1", "0.0.0.0"):
            assert normalize_ip(private) is None
        assert normalize_ip("8.8.8.8") == "8.8.8.8"
        assert normalize_ip("2001:4860:4860::8888") == "2001:4860:4860::8888"

    def test_url_canonicalization_collapses_equivalent_forms(self) -> None:
        # Same indicator, three spellings — must produce one cache key.
        assert (
            normalize_url("HTTP://Evil.Example.:80/Path")
            == normalize_url("http://evil.example/Path")
            == "http://evil.example/Path"
        )
        # Default HTTPS port dropped, non-default kept.
        assert normalize_url("https://evil.example:443/x") == "https://evil.example/x"
        assert normalize_url("https://evil.example:8443/x") == "https://evil.example:8443/x"
        # Query survives — a C2 path/query is often the whole indicator.
        assert normalize_url("http://c2.example/reg?id=1") == "http://c2.example/reg?id=1"

    def test_defanged_indicators_are_refanged(self) -> None:
        assert normalize_url("hxxp://evil[.]example/x") == "http://evil.example/x"
        assert normalize_ip("8[.]8[.]8[.]8") == "8.8.8.8"

    def test_non_http_schemes_and_junk_are_rejected(self) -> None:
        assert normalize_url("mailto:a@b.com") is None
        assert normalize_url("not a url") is None
        assert normalize_url("http://") is None

    def test_oversized_urls_are_dropped(self) -> None:
        assert normalize_url("http://evil.example/" + "a" * 3000) is None


class TestBenignFiltering:
    def test_platform_domains_are_filtered(self) -> None:
        # Present in essentially every APK — querying them wastes quota.
        assert is_benign_domain("schemas.android.com")
        assert is_benign_domain("play.google.com")
        assert is_benign_domain("googleapis.com")
        assert not is_benign_domain("evil.example")
        # Suffix matching must not be fooled by a lookalike.
        assert not is_benign_domain("google.com.evil.tk")

    def test_make_ioc_drops_benign_domains_and_urls(self) -> None:
        assert make_ioc(IocType.domain, "schemas.android.com") is None
        assert make_ioc(IocType.url, "https://play.google.com/store") is None
        assert make_ioc(IocType.domain, "c2.evil.tk") is not None

    def test_make_ioc_keeps_ip_urls_even_though_hosts_are_checked(self) -> None:
        ioc = make_ioc(IocType.url, "http://8.8.8.8/payload.apk")
        assert ioc is not None and ioc.value == "http://8.8.8.8/payload.apk"


class TestIdentity:
    def test_iocs_dedupe_across_sources(self) -> None:
        # The same domain seen by static and dynamic analysis is one lookup.
        static = Ioc(IocType.domain, "c2.evil.tk", "static")
        dynamic = Ioc(IocType.domain, "c2.evil.tk", "dynamic")
        assert static == dynamic
        assert len(dedupe([static, dynamic])) == 1

    def test_key_is_stable_and_typed(self) -> None:
        assert Ioc(IocType.domain, "c2.evil.tk").key == "domain:c2.evil.tk"


class TestUrlExpansion:
    def test_urls_yield_host_indicators(self) -> None:
        urls = [
            Ioc(IocType.url, "http://c2.evil.tk/reg", "static"),
            Ioc(IocType.url, "http://45.55.1.2/panel", "dynamic"),
        ]
        derived = expand_urls(urls)
        assert Ioc(IocType.domain, "c2.evil.tk") in derived
        assert Ioc(IocType.ip, "45.55.1.2") in derived

    def test_benign_hosts_are_not_expanded(self) -> None:
        urls = [Ioc(IocType.url, "http://8.8.8.8/x"), Ioc(IocType.url, "http://c2.evil.tk/x")]
        # A benign-suffixed host would be dropped; these are kept.
        assert len(expand_urls(urls)) == 2
        assert expand_urls([Ioc(IocType.url, "http://c2.evil.tk/x")]) == [
            Ioc(IocType.domain, "c2.evil.tk")
        ]

    def test_private_host_urls_yield_no_indicator(self) -> None:
        assert expand_urls([Ioc(IocType.url, "http://192.168.0.1/admin")]) == []


class TestSampleIocs:
    def test_all_digests_are_included(self) -> None:
        iocs = sample_iocs(sha256="a" * 64, sha1="b" * 40, md5="c" * 32)
        assert [i.value for i in iocs] == ["a" * 64, "b" * 40, "c" * 32]
        assert all(i.type is IocType.hash and i.source == "sample" for i in iocs)

    def test_missing_digests_are_skipped(self) -> None:
        assert len(sample_iocs(sha256="a" * 64, md5=None)) == 1


class TestHarvestFromFindings:
    def test_direct_types_use_the_detail_verbatim(self) -> None:
        rows = [
            {"type": "url", "detail": "http://c2.evil.tk/reg", "source_engine": "static"},
            {"type": "ip", "detail": "45.55.1.2", "source_engine": "static"},
            {"type": "cert", "detail": "AA:BB:CC", "source_engine": "static"},
        ]
        iocs = iocs_from_findings(rows)
        assert {i.type for i in iocs} == {IocType.url, IocType.ip, IocType.cert}
        assert all(i.source == "static" for i in iocs)

    def test_network_findings_are_scanned_for_embedded_indicators(self) -> None:
        rows = [
            {
                "type": "network",
                "detail": "POST http://c2.evil.tk/register from app",
                "source_engine": "dynamic",
            }
        ]
        iocs = iocs_from_findings(rows)
        # The URL is captured; the host is not double-counted here (the pipeline
        # derives it via expand_urls instead).
        assert Ioc(IocType.url, "http://c2.evil.tk/register") in iocs
        assert Ioc(IocType.domain, "c2.evil.tk") not in iocs

    def test_bare_hosts_in_prose_are_captured(self) -> None:
        rows = [{"type": "behavior", "detail": "resolves panel.evil.top and 45.55.1.2"}]
        iocs = iocs_from_findings(rows)
        assert Ioc(IocType.domain, "panel.evil.top") in iocs
        assert Ioc(IocType.ip, "45.55.1.2") in iocs

    def test_caps_bound_the_indicator_set(self) -> None:
        rows = [
            {"type": "url", "detail": f"http://evil{i}.tk/x", "source_engine": "static"}
            for i in range(200)
        ]
        iocs = iocs_from_findings(rows, caps={IocType.url: 5})
        assert len(iocs) == 5

    def test_earlier_rows_win_the_cap(self) -> None:
        # The backend passes dynamic findings first precisely for this reason.
        rows = [
            {"type": "url", "detail": "http://observed.evil.tk/x", "source_engine": "dynamic"},
            {"type": "url", "detail": "http://scraped.evil.tk/x", "source_engine": "static"},
        ]
        iocs = iocs_from_findings(rows, caps={IocType.url: 1})
        assert [i.source for i in iocs] == ["dynamic"]

    def test_malformed_rows_are_skipped_not_raised(self) -> None:
        rows = [
            "not a dict",
            {"type": "url"},  # no detail
            {"detail": "http://x.evil.tk"},  # no type
            {"type": "url", "detail": ""},
            {"type": "url", "detail": "http://good.evil.tk/x"},
        ]
        iocs = iocs_from_findings(rows)  # type: ignore[arg-type]
        assert [i.value for i in iocs] == ["http://good.evil.tk/x"]

    def test_unrelated_finding_types_contribute_nothing(self) -> None:
        rows = [{"type": "permission", "detail": "android.permission.SEND_SMS"}]
        assert iocs_from_findings(rows) == []
