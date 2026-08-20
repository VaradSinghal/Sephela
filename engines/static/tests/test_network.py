"""URL and IP extractors — the IoCs the threat-intel stage later enriches.

Both read the string corpus out of ``ctx.shared``, which makes the ordering in
``default_extractors`` load-bearing: run before ``strings`` and they find nothing, with
no error to say so.
"""

from __future__ import annotations

import pytest

from sephela_static.envelope import FindingType, Severity
from sephela_static.extractors.network import IpExtractor, UrlExtractor, _valid_public_ip


def _urls(corpus: list[str], make_context):
    ctx = make_context(shared={"strings": {"strings": corpus}})
    return UrlExtractor().extract(ctx)


def _ips(corpus: list[str], make_context):
    ctx = make_context(shared={"strings": {"strings": corpus}})
    return IpExtractor().extract(ctx)


class TestUrlExtraction:
    def test_an_http_url_is_found(self, make_context) -> None:
        result = _urls(["connect to https://c2.example.net/gate.php now"], make_context)

        assert result.evidence["urls"] == ["https://c2.example.net/gate.php"]

    @pytest.mark.parametrize("scheme", ["http", "https", "ftp"])
    def test_each_supported_scheme_is_recognised(self, scheme: str, make_context) -> None:
        result = _urls([f"{scheme}://host.example/path"], make_context)

        assert result.evidence["count"] == 1

    def test_the_scheme_match_is_case_insensitive(self, make_context) -> None:
        # Obfuscated payloads mix case to defeat naive greps.
        result = _urls(["HTTPS://Host.Example/Path"], make_context)

        assert result.evidence["count"] == 1

    def test_several_urls_in_one_string_are_all_found(self, make_context) -> None:
        result = _urls(["http://a.example/x http://b.example/y"], make_context)

        assert result.evidence["count"] == 2

    def test_urls_are_deduplicated_across_strings(self, make_context) -> None:
        result = _urls(["http://a.example/x", "http://a.example/x"], make_context)

        assert result.evidence["urls"] == ["http://a.example/x"]

    def test_the_output_is_sorted_for_a_stable_envelope(self, make_context) -> None:
        # Two runs of the same sample must produce byte-identical evidence, or every
        # re-analysis looks like a change.
        result = _urls(["http://z.example/", "http://a.example/"], make_context)

        assert result.evidence["urls"] == sorted(result.evidence["urls"])

    @pytest.mark.parametrize("terminator", ['"', "'", "<", ">", ")", " "])
    def test_a_url_stops_at_its_delimiter(self, terminator: str, make_context) -> None:
        # URLs are found inside Java string literals and XML, so trailing punctuation
        # would otherwise become part of the indicator and never match a feed.
        result = _urls([f"http://host.example/path{terminator}trailing"], make_context)

        assert result.evidence["urls"] == ["http://host.example/path"]

    def test_a_bare_domain_is_not_a_url(self, make_context) -> None:
        # Without a scheme it is not an indicator this extractor claims to find, and
        # every Java package name would qualify.
        result = _urls(["c2.example.net", "com.example.app"], make_context)

        assert result.evidence["count"] == 0

    def test_an_empty_corpus_yields_nothing(self, make_context) -> None:
        result = _urls([], make_context)

        assert result.evidence == {"count": 0, "urls": []}
        assert result.findings == []

    def test_a_missing_corpus_does_not_raise(self, make_context) -> None:
        # The strings extractor can fail independently — the pipeline isolates it — and
        # this one must then degrade rather than take the run down with it.
        result = UrlExtractor().extract(make_context())

        assert result.evidence["count"] == 0


class TestUrlFindings:
    def test_each_url_becomes_one_finding(self, make_context) -> None:
        result = _urls(["http://a.example/", "http://b.example/"], make_context)

        assert len(result.findings) == 2

    def test_the_finding_carries_the_url_and_its_provenance(self, make_context) -> None:
        result = _urls(["http://c2.example.net/gate.php"], make_context)

        (finding,) = result.findings
        assert finding.detail == "http://c2.example.net/gate.php"
        assert finding.provenance.extractor == "urls"
        assert finding.type is FindingType.url

    def test_a_url_is_informational_not_a_verdict(self, make_context) -> None:
        # A URL is an indicator; whether it is malicious is the threat-intel stage's
        # call. Rating it high here would inflate the score before anything is known.
        result = _urls(["http://c2.example.net/"], make_context)

        assert result.findings[0].severity is Severity.info

    def test_the_finding_maps_to_mitre(self, make_context) -> None:
        result = _urls(["http://c2.example.net/"], make_context)

        assert result.findings[0].mappings.mitre == ["T1071"]

    def test_finding_ids_are_unique(self, make_context) -> None:
        # A collision would have one indicator overwrite another downstream.
        result = _urls([f"http://host{i}.example/" for i in range(5)], make_context)

        assert len({f.id for f in result.findings}) == 5


class TestIpValidation:
    @pytest.mark.parametrize("ip", ["8.8.8.8", "1.2.3.4", "93.184.216.34", "45.33.32.156"])
    def test_a_public_address_is_accepted(self, ip: str) -> None:
        assert _valid_public_ip(ip) is True

    @pytest.mark.parametrize("ip", ["203.0.113.5", "198.51.100.7", "192.0.2.9"])
    def test_a_documentation_range_address_is_rejected(self, ip: str) -> None:
        # RFC 5737 test ranges. Python's ipaddress reports these as private, and they
        # are exactly what appears in a README or a unit test that shipped in the APK —
        # not a C2 endpoint.
        assert _valid_public_ip(ip) is False

    @pytest.mark.parametrize(
        "ip",
        [
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
            "172.20.5.5",
            "172.31.255.255",
            "127.0.0.1",
            "224.0.0.1",
            "0.0.0.0",
            "255.255.255.255",
        ],
    )
    def test_a_private_loopback_multicast_or_reserved_address_is_rejected(self, ip: str) -> None:
        # None of these can be a C2 endpoint reachable from a victim's phone, and every
        # one of them appears in ordinary app code and config.
        assert _valid_public_ip(ip) is False

    @pytest.mark.parametrize("candidate", ["999.1.1.1", "1.2.3", "not-an-ip", ""])
    def test_a_malformed_candidate_is_rejected(self, candidate: str) -> None:
        assert _valid_public_ip(candidate) is False


class TestIpExtraction:
    def test_a_public_ip_is_found(self, make_context) -> None:
        result = _ips(["beacon to 93.184.216.34 every hour"], make_context)

        assert result.evidence["ips"] == ["93.184.216.34"]

    def test_a_private_ip_is_filtered_out(self, make_context) -> None:
        result = _ips(["192.168.1.1", "93.184.216.34"], make_context)

        assert result.evidence["ips"] == ["93.184.216.34"]

    def test_a_version_number_is_not_an_ip(self, make_context) -> None:
        # Version strings look exactly like dotted quads and are everywhere.
        result = _ips(["1.2.3", "sdk version 33.0.1"], make_context)

        assert result.evidence["count"] == 0

    def test_a_longer_digit_run_is_not_captured_as_an_ip(self, make_context) -> None:
        # The lookaround guards stop "11.2.3.44444" yielding "1.2.3.4".
        result = _ips(["11.22.33.4444"], make_context)

        assert result.evidence["count"] == 0

    def test_ips_are_deduplicated_and_sorted(self, make_context) -> None:
        result = _ips(["93.184.216.34", "8.8.8.8", "93.184.216.34"], make_context)

        assert result.evidence["ips"] == sorted({"93.184.216.34", "8.8.8.8"})

    def test_each_ip_becomes_an_informational_finding(self, make_context) -> None:
        result = _ips(["93.184.216.34"], make_context)

        (finding,) = result.findings
        assert finding.type is FindingType.ip
        assert finding.severity is Severity.info
        assert finding.provenance.extractor == "ips"

    def test_an_empty_corpus_yields_nothing(self, make_context) -> None:
        result = _ips([], make_context)

        assert result.evidence == {"count": 0, "ips": []}

    def test_a_missing_corpus_does_not_raise(self, make_context) -> None:
        assert IpExtractor().extract(make_context()).evidence["count"] == 0


class TestSharedEvidenceContract:
    def test_both_read_the_key_the_string_extractor_writes(self, make_context) -> None:
        # The pipeline files evidence under `extractor.name`, so these two must look
        # under "strings". A rename on either side is a silent no-op, not an error.
        from sephela_static.extractors.strings import StringExtractor

        assert StringExtractor.name == "strings"

    def test_they_run_after_strings_in_the_default_chain(self) -> None:
        from sephela_static.extractors import default_extractors

        names = [e.name for e in default_extractors()]

        assert names.index("strings") < names.index("urls")
        assert names.index("strings") < names.index("ips")
