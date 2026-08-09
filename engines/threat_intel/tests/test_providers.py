"""Provider response parsing + HTTP error mapping.

Each provider is driven through a real ``httpx`` client backed by a mock
transport, so request construction (headers, form bodies, VT's base64url URL id)
is covered alongside the parsing. Payloads are trimmed but structurally faithful
to the real APIs.
"""

from __future__ import annotations

import base64

import httpx
import pytest

from sephela_threat_intel.base import (
    ProviderError,
    ProviderUnavailableError,
    RateLimitedError,
    Verdict,
)
from sephela_threat_intel.iocs import Ioc, IocType
from sephela_threat_intel.providers import build_providers
from sephela_threat_intel.providers.abuseipdb import AbuseIpDbProvider
from sephela_threat_intel.providers.bazaar import MalwareBazaarProvider
from sephela_threat_intel.providers.otx import OtxProvider
from sephela_threat_intel.providers.urlhaus import UrlHausProvider
from sephela_threat_intel.providers.virustotal import VirusTotalProvider

HASH = Ioc(IocType.hash, "a" * 64, "sample")
DOMAIN = Ioc(IocType.domain, "c2.evil.tk", "static")
IP = Ioc(IocType.ip, "45.55.1.2", "static")
URL = Ioc(IocType.url, "http://c2.evil.tk/reg", "dynamic")


def vt_payload(malicious: int, harmless: int, *, label: str | None = None) -> dict[str, object]:
    attributes: dict[str, object] = {
        "last_analysis_stats": {
            "malicious": malicious,
            "suspicious": 0,
            "harmless": harmless,
            "undetected": 0,
        },
        "last_analysis_results": {
            "VendorA": {"category": "malicious", "result": "Android.Cerberus"},
            "VendorB": {"category": "undetected", "result": None},
        },
    }
    if label:
        attributes["popular_threat_classification"] = {
            "suggested_threat_label": label,
            "popular_threat_name": [{"value": "cerberus"}],
        }
    return {"data": {"attributes": attributes}}


class TestVirusTotal:
    async def test_high_detection_ratio_is_malicious(self, json_client) -> None:  # type: ignore[no-untyped-def]
        provider = VirusTotalProvider(api_key="k")
        async with json_client(vt_payload(20, 50, label="trojan.cerberus")) as client:
            result = await provider.lookup(HASH, client)
        assert result.verdict is Verdict.malicious
        assert result.score == pytest.approx(0.571, abs=0.01)
        assert "cerberus" in " ".join(result.families).lower()
        assert result.signatures == ["Android.Cerberus"]

    async def test_single_detection_is_only_suspicious(self, json_client) -> None:  # type: ignore[no-untyped-def]
        # One hit out of 70 is routinely a false positive on packed-but-legit APKs.
        provider = VirusTotalProvider(api_key="k")
        async with json_client(vt_payload(1, 69)) as client:
            result = await provider.lookup(HASH, client)
        assert result.verdict is Verdict.suspicious

    async def test_clean_report_is_benign(self, json_client) -> None:  # type: ignore[no-untyped-def]
        provider = VirusTotalProvider(api_key="k")
        async with json_client(vt_payload(0, 70)) as client:
            result = await provider.lookup(HASH, client)
        assert result.verdict is Verdict.benign
        assert result.score == 0.0

    async def test_missing_record_is_unknown_not_an_error(self, json_client) -> None:  # type: ignore[no-untyped-def]
        provider = VirusTotalProvider(api_key="k")
        async with json_client({}, status=404) as client:
            result = await provider.lookup(HASH, client)
        assert result.verdict is Verdict.unknown
        assert result.raw == {"found": False}

    async def test_url_lookups_use_base64url_ids_and_send_the_key(self, recording_client) -> None:  # type: ignore[no-untyped-def]
        provider = VirusTotalProvider(api_key="secret")
        client, seen = recording_client(vt_payload(5, 5))
        async with client:
            await provider.lookup(URL, client)
        expected = base64.urlsafe_b64encode(URL.value.encode()).decode().rstrip("=")
        assert seen[0].url.path.endswith(f"/urls/{expected}")
        assert seen[0].headers["x-apikey"] == "secret"

    async def test_empty_stats_are_unknown(self, json_client) -> None:  # type: ignore[no-untyped-def]
        provider = VirusTotalProvider(api_key="k")
        async with json_client({"data": {"attributes": {}}}) as client:
            result = await provider.lookup(HASH, client)
        assert result.verdict is Verdict.unknown

    async def test_garbage_payload_does_not_raise(self, json_client) -> None:  # type: ignore[no-untyped-def]
        # Provider responses are untrusted input.
        provider = VirusTotalProvider(api_key="k")
        async with json_client({"data": "not-an-object"}) as client:
            result = await provider.lookup(HASH, client)
        assert result.verdict is Verdict.unknown


class TestOtx:
    async def test_multiple_pulses_are_malicious_with_attribution(self, json_client) -> None:  # type: ignore[no-untyped-def]
        payload = {
            "pulse_info": {
                "count": 4,
                "pulses": [
                    {
                        "name": "Cerberus campaign",
                        "malware_families": [{"display_name": "Cerberus"}],
                        "adversary": "TA505",
                    }
                ],
            }
        }
        provider = OtxProvider(api_key="k")
        async with json_client(payload) as client:
            result = await provider.lookup(DOMAIN, client)
        assert result.verdict is Verdict.malicious
        assert result.families == ["Cerberus"]
        assert result.actors == ["TA505"]

    async def test_single_pulse_is_suspicious(self, json_client) -> None:  # type: ignore[no-untyped-def]
        provider = OtxProvider(api_key="k")
        async with json_client({"pulse_info": {"count": 1, "pulses": []}}) as client:
            result = await provider.lookup(DOMAIN, client)
        assert result.verdict is Verdict.suspicious

    async def test_no_pulses_is_unknown_not_benign(self, json_client) -> None:  # type: ignore[no-untyped-def]
        # OTX silence means nobody reported it, not that it is clean.
        provider = OtxProvider(api_key="k")
        async with json_client({"pulse_info": {"count": 0, "pulses": []}}) as client:
            result = await provider.lookup(DOMAIN, client)
        assert result.verdict is Verdict.unknown

    async def test_api_key_header_is_sent(self, recording_client) -> None:  # type: ignore[no-untyped-def]
        provider = OtxProvider(api_key="otx-key")
        client, seen = recording_client({"pulse_info": {"count": 0}})
        async with client:
            await provider.lookup(IP, client)
        assert seen[0].headers["X-OTX-API-KEY"] == "otx-key"
        assert "/IPv4/45.55.1.2/general" in str(seen[0].url)


class TestAbuseIpDb:
    async def test_high_confidence_is_malicious(self, json_client) -> None:  # type: ignore[no-untyped-def]
        payload = {
            "data": {
                "abuseConfidenceScore": 88,
                "totalReports": 42,
                "usageType": "Data Center/Web Hosting/Transit",
                "countryCode": "NL",
            }
        }
        provider = AbuseIpDbProvider(api_key="k")
        async with json_client(payload) as client:
            result = await provider.lookup(IP, client)
        assert result.verdict is Verdict.malicious
        assert result.score == pytest.approx(0.88)
        assert result.raw["usage_type"].startswith("Data Center")

    async def test_reports_without_confidence_are_still_suspicious(self, json_client) -> None:  # type: ignore[no-untyped-def]
        provider = AbuseIpDbProvider(api_key="k")
        async with json_client({"data": {"abuseConfidenceScore": 0, "totalReports": 3}}) as client:
            result = await provider.lookup(IP, client)
        assert result.verdict is Verdict.suspicious

    async def test_clean_ip_is_benign(self, json_client) -> None:  # type: ignore[no-untyped-def]
        provider = AbuseIpDbProvider(api_key="k")
        async with json_client({"data": {"abuseConfidenceScore": 0, "totalReports": 0}}) as client:
            result = await provider.lookup(IP, client)
        assert result.verdict is Verdict.benign

    def test_only_handles_ips(self) -> None:
        provider = AbuseIpDbProvider(api_key="k")
        assert provider.handles(IP)
        assert not provider.handles(HASH)
        assert not provider.handles(DOMAIN)


class TestUrlHaus:
    async def test_listed_url_is_malicious(self, json_client) -> None:  # type: ignore[no-untyped-def]
        payload = {
            "query_status": "ok",
            "threat": "malware_download",
            "url_status": "online",
            "tags": ["apk", "cerberus"],
        }
        async with json_client(payload) as client:
            result = await UrlHausProvider().lookup(URL, client)
        assert result.verdict is Verdict.malicious
        assert result.score == 1.0
        assert result.families == ["malware_download"]

    async def test_offline_url_keeps_the_verdict_but_lowers_confidence(self, json_client) -> None:  # type: ignore[no-untyped-def]
        payload = {"query_status": "ok", "threat": "malware_download", "url_status": "offline"}
        async with json_client(payload) as client:
            result = await UrlHausProvider().lookup(URL, client)
        assert result.verdict is Verdict.malicious
        assert result.score == 0.7

    async def test_no_results_in_body_is_unknown(self, json_client) -> None:  # type: ignore[no-untyped-def]
        # URLhaus signals absence with HTTP 200 + query_status, not a 404.
        async with json_client({"query_status": "no_results"}) as client:
            result = await UrlHausProvider().lookup(URL, client)
        assert result.verdict is Verdict.unknown
        assert result.raw["query_status"] == "no_results"

    async def test_host_lookup_counts_urls(self, json_client) -> None:  # type: ignore[no-untyped-def]
        payload = {"query_status": "ok", "urls": [{}, {}, {}], "firstseen": "2026-01-01"}
        async with json_client(payload) as client:
            result = await UrlHausProvider().lookup(DOMAIN, client)
        assert result.verdict is Verdict.malicious
        assert result.raw["url_count"] == 3

    async def test_host_lookups_post_the_host_field(self, recording_client) -> None:  # type: ignore[no-untyped-def]
        client, seen = recording_client({"query_status": "no_results"})
        async with client:
            await UrlHausProvider().lookup(DOMAIN, client)
        assert seen[0].method == "POST"
        assert b"host=c2.evil.tk" in seen[0].content

    def test_is_configured_without_a_key(self) -> None:
        # The keyless feed is what makes a zero-config deployment still useful.
        assert UrlHausProvider().configured is True


class TestMalwareBazaar:
    async def test_known_sample_is_malicious_with_a_family(self, json_client) -> None:  # type: ignore[no-untyped-def]
        payload = {
            "query_status": "ok",
            "data": [
                {
                    "signature": "Cerberus",
                    "file_type": "apk",
                    "tags": ["android", "banker"],
                    "vendor_intel": {"VendorX": {"detection": "Android/Cerberus.A"}},
                }
            ],
        }
        async with json_client(payload) as client:
            result = await MalwareBazaarProvider().lookup(HASH, client)
        assert result.verdict is Verdict.malicious
        assert result.score == 1.0
        assert result.families == ["Cerberus"]
        assert result.signatures == ["VendorX: Android/Cerberus.A"]

    async def test_hash_not_found_is_unknown(self, json_client) -> None:  # type: ignore[no-untyped-def]
        async with json_client({"query_status": "hash_not_found"}) as client:
            result = await MalwareBazaarProvider().lookup(HASH, client)
        assert result.verdict is Verdict.unknown

    async def test_auth_key_is_sent_only_when_configured(self, recording_client) -> None:  # type: ignore[no-untyped-def]
        client, seen = recording_client({"query_status": "hash_not_found"})
        async with client:
            await MalwareBazaarProvider(api_key="bz").lookup(HASH, client)
            await MalwareBazaarProvider().lookup(HASH, client)
        assert seen[0].headers.get("Auth-Key") == "bz"
        assert "Auth-Key" not in seen[1].headers

    async def test_odd_vendor_intel_shapes_do_not_raise(self, json_client) -> None:  # type: ignore[no-untyped-def]
        payload = {
            "query_status": "ok",
            "data": [{"vendor_intel": {"A": [{"malware_family": "Hydra"}], "B": "junk"}}],
        }
        async with json_client(payload) as client:
            result = await MalwareBazaarProvider().lookup(HASH, client)
        assert result.signatures == ["A: Hydra"]


class TestHttpErrorMapping:
    """One provider suffices — the mapping lives in the shared helper."""

    async def test_429_is_rate_limited(self, json_client) -> None:  # type: ignore[no-untyped-def]
        async with json_client({}, status=429) as client:
            with pytest.raises(RateLimitedError):
                await VirusTotalProvider(api_key="k").lookup(HASH, client)

    async def test_401_and_403_are_quota_or_credential_failures(self, json_client) -> None:  # type: ignore[no-untyped-def]
        for status in (401, 403):
            async with json_client({}, status=status) as client:
                with pytest.raises(RateLimitedError):
                    await VirusTotalProvider(api_key="k").lookup(HASH, client)

    async def test_5xx_is_unavailable(self, json_client) -> None:  # type: ignore[no-untyped-def]
        async with json_client({}, status=503) as client:
            with pytest.raises(ProviderUnavailableError):
                await VirusTotalProvider(api_key="k").lookup(HASH, client)

    async def test_timeout_is_unavailable(self, make_client) -> None:  # type: ignore[no-untyped-def]
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("too slow", request=request)

        async with make_client(handler) as client:
            with pytest.raises(ProviderUnavailableError):
                await VirusTotalProvider(api_key="k").lookup(HASH, client)

    async def test_html_error_page_is_a_provider_error(self, make_client) -> None:  # type: ignore[no-untyped-def]
        async with make_client(lambda _r: httpx.Response(200, text="<html>oops</html>")) as client:
            with pytest.raises(ProviderError):
                await VirusTotalProvider(api_key="k").lookup(HASH, client)


class TestRegistry:
    def test_keyless_providers_survive_an_empty_config(self) -> None:
        names = {p.name for p in build_providers({})}
        assert names == {"urlhaus", "bazaar"}

    def test_keyed_providers_appear_once_configured(self) -> None:
        names = {p.name for p in build_providers({"virustotal": "k", "abuseipdb": "k"})}
        assert names == {"urlhaus", "bazaar", "virustotal", "abuseipdb"}

    def test_blank_keys_are_treated_as_absent(self) -> None:
        names = {p.name for p in build_providers({"virustotal": ""})}
        assert "virustotal" not in names
