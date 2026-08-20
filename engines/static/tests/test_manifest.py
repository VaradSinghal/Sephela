"""Manifest, permission, component, and certificate extractors.

The four androguard-backed extractors. Between them they produce the permission
findings that dominate a banking-trojan score, so a missed mapping here is a missed
verdict everywhere downstream.
"""

from __future__ import annotations

import pytest
from conftest import FakeApk, FakeCertificate  # type: ignore[import-not-found]

from sephela_static.envelope import FindingType, Severity
from sephela_static.extractors.manifest import (
    DANGEROUS_PERMISSIONS,
    CertificateExtractor,
    ComponentExtractor,
    ManifestExtractor,
    PermissionExtractor,
)


class TestManifestExtractor:
    def test_the_package_identity_is_extracted(self, make_context) -> None:
        ctx = make_context(
            apk=FakeApk(package="com.bank.fake", version_name="2.1", version_code="7")
        )

        evidence = ManifestExtractor().extract(ctx).evidence

        assert evidence["package_name"] == "com.bank.fake"
        assert evidence["version_name"] == "2.1"
        assert evidence["version_code"] == "7"

    def test_the_sdk_range_and_entry_point_are_extracted(self, make_context) -> None:
        ctx = make_context(
            apk=FakeApk(min_sdk="21", target_sdk="33", main_activity="com.bank.fake.Splash")
        )

        evidence = ManifestExtractor().extract(ctx).evidence

        assert (evidence["min_sdk"], evidence["target_sdk"]) == ("21", "33")
        assert evidence["main_activity"] == "com.bank.fake.Splash"

    def test_it_raises_no_findings(self, make_context) -> None:
        # Package metadata is context for other findings, not a finding itself.
        assert ManifestExtractor().extract(make_context(apk=FakeApk())).findings == []

    def test_it_declares_that_it_needs_tooling(self) -> None:
        # The pipeline and the engine image both key off this.
        assert ManifestExtractor.requires_tools is True


class TestPermissionExtractor:
    @pytest.mark.parametrize("permission", sorted(DANGEROUS_PERMISSIONS))
    def test_each_dangerous_permission_yields_its_mapped_finding(
        self, permission: str, make_context
    ) -> None:
        ctx = make_context(apk=FakeApk(permissions=[permission]))
        expected_severity, expected_mitre, expected_owasp = DANGEROUS_PERMISSIONS[permission]

        result = PermissionExtractor().extract(ctx)

        (finding,) = result.findings
        assert finding.id == f"perm:{permission}"
        assert finding.type is FindingType.permission
        assert finding.severity is expected_severity
        assert finding.mappings.mitre == expected_mitre
        assert finding.mappings.owasp_mobile == expected_owasp
        # An analyst has to be able to get from the finding back to the manifest.
        assert finding.provenance.locator == "AndroidManifest.xml"

    def test_a_benign_permission_yields_no_finding(self, make_context) -> None:
        # INTERNET is requested by essentially every app; a finding for it would bury
        # the ones that matter.
        ctx = make_context(apk=FakeApk(permissions=["android.permission.INTERNET"]))

        result = PermissionExtractor().extract(ctx)

        assert result.findings == []

    def test_every_permission_is_still_recorded_as_evidence(self, make_context) -> None:
        # The permission agent and the scoring engine both read the full list, not just
        # the flagged ones.
        permissions = ["android.permission.INTERNET", "android.permission.READ_SMS"]
        ctx = make_context(apk=FakeApk(permissions=permissions))

        evidence = PermissionExtractor().extract(ctx).evidence

        assert evidence["permissions"] == permissions
        assert evidence["count"] == 2

    def test_accessibility_is_the_most_severe_permission(self, make_context) -> None:
        # It is what a banking-overlay trojan actually needs: read every screen and
        # synthesise taps. Nothing in the table should outrank it.
        severity, _, _ = DANGEROUS_PERMISSIONS["android.permission.BIND_ACCESSIBILITY_SERVICE"]

        assert severity is Severity.critical

    def test_several_dangerous_permissions_each_yield_a_finding(self, make_context) -> None:
        ctx = make_context(
            apk=FakeApk(
                permissions=[
                    "android.permission.BIND_ACCESSIBILITY_SERVICE",
                    "android.permission.SYSTEM_ALERT_WINDOW",
                    "android.permission.RECEIVE_SMS",
                    "android.permission.INTERNET",
                ]
            )
        )

        result = PermissionExtractor().extract(ctx)

        assert len(result.findings) == 3

    def test_no_permissions_is_a_valid_manifest(self, make_context) -> None:
        result = PermissionExtractor().extract(make_context(apk=FakeApk(permissions=[])))

        assert result.evidence == {"count": 0, "permissions": []}
        assert result.findings == []

    def test_every_finding_carries_a_confidence(self, make_context) -> None:
        # The scoring engine weights by confidence; an unset one would silently
        # contribute nothing.
        ctx = make_context(apk=FakeApk(permissions=["android.permission.READ_SMS"]))

        (finding,) = PermissionExtractor().extract(ctx).findings

        assert 0.0 < finding.confidence <= 1.0


class TestPermissionTable:
    def test_every_entry_maps_to_mitre_and_owasp(self) -> None:
        # These mappings are what a SOC triages against and what the compliance section
        # of the report is built from.
        for permission, (_, mitre, owasp) in DANGEROUS_PERMISSIONS.items():
            assert mitre, f"{permission} has no MITRE technique"
            assert owasp, f"{permission} has no OWASP category"

    def test_the_overlay_and_accessibility_pair_are_both_present(self) -> None:
        # Together they are the overlay-trojan signature; either alone is much weaker.
        assert "android.permission.BIND_ACCESSIBILITY_SERVICE" in DANGEROUS_PERMISSIONS
        assert "android.permission.SYSTEM_ALERT_WINDOW" in DANGEROUS_PERMISSIONS

    def test_sms_interception_permissions_are_present(self) -> None:
        # How a trojan defeats one-time passcodes.
        assert {
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
        } <= set(DANGEROUS_PERMISSIONS)


class TestComponentExtractor:
    def test_every_component_kind_is_listed_and_counted(self, make_context) -> None:
        ctx = make_context(
            apk=FakeApk(
                activities=["A1", "A2"], services=["S1"], receivers=["R1"], providers=["P1"]
            )
        )

        evidence = ComponentExtractor().extract(ctx).evidence

        assert evidence["activities"] == ["A1", "A2"]
        assert evidence["counts"] == {
            "activities": 2,
            "services": 1,
            "receivers": 1,
            "providers": 1,
        }

    def test_intent_filters_are_recorded_per_component(self, make_context) -> None:
        # A declared filter is what makes a component reachable from another app.
        filters = {"Launcher": {"action": ["android.intent.action.MAIN"]}}
        ctx = make_context(apk=FakeApk(activities=["Launcher"], intent_filters=filters))

        evidence = ComponentExtractor().extract(ctx).evidence

        assert evidence["intent_filters"] == filters

    def test_a_component_without_filters_is_absent_from_the_map(self, make_context) -> None:
        ctx = make_context(apk=FakeApk(activities=["Internal"], intent_filters={}))

        evidence = ComponentExtractor().extract(ctx).evidence

        assert evidence["intent_filters"] == {}

    def test_a_broken_intent_filter_api_degrades_to_an_empty_map(self, make_context) -> None:
        # androguard's intent-filter signature has changed between releases; losing the
        # filters costs detail, while raising would cost the component list too.
        ctx = make_context(apk=FakeApk(activities=["A"], intent_filters_raise=True))

        evidence = ComponentExtractor().extract(ctx).evidence

        assert evidence["intent_filters"] == {}
        assert evidence["activities"] == ["A"]

    def test_an_app_with_no_components_is_valid(self, make_context) -> None:
        evidence = ComponentExtractor().extract(make_context(apk=FakeApk())).evidence

        assert evidence["counts"] == {
            "activities": 0,
            "services": 0,
            "receivers": 0,
            "providers": 0,
        }

    def test_providers_are_listed_even_though_filters_are_not_probed_for_them(
        self, make_context
    ) -> None:
        # The filter loop covers activities, services, and receivers; providers are
        # exported via an attribute rather than a filter, so they must still be listed.
        ctx = make_context(apk=FakeApk(providers=["com.example.Provider"]))

        evidence = ComponentExtractor().extract(ctx).evidence

        assert evidence["providers"] == ["com.example.Provider"]


class TestCertificateExtractor:
    def test_certificate_details_are_extracted(self, make_context) -> None:
        cert = FakeCertificate(subject="CN=Bank App", issuer="CN=Real CA", serial_number=42)
        ctx = make_context(apk=FakeApk(certificates=[cert]))

        evidence = CertificateExtractor().extract(ctx).evidence

        (info,) = evidence["certificates"]
        assert info["subject"] == "CN=Bank App"
        assert info["issuer"] == "CN=Real CA"
        assert info["serial"] == "42"

    def test_the_digest_is_hex_encoded(self, make_context) -> None:
        # It is the key a threat-intel feed is queried with; raw bytes would not
        # serialise into the envelope at all.
        ctx = make_context(apk=FakeApk(certificates=[FakeCertificate(sha256=b"\xab" * 32)]))

        evidence = CertificateExtractor().extract(ctx).evidence

        assert evidence["certificates"][0]["sha256"] == "ab" * 32

    def test_a_certificate_with_no_digest_is_still_recorded(self, make_context) -> None:
        # v3-only signing and unusual schemes leave androguard without a digest.
        ctx = make_context(apk=FakeApk(certificates=[FakeCertificate(sha256=None)]))

        evidence = CertificateExtractor().extract(ctx).evidence

        assert evidence["certificates"][0]["sha256"] is None

    def test_a_self_signed_certificate_is_identified(self, make_context) -> None:
        cert = FakeCertificate(subject="CN=Same", issuer="CN=Same")
        ctx = make_context(apk=FakeApk(certificates=[cert]))

        evidence = CertificateExtractor().extract(ctx).evidence

        assert evidence["certificates"][0]["self_signed"] is True

    def test_a_ca_signed_certificate_is_not(self, make_context) -> None:
        cert = FakeCertificate(subject="CN=App", issuer="CN=Real CA")
        ctx = make_context(apk=FakeApk(certificates=[cert]))

        evidence = CertificateExtractor().extract(ctx).evidence

        assert evidence["certificates"][0]["self_signed"] is False

    def test_a_debug_certificate_raises_a_finding(self, make_context) -> None:
        # A production app signed with the debug key was not built by a release
        # pipeline, which for a banking app is decisive.
        cert = FakeCertificate(subject="CN=Android Debug, O=Android")
        ctx = make_context(apk=FakeApk(certificates=[cert]))

        result = CertificateExtractor().extract(ctx)

        (finding,) = result.findings
        assert finding.id == "cert:debug"
        assert finding.type is FindingType.cert
        assert finding.severity is Severity.medium
        assert finding.mappings.owasp_mobile == ["M7"]

    def test_a_release_certificate_raises_no_finding(self, make_context) -> None:
        ctx = make_context(apk=FakeApk(certificates=[FakeCertificate()]))

        assert CertificateExtractor().extract(ctx).findings == []

    def test_several_certificates_are_all_recorded(self, make_context) -> None:
        # An APK can carry multiple signers, and a rotated key is worth seeing.
        ctx = make_context(
            apk=FakeApk(
                certificates=[FakeCertificate(subject="CN=One"), FakeCertificate(subject="CN=Two")]
            )
        )

        evidence = CertificateExtractor().extract(ctx).evidence

        assert [c["subject"] for c in evidence["certificates"]] == ["CN=One", "CN=Two"]

    def test_an_unparseable_signature_scheme_degrades_to_an_empty_list(self, make_context) -> None:
        # Signature-scheme parsing varies across androguard versions and APK v2/v3/v4;
        # the rest of the static analysis is still worth having.
        ctx = make_context(apk=FakeApk(certificates_raise=True))

        result = CertificateExtractor().extract(ctx)

        assert result.evidence == {"certificates": []}
        assert result.findings == []

    def test_an_unsigned_apk_yields_no_certificates(self, make_context) -> None:
        result = CertificateExtractor().extract(make_context(apk=FakeApk(certificates=[])))

        assert result.evidence == {"certificates": []}


class TestSharedParse:
    def test_all_four_read_one_parse_of_the_apk(self, make_context) -> None:
        # ExtractionContext caches _apk_obj so the four extractors do not each pay for a
        # full androguard parse of a 300 MiB sample.
        apk = FakeApk(permissions=["android.permission.READ_SMS"], activities=["A"])
        ctx = make_context(apk=apk)

        for extractor in (
            ManifestExtractor(),
            PermissionExtractor(),
            ComponentExtractor(),
            CertificateExtractor(),
        ):
            extractor.extract(ctx)

        assert ctx.androguard_apk() is apk
