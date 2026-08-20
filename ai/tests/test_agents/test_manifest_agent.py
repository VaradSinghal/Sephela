"""ManifestAgent — prompt construction, findings extraction, deterministic path.

The deterministic path matters as much as the LLM one: it is what a deployment with
no model credential falls back to, and two of its bugs are pinned below.
"""

from __future__ import annotations

from typing import Any

import pytest

from ai.agents.manifest import (
    DANGEROUS_PERMISSIONS,
    ManifestAgent,
    analyze_manifest_deterministic,
)
from ai.schemas.base import Severity
from ai.schemas.manifest import ComponentInfo, ManifestAnalysis


@pytest.fixture
def static_evidence(sample_evidence: dict[str, Any]) -> dict[str, Any]:
    """The manifest agent reads the flattened static evidence, not the whole envelope."""
    return sample_evidence["static_evidence"]


class TestPrompt:
    def test_it_names_the_package_and_every_permission(
        self, static_evidence: dict[str, Any]
    ) -> None:
        prompt = ManifestAgent().build_prompt(static_evidence, {})

        assert "com.example.test" in prompt
        for perm in static_evidence["permissions"]["permissions"]:
            assert perm in prompt

    def test_it_reports_component_counts(self, static_evidence: dict[str, Any]) -> None:
        prompt = ManifestAgent().build_prompt(static_evidence, {})

        # The counts are what tell the model how much surface there is to reason about.
        assert "Activities: 1" in prompt
        assert "Services: 1" in prompt


class TestFindingsExtraction:
    def test_an_exported_activity_produces_a_finding(self) -> None:
        # Regression: the deterministic path used `rstrip("s")` on "activities",
        # yielding component_type="activitie", which matched nothing here — so an
        # exported activity, the surface another app can launch, produced nothing.
        output = ManifestAnalysis(
            package_name="com.example",
            components=[
                ComponentInfo(name="com.example.Main", component_type="activity", exported=True)
            ],
            allow_backup=False,
        )

        findings = ManifestAgent().extract_findings(output)

        assert [f.type for f in findings] == ["exported_component"]
        assert "com.example.Main" in findings[0].title

    def test_a_non_exported_component_produces_nothing(self) -> None:
        output = ManifestAnalysis(
            package_name="com.example",
            components=[
                ComponentInfo(name="com.example.Main", component_type="activity", exported=False)
            ],
            allow_backup=False,
        )

        assert ManifestAgent().extract_findings(output) == []

    def test_debuggable_and_allow_backup_each_produce_a_finding(self) -> None:
        output = ManifestAnalysis(package_name="com.example", debuggable=True, allow_backup=True)

        types = {f.type for f in ManifestAgent().extract_findings(output)}

        assert types == {"debuggable", "backup_allowed"}

    def test_a_hardened_manifest_produces_nothing(self) -> None:
        output = ManifestAnalysis(package_name="com.example", debuggable=False, allow_backup=False)

        assert ManifestAgent().extract_findings(output) == []

    def test_permission_findings_are_carried_through(self) -> None:
        analysis = analyze_manifest_deterministic(
            {"permissions": {"permissions": ["android.permission.BIND_ACCESSIBILITY_SERVICE"]}}
        )

        findings = ManifestAgent().extract_findings(analysis)

        assert any(f.type == "permission" for f in findings)


class TestDeterministicPath:
    def test_every_component_type_maps_to_the_singular_extract_findings_expects(self) -> None:
        analysis = analyze_manifest_deterministic(
            {
                "components": {
                    "activities": ["A"],
                    "services": ["S"],
                    "receivers": ["R"],
                    "providers": ["P"],
                    "intent_filters": {"A": [{"action": "MAIN"}]},
                }
            }
        )

        by_name = {c.name: c.component_type for c in analysis.components}
        assert by_name == {"A": "activity", "S": "service", "R": "receiver", "P": "provider"}

    def test_a_component_with_an_intent_filter_is_treated_as_exported(self) -> None:
        analysis = analyze_manifest_deterministic(
            {
                "components": {
                    "activities": ["Launcher", "Internal"],
                    "intent_filters": {"Launcher": [{"action": "android.intent.action.MAIN"}]},
                }
            }
        )

        exported = {c.name for c in analysis.components if c.exported}
        assert exported == {"Launcher"}

    def test_the_intent_filter_shape_the_static_engine_emits_is_accepted(self) -> None:
        # ComponentExtractor stores androguard's get_intent_filters() result verbatim,
        # which is a single dict per component. ComponentInfo.intent_filters is a
        # list[dict], so passing it straight through raised ValidationError for every
        # component — this function could not run on real evidence at all.
        analysis = analyze_manifest_deterministic(
            {
                "components": {
                    "activities": ["Launcher"],
                    "intent_filters": {
                        "Launcher": {
                            "action": ["android.intent.action.MAIN"],
                            "category": ["android.intent.category.LAUNCHER"],
                        }
                    },
                }
            }
        )

        (component,) = analysis.components
        assert component.exported is True
        assert component.intent_filters == [
            {
                "action": ["android.intent.action.MAIN"],
                "category": ["android.intent.category.LAUNCHER"],
            }
        ]

    def test_a_list_of_intent_filters_is_also_accepted(self) -> None:
        analysis = analyze_manifest_deterministic(
            {
                "components": {
                    "services": ["Svc"],
                    "intent_filters": {"Svc": [{"action": ["a"]}, {"action": ["b"]}]},
                }
            }
        )

        assert analysis.components[0].intent_filters == [{"action": ["a"]}, {"action": ["b"]}]

    def test_a_component_with_no_intent_filter_gets_an_empty_list(self) -> None:
        analysis = analyze_manifest_deterministic({"components": {"activities": ["Internal"]}})

        (component,) = analysis.components
        assert component.exported is False
        assert component.intent_filters == []

    @pytest.mark.parametrize("permission", sorted(DANGEROUS_PERMISSIONS))
    def test_each_dangerous_permission_is_scored_and_mapped(self, permission: str) -> None:
        analysis = analyze_manifest_deterministic({"permissions": {"permissions": [permission]}})

        (finding,) = analysis.permissions
        expected_sev, expected_conf, expected_mitre, expected_owasp, _ = DANGEROUS_PERMISSIONS[
            permission
        ]
        assert finding.permission_name == permission
        assert finding.severity == expected_sev
        assert finding.confidence == expected_conf
        assert finding.mitre_techniques == expected_mitre
        assert finding.owasp_mobile == expected_owasp
        # An analyst has to be able to get from the finding back to the evidence.
        assert finding.evidence_refs[0].extractor == "permissions"

    def test_a_benign_permission_is_not_flagged(self) -> None:
        analysis = analyze_manifest_deterministic(
            {"permissions": {"permissions": ["android.permission.INTERNET"]}}
        )

        assert analysis.permissions == []

    def test_dangerous_permissions_are_counted_from_severity(self) -> None:
        analysis = analyze_manifest_deterministic(
            {
                "permissions": {
                    "permissions": [
                        "android.permission.BIND_ACCESSIBILITY_SERVICE",  # critical
                        "android.permission.RECORD_AUDIO",  # medium
                        "android.permission.INTERNET",  # not dangerous
                    ]
                }
            }
        )

        # model_post_init counts only high and critical.
        assert analysis.dangerous_permission_count == 1

    def test_certificates_are_carried_through_verbatim(self) -> None:
        certs = [{"subject": "CN=Android Debug", "issuer": "CN=Android Debug"}]

        analysis = analyze_manifest_deterministic({"certificate": {"certificates": certs}})

        assert analysis.certificates == certs

    def test_an_empty_envelope_still_yields_a_usable_analysis(self) -> None:
        # Every upstream extractor can fail independently, so this is a real input.
        analysis = analyze_manifest_deterministic({})

        assert analysis.package_name == "unknown"
        assert analysis.permissions == []
        assert analysis.components == []

    def test_allow_backup_defaults_to_true_the_way_android_does(self) -> None:
        # Absent android:allowBackup means backups are permitted, so defaulting to
        # False here would under-report a real exposure.
        assert analyze_manifest_deterministic({}).allow_backup is True

    def test_manifest_attributes_are_read_from_the_evidence(self) -> None:
        analysis = analyze_manifest_deterministic(
            {
                "manifest": {
                    "package_name": "com.bank.fake",
                    "version_name": "9.9",
                    "min_sdk": 21,
                    "target_sdk": 33,
                    "debuggable": True,
                    "allow_backup": False,
                    "uses_cleartext_traffic": True,
                }
            }
        )

        assert analysis.package_name == "com.bank.fake"
        assert analysis.version_name == "9.9"
        assert (analysis.min_sdk, analysis.target_sdk) == (21, 33)
        assert analysis.debuggable is True
        assert analysis.allow_backup is False
        assert analysis.uses_cleartext_traffic is True


class TestPermissionTable:
    def test_accessibility_is_the_most_severe_entry(self) -> None:
        # It is the permission a banking overlay trojan actually needs: it can read
        # every screen and synthesise taps. Nothing should outrank it.
        sev, *_ = DANGEROUS_PERMISSIONS["android.permission.BIND_ACCESSIBILITY_SERVICE"]
        assert sev is Severity.critical

    def test_every_entry_carries_a_mitre_technique_and_a_rationale(self) -> None:
        for perm, (_, _, mitre, owasp, rationale) in DANGEROUS_PERMISSIONS.items():
            assert mitre, f"{perm} has no MITRE mapping"
            assert owasp, f"{perm} has no OWASP mapping"
            assert rationale.strip(), f"{perm} has no rationale for a report to quote"
